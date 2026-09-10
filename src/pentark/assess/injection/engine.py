"""Injection scanner: probe each parameter for SQLi, cmd injection, SSTI, XSS.

Detection is layered and non-destructive:
  * SQLi  — error-based (a quote surfaces a DB error) and blind time-based
            (`SLEEP(n)`), confirmed against a zero-delay control to reject slow
            endpoints; optional sqlmap `--banner` for a version string.
  * Cmd   — blind time-based (`; sleep n`), same control logic.
  * SSTI  — inject `{{269*271}}` / `${...}` and confirm the product (72899)
            appears while the raw expression does not (i.e. it was evaluated).
  * XSS   — reflect a unique canary with an HTML-breaking payload; optional
            Playwright confirmation that `alert(document.domain)` really fires.
"""

from __future__ import annotations

from typing import Callable

import httpx

from pentark.assess.injection import payloads as pl
from pentark.assess.injection.confirmers import SqlmapLike, XssConfirmerLike
from pentark.assess.injection.params import (
    InjectionPoint,
    build_request,
    points_from_forms,
    points_from_url,
)
from pentark.assess.http_client import HttpClient
from pentark.assess.models import Finding
from pentark.core.audit import AuditLog, NullAuditLog

_V_SQLI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 Critical
_V_CMDI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 Critical
_V_SSTI = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"   # 9.1 Critical
_V_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"    # 6.1 Medium


def _default_elapsed(resp: httpx.Response) -> float:
    return resp.elapsed.total_seconds()


class InjectionScanner:
    def __init__(
        self,
        http: HttpClient,
        *,
        sleep_seconds: int = 5,
        include_post_forms: bool = False,
        sqlmap: SqlmapLike | None = None,
        xss_confirmer: XssConfirmerLike | None = None,
        audit: AuditLog | NullAuditLog | None = None,
        elapsed_of: Callable[[httpx.Response], float] = _default_elapsed,
    ) -> None:
        self.http = http
        self.sleep_seconds = sleep_seconds
        self.include_post_forms = include_post_forms
        self.sqlmap = sqlmap
        self.xss_confirmer = xss_confirmer
        self.audit = audit or NullAuditLog()
        self.elapsed_of = elapsed_of

    # -- discovery + orchestration -----------------------------------------

    def run(self, target: str) -> list[Finding]:
        points = list(points_from_url(target))
        try:
            html = self.http.get(target).text
        except Exception:
            html = ""
        points += points_from_forms(html, target)

        tested: list[InjectionPoint] = []
        skipped = 0
        for p in points:
            if p.is_mutating and not self.include_post_forms:
                skipped += 1
                continue
            tested.append(p)
        if skipped:
            self.audit.log(
                "inject.skip_mutating", target=target,
                result=f"{skipped} POST-form parameter(s) skipped (pass include_post_forms)",
            )

        findings: list[Finding] = []
        for point in tested:
            self.audit.log("inject.point", target=target, module=point.label())
            findings.extend(self._test_point(target, point))
        return _dedupe(findings)

    # -- per-parameter techniques ------------------------------------------

    def _test_point(self, target: str, point: InjectionPoint) -> list[Finding]:
        base = point.fields.get(point.param) or "1"
        try:
            base_resp, _ = self._send(point, base)
        except Exception:
            return []
        base_text = base_resp.text
        base_elapsed = self.elapsed_of(base_resp)

        out: list[Finding] = []
        f = self._sqli_error(point, base, base_text)
        f = f or self._sqli_time(point, base, base_elapsed)
        if f:
            out.append(f)
        cmd = self._cmd_injection(point, base, base_elapsed)
        if cmd:
            out.append(cmd)
        ssti = self._ssti(point, base)
        if ssti:
            out.append(ssti)
        xss = self._xss(target, point, base)
        if xss:
            out.append(xss)
        return out

    def _sqli_error(self, point, base, base_text) -> Finding | None:
        if pl.find_sql_error(base_text):
            return None  # already erroring without us -> can't attribute
        for suffix in pl.sqli_error_payloads():
            resp, _ = self._send(point, base + suffix)
            err = pl.find_sql_error(resp.text)
            if err:
                banner = self._sqlmap_banner(point, base + suffix)
                return self._finding(
                    "sqli", f"SQL injection (error-based) in '{point.param}'", point,
                    _V_SQLI, "CWE-89", "high",
                    f"Injecting {suffix!r} elicited a database error: {err!r}." + banner[0],
                    f"payload={base + suffix!r}; error={err!r}{banner[1]}",
                )
        return None

    def _sqli_time(self, point, base, base_elapsed) -> Finding | None:
        for tp in pl.sqli_time_payloads(self.sleep_seconds):
            hit = self._timed_confirm(point, base, tp, base_elapsed)
            if hit is None:
                continue
            payload_e, control_e = hit
            banner = self._sqlmap_banner(point, base + tp.payload)
            return self._finding(
                "sqli", f"SQL injection (blind time-based, {tp.name}) in '{point.param}'",
                point, _V_SQLI, "CWE-89", "high",
                f"A {tp.name} time payload delayed the response by ~{payload_e:.1f}s "
                f"(control {control_e:.1f}s, baseline {base_elapsed:.1f}s), proving blind SQLi."
                + banner[0],
                f"payload={base + tp.payload!r}; delay={payload_e:.1f}s{banner[1]}",
            )
        return None

    def _cmd_injection(self, point, base, base_elapsed) -> Finding | None:
        for tp in pl.cmd_time_payloads(self.sleep_seconds):
            hit = self._timed_confirm(point, base, tp, base_elapsed)
            if hit is None:
                continue
            payload_e, control_e = hit
            return self._finding(
                "cmd-injection", f"OS command injection ({tp.name}) in '{point.param}'",
                point, _V_CMDI, "CWE-78", "high",
                f"A {tp.name} time-delay payload delayed the response by ~{payload_e:.1f}s "
                f"(control {control_e:.1f}s), proving command execution.",
                f"payload={base + tp.payload!r}; delay={payload_e:.1f}s",
            )
        return None

    def _ssti(self, point, base) -> Finding | None:
        for sp in pl.ssti_payloads():
            resp, _ = self._send(point, sp.payload)
            if pl.ssti_evaluated(resp.text):
                return self._finding(
                    "ssti", f"Server-side template injection ({sp.engine}) in '{point.param}'",
                    point, _V_SSTI, "CWE-1336", "high",
                    f"The template expression {pl.SSTI_EXPR} was evaluated to {pl.SSTI_PRODUCT} "
                    f"({sp.engine}), proving server-side template injection.",
                    f"payload={sp.payload!r}; response contained {pl.SSTI_PRODUCT}",
                )
        return None

    def _xss(self, target, point, base) -> Finding | None:
        xp = pl.xss_payload()
        resp, url = self._send(point, xp.payload)
        conf = pl.xss_reflected(resp.text, xp.canary)
        stored = False
        if conf is None and point.location == "form":
            # Re-read the target: did our canary persist there (stored XSS)?
            try:
                back = self.http.get(target).text
            except Exception:
                back = ""
            conf = pl.xss_reflected(back, xp.canary)
            stored = conf is not None
        if conf is None:
            return None

        dom_confirmed = False
        if self.xss_confirmer is not None and point.method == "GET":
            dom_confirmed = self.xss_confirmer.confirm(url)
            if dom_confirmed:
                conf = "high"
        kind = "stored" if stored else "reflected"
        proof = " Confirmed executing in a headless browser (alert(document.domain))." if dom_confirmed else ""
        return self._finding(
            "xss", f"{kind.capitalize()} XSS in '{point.param}'", point,
            _V_XSS, "CWE-79", conf,
            f"A unique canary reflected unescaped in an HTML context, so injected markup "
            f"executes in the browser ({kind} XSS).{proof}",
            f"canary={xp.canary!r}; payload reflected unescaped"
            + ("; DOM execution confirmed" if dom_confirmed else ""),
        )

    # -- helpers -----------------------------------------------------------

    def _timed_confirm(self, point, base, tp, base_elapsed):
        """Return (payload_elapsed, control_elapsed) if the payload truly delayed."""
        n = self.sleep_seconds
        payload_resp, _ = self._send(point, base + tp.payload)
        payload_e = self.elapsed_of(payload_resp)
        if payload_e < n * 0.5:
            return None  # not slow -> skip the extra control request
        control_resp, _ = self._send(point, base + tp.control)
        control_e = self.elapsed_of(control_resp)
        if pl.is_delayed(base_elapsed, payload_e, control_e, n):
            return payload_e, control_e
        return None

    def _sqlmap_banner(self, point, value) -> tuple[str, str]:
        """(description-suffix, evidence-suffix) from an optional sqlmap run."""
        if self.sqlmap is None:
            return "", ""
        res = self.sqlmap.confirm(point, value)
        if res.banner:
            return f" sqlmap confirmed; DBMS banner: {res.banner}.", f"; sqlmap banner={res.banner!r}"
        if res.confirmed:
            return " sqlmap confirmed the injection.", "; sqlmap=confirmed"
        return "", ""

    def _send(self, point: InjectionPoint, value: str):
        method, url, data = build_request(point, value)
        if method == "GET":
            return self.http.get(url), url
        return self.http.request("POST", url, data=data), url

    def _finding(self, check_id, name, point, vector, cwe, confidence, desc, evidence) -> Finding:
        return Finding(
            check_id=f"injection-{check_id}", name=name, endpoint=point.label(),
            cvss_vector=vector,
            description=desc + " PoC is non-destructive (execution proven; no data dumped).",
            remediation=_REMEDIATION[check_id], evidence=evidence,
            confidence=confidence, cwe=cwe,
        )


_REMEDIATION = {
    "sqli": "Use parameterized queries / prepared statements; never concatenate input into SQL.",
    "cmd-injection": "Avoid shelling out; if unavoidable, use argument vectors (no shell) and strict allowlists.",
    "ssti": "Never render user input as a template; use a sandboxed, logic-less template with escaping.",
    "xss": "Context-aware output encoding, a strict CSP, and input validation/allowlisting.",
}


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())


__all__ = ["InjectionScanner"]
