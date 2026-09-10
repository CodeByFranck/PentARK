"""Business-logic scanner: rate limiting, numeric abuse, step-skipping, races.

Semi-automated by design. Every finding is a *candidate anomaly* reported at low
confidence with an explicit "manual review" note — the scanner proves the
surprising behavior (e.g. a negative price was accepted) but never escalates it
into an exploit.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from urllib.parse import urlencode, urlsplit

import httpx

from pentark.assess.http_client import HttpClient
from pentark.assess.logic.spec import (
    LogicSpec,
    NumericFieldTarget,
    RaceTarget,
    RateLimitTarget,
    WorkflowTarget,
)
from pentark.assess.models import Finding
from pentark.core.audit import AuditLog, NullAuditLog

_V_RATELIMIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"    # 5.3 Medium
_V_NUMERIC = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"      # 6.5 Medium
_V_WORKFLOW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"     # 6.4 Medium
_V_RACE = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N"         # 5.7 Medium

_REVIEW = " Flagged for MANUAL REVIEW — verify against intended business rules; not auto-exploited."
_ERROR_MARKERS = ("invalid", "must be", "not allowed", "error", "out of range", "too large")


class LogicScanner:
    def __init__(
        self,
        http: HttpClient,
        *,
        audit: AuditLog | NullAuditLog | None = None,
        executor_factory: Callable[[int], ThreadPoolExecutor] = ThreadPoolExecutor,
    ) -> None:
        self.http = http
        self.audit = audit or NullAuditLog()
        self._executor_factory = executor_factory

    def run(self, spec: LogicSpec) -> list[Finding]:
        findings: list[Finding] = []
        for t in spec.rate_limit:
            findings += self._rate_limit(t)
        for n in spec.numeric:
            findings += self._numeric(n)
        for w in spec.workflows:
            findings += self._workflow(w)
        for r in spec.race:
            findings += self._race(r)
        return findings

    # -- 1. rate limiting ---------------------------------------------------

    def _rate_limit(self, t: RateLimitTarget) -> list[Finding]:
        statuses: list[int] = []
        throttled = False
        for _ in range(t.attempts):
            resp = self._send(t.method, t.url, t.body)
            if resp is None:
                continue
            statuses.append(resp.status_code)
            if resp.status_code == t.throttle_status or (
                t.throttle_marker and t.throttle_marker in resp.text
            ):
                throttled = True
                break
        self.audit.log("logic.rate_limit", target=t.url, result=f"throttled={throttled}")
        if throttled or not statuses:
            return []
        return [self._finding(
            "logic-rate-limit", f"Possible missing rate limiting on '{t.name}'", t.url,
            _V_RATELIMIT, "CWE-799", "low",
            f"Sent {len(statuses)} requests to a sensitive endpoint with no throttling "
            f"(no HTTP {t.throttle_status} or lockout observed), enabling brute force / abuse.",
            f"{len(statuses)} requests, status codes seen: {sorted(set(statuses))}",
        )]

    # -- 2. numeric abuse ---------------------------------------------------

    def _numeric(self, n: NumericFieldTarget) -> list[Finding]:
        base = self._send_numeric(n, n.valid)
        base_ok = base is not None and base.is_success
        accepted: list[str] = []
        for value in n.bad_values:
            resp = self._send_numeric(n, value)
            if resp is None:
                continue
            if self._value_accepted(resp):
                accepted.append(value)
        self.audit.log("logic.numeric", target=n.url, result=f"accepted={accepted}")
        if not accepted:
            return []
        note = "" if base_ok else " (baseline with a valid value did not clearly succeed — verify)."
        return [self._finding(
            "logic-numeric", f"Possible missing validation on numeric field '{n.field}'", n.url,
            _V_NUMERIC, "CWE-20", "low",
            f"The '{n.field}' field accepted out-of-range value(s) {accepted} that a price/"
            f"quantity field should reject (e.g. negative totals, integer overflow).{note}",
            f"field={n.field}; accepted values={accepted}",
        )]

    # -- 3. workflow step-skipping -----------------------------------------

    def _workflow(self, w: WorkflowTarget) -> list[Finding]:
        step = w.steps[w.protected_index]
        # Request the protected step directly, with NO prior steps performed.
        resp = self._send(step.method, step.url, step.body)
        if resp is None:
            return []
        blocked = resp.status_code in w.blocked_statuses or resp.is_redirect
        served = resp.is_success and (not w.success_marker or w.success_marker in resp.text)
        self.audit.log("logic.workflow", target=step.url, result=f"served={served and not blocked}")
        if blocked or not served:
            return []
        return [self._finding(
            "logic-workflow", f"Possible workflow step-skipping in '{w.name}'", step.url,
            _V_WORKFLOW, "CWE-841", "low",
            f"Step {w.protected_index + 1} of the '{w.name}' workflow was reachable directly "
            f"(HTTP {resp.status_code}) without completing the prior steps, so a required "
            "sequence/state check may be missing server-side.",
            f"GET {step.url} with no prerequisites -> HTTP {resp.status_code}",
        )]

    # -- 4. race conditions -------------------------------------------------

    def _race(self, r: RaceTarget) -> list[Finding]:
        results: list[tuple[int, bool]] = []

        def _once(_i: int) -> tuple[int, bool] | None:
            resp = self._send(r.method, r.url, r.body)
            if resp is None:
                return None
            ok = resp.status_code == r.success_status and (
                not r.success_marker or r.success_marker in resp.text
            )
            return resp.status_code, ok

        with self._executor_factory(r.concurrency) as ex:
            for res in ex.map(_once, range(r.concurrency)):
                if res is not None:
                    results.append(res)

        successes = sum(1 for _, ok in results if ok)
        self.audit.log("logic.race", target=r.url, result=f"successes={successes}/{r.concurrency}")
        if successes <= r.expected_success:
            return []
        throttle_note = ""
        if getattr(self.http.rate_limiter, "min_interval", 0):
            throttle_note = " (NOTE: client rate limiting is on — raise rate_limit_rps for higher-fidelity race tests.)"
        return [self._finding(
            "logic-race", f"Possible race condition in '{r.name}'", r.url,
            _V_RACE, "CWE-362", "low",
            f"{successes} of {r.concurrency} concurrent requests succeeded where at most "
            f"{r.expected_success} should — the operation may not be atomic (TOCTOU).{throttle_note}",
            f"{successes}/{r.concurrency} concurrent successes; statuses={sorted({s for s, _ in results})}",
        )]

    # -- helpers -----------------------------------------------------------

    def _send(self, method: str, url: str, fields: dict[str, str], *, as_query: bool = False):
        try:
            if method.upper() == "GET" or as_query:
                target = url + ("&" if urlsplit(url).query else "?") + urlencode(fields) if fields else url
                return self.http.get(target)
            return self.http.request(method.upper(), url, data=fields)
        except Exception:
            return None

    def _send_numeric(self, n: NumericFieldTarget, value: str):
        fields = {**n.extra, n.field: value}
        return self._send(n.method, n.url, fields, as_query=(n.location == "query"))

    @staticmethod
    def _value_accepted(resp: httpx.Response) -> bool:
        if not resp.is_success:
            return False
        low = resp.text.lower()
        return not any(m in low for m in _ERROR_MARKERS)

    def _finding(self, check_id, name, url, vector, cwe, confidence, desc, evidence) -> Finding:
        return Finding(
            check_id=check_id, name=name, endpoint=url, cvss_vector=vector,
            description=desc + _REVIEW,
            remediation=_REMEDIATION[check_id], evidence=evidence,
            confidence=confidence, cwe=cwe,
        )


_REMEDIATION = {
    "logic-rate-limit": "Enforce server-side rate limiting / lockout on sensitive endpoints (login, reset, checkout).",
    "logic-numeric": "Validate numeric inputs server-side (type, sign, bounds) and use safe integer/decimal types.",
    "logic-workflow": "Enforce workflow state server-side; verify prior steps/authorization before serving later ones.",
    "logic-race": "Make critical operations atomic (transactions, row locks, idempotency keys, unique constraints).",
}


__all__ = ["LogicScanner"]
