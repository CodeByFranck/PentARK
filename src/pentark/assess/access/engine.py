"""A01 – Broken Access Control auditor.

Four techniques, all routed through the HttpClient choke point (scope + throttle
+ audit) and emitting standard :class:`~pentark.assess.models.Finding` objects:

1. **Cross-identity replay** — replay each recorded request under every *less*
   privileged identity and with no session. A 200 whose body length matches the
   authorized response means privileged data leaked to someone who should not see
   it (CWE-863).
2. **IDOR** — find numeric / UUID identifiers in a request, mutate them, and
   replay under the *same* identity. A 200 returning a *different* valid record
   proves object-level access is not enforced (CWE-639). GET only — the PoC
   retrieves one unauthorized record and never writes.
3. **Forced browsing** — request known admin paths as a low-priv / anonymous
   identity; a 200 is unauthorized access (CWE-425).
4. **HTTP method tampering** — GET->PUT/DELETE. Safe mode only *discovers* exposed
   write methods via OPTIONS (non-destructive); actually sending write methods
   requires the explicit ``allow_mutation`` opt-in (CWE-650).

Safety: with ``allow_mutation=False`` (the default) the auditor sends nothing
outside :data:`~pentark.assess.access.models.SAFE_METHODS`, so no request can
change server state. Anything skipped for safety is logged, never dropped
silently.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from pentark.assess.access.models import RecordedRequest, ReplayResult
from pentark.assess.http_client import HttpClient
from pentark.assess.models import Finding
from pentark.core.audit import AuditLog, NullAuditLog
from pentark.core.scope import Scope, SessionIdentity

# The no-session identity: no cookies, no auth headers.
ANONYMOUS = SessionIdentity(name="anonymous", role="anon", privilege=-1)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_WRITE_METHODS = ("PUT", "DELETE", "PATCH", "POST")

# A small curated list; extend via the CLI. Kept generic (framework-agnostic).
DEFAULT_ADMIN_PATHS = (
    "/admin", "/admin/", "/administrator", "/manage", "/management",
    "/console", "/dashboard", "/admin/users", "/admin/config", "/config",
    "/api/admin", "/users", "/actuator", "/server-status", "/.env",
)

_PREVIEW_LEN = 200


def _vector_for(privilege: int, *, anon: bool) -> tuple[str, str]:
    """(CVSS vector, human phrase) for a confidentiality-loss access-control bug."""
    if anon or privilege < 0:
        return ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "an unauthenticated client")  # 7.5 High
    return ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "a lower-privileged identity")     # 6.5 Medium


class AccessControlAuditor:
    def __init__(
        self,
        http: HttpClient,
        scope: Scope,
        *,
        audit: AuditLog | NullAuditLog | None = None,
        allow_mutation: bool = False,
        admin_paths: tuple[str, ...] = DEFAULT_ADMIN_PATHS,
        length_tolerance_ratio: float = 0.05,
        length_tolerance_abs: int = 16,
    ) -> None:
        self.http = http
        self.scope = scope
        self.audit = audit or NullAuditLog()
        self.allow_mutation = allow_mutation
        self.admin_paths = admin_paths
        self.length_tolerance_ratio = length_tolerance_ratio
        self.length_tolerance_abs = length_tolerance_abs

    # -- public API ---------------------------------------------------------

    def run(
        self,
        requests: list[RecordedRequest] | None = None,
        *,
        forced_browsing_base: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        requests = requests or []
        for req in requests:
            findings.extend(self._cross_identity_replay(req))
            findings.extend(self._idor(req))
            findings.extend(self._method_tampering(req))
        if forced_browsing_base:
            findings.extend(self._forced_browsing(forced_browsing_base))
        return findings

    # -- technique 1: cross-identity replay ---------------------------------

    def _cross_identity_replay(self, req: RecordedRequest) -> list[Finding]:
        if not req.is_safe and not self.allow_mutation:
            self.audit.log(
                "access.skip_mutating", target=req.url, module="cross-identity",
                result=f"{req.method} skipped (safe mode; pass allow_mutation to replay)",
            )
            return []

        baseline_ident = self._baseline_identity(req)
        if baseline_ident is None:
            return []
        base = self._replay(req, baseline_ident)
        if not base.is_ok:
            return []  # can't establish what "authorized data" looks like

        findings: list[Finding] = []
        for ident in self._other_identities(baseline_ident):
            resp = self._replay(req, ident)
            if resp.is_ok and self._length_matches(resp.body_len, base.body_len):
                vector, who = _vector_for(ident.privilege, anon=ident.is_anonymous)
                exact = resp.body_len == base.body_len
                findings.append(
                    Finding(
                        check_id="access-broken",
                        name=f"Broken access control: {who} can read '{req.name}'",
                        endpoint=f"{req.method} {req.url}",
                        cvss_vector=vector,
                        description=(
                            f"The endpoint returns the same response to identity "
                            f"{ident.name!r} (privilege {ident.privilege}) as to the "
                            f"authorized identity {baseline_ident.name!r} (privilege "
                            f"{baseline_ident.privilege}). Access is not enforced server-side."
                        ),
                        remediation=(
                            "Enforce authorization on every request server-side (deny by "
                            "default); verify the session's role and object ownership before "
                            "returning data. Never rely on the client hiding endpoints."
                        ),
                        evidence=(
                            f"authorized ({baseline_ident.name}) -> HTTP {base.status}, "
                            f"{base.body_len} bytes; replayed as {ident.name} -> HTTP "
                            f"{resp.status}, {resp.body_len} bytes"
                            + (" (identical length)" if exact else " (length within tolerance)")
                        ),
                        confidence="high" if exact else "medium",
                        cwe="CWE-863",
                    )
                )
        return findings

    # -- technique 2: IDOR --------------------------------------------------

    def _idor(self, req: RecordedRequest) -> list[Finding]:
        # Object access is read-only here: GET the original id, then GET a
        # neighbouring id under the same identity. Never mutating.
        ident = self._baseline_identity(req) or ANONYMOUS
        original = self._replay(req, ident, method="GET")
        if not original.is_ok:
            return []

        findings: list[Finding] = []
        for label, mutated_url in _idor_candidates(req.url):
            probe = RecordedRequest(
                name=req.name, method="GET", url=mutated_url,
                recorded_as=req.recorded_as, headers=req.headers,
            )
            resp = self._replay(probe, ident, method="GET")
            if resp.is_ok and self._looks_like_other_record(original, resp):
                findings.append(
                    Finding(
                        check_id="access-idor",
                        name=f"IDOR: object reference '{label}' is not access-controlled",
                        endpoint=f"GET {mutated_url}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",  # 6.5 Medium
                        description=(
                            f"Changing the object identifier ({label}) returned a different, "
                            f"valid record for identity {ident.name!r}. The server does not "
                            "check that the caller owns / may access the referenced object."
                        ),
                        remediation=(
                            "Authorize every object reference against the current session "
                            "(ownership / ACL check). Prefer unguessable identifiers, but treat "
                            "that as defense-in-depth, not the control."
                        ),
                        evidence=(
                            f"original -> HTTP {original.status}, {original.body_len} bytes; "
                            f"mutated {mutated_url} -> HTTP {resp.status}, {resp.body_len} bytes. "
                            f"Retrieved record (PoC, truncated): {resp.body_preview!r}"
                        ),
                        confidence="medium",
                        cwe="CWE-639",
                    )
                )
                break  # one confirmed PoC per request is enough; don't enumerate
        return findings

    # -- technique 3: forced browsing ---------------------------------------

    def _forced_browsing(self, base: str) -> list[Finding]:
        findings: list[Finding] = []
        # Test as each non-privileged identity plus no session.
        idents = [ANONYMOUS] + [i for i in self.scope.identities if i.privilege <= 0]
        for path in self.admin_paths:
            url = urljoin(base, path)
            for ident in idents:
                resp = self._get(url, ident)
                if resp.is_ok:
                    vector, who = _vector_for(ident.privilege, anon=ident.is_anonymous)
                    findings.append(
                        Finding(
                            check_id="access-forced-browsing",
                            name=f"Forced browsing: {who} reached {path}",
                            endpoint=f"GET {url}",
                            cvss_vector=vector,
                            description=(
                                f"The administrative/internal path {path!r} returned HTTP "
                                f"{resp.status} to {ident.name!r} with no authorization step. "
                                "Sensitive functionality is reachable by direct request."
                            ),
                            remediation=(
                                "Require authentication and an explicit role check on every "
                                "administrative route; return 401/403 (not 200) to unauthorized "
                                "callers. Do not rely on the URL being unlinked."
                            ),
                            evidence=f"GET {url} as {ident.name} -> HTTP {resp.status}, {resp.body_len} bytes",
                            confidence="high",
                            cwe="CWE-425",
                        )
                    )
                    break  # reported for the least-privileged identity that got in
        return findings

    # -- technique 4: HTTP method tampering ---------------------------------

    def _method_tampering(self, req: RecordedRequest) -> list[Finding]:
        if req.method != "GET":
            return []
        ident = self._baseline_identity(req) or ANONYMOUS

        if not self.allow_mutation:
            # Non-destructive: ask the server which methods it advertises.
            opts = self._replay(
                RecordedRequest(name=req.name, method="OPTIONS", url=req.url), ident,
                method="OPTIONS",
            )
            allow = opts.body_preview  # engine stashes the Allow header here for OPTIONS
            exposed = [m for m in _WRITE_METHODS if m in allow.upper()]
            if not exposed:
                return []
            return [
                Finding(
                    check_id="access-method-tampering",
                    name=f"Write methods advertised on read endpoint '{req.name}'",
                    endpoint=f"OPTIONS {req.url}",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",  # 7.5 High
                    description=(
                        f"The endpoint advertises write methods ({', '.join(exposed)}) via its "
                        "Allow header on a resource fetched with GET. If those methods are not "
                        "authorized, an attacker may modify or delete data by changing the verb."
                    ),
                    remediation=(
                        "Restrict each route to the methods it needs and authorize state-changing "
                        "verbs explicitly; return 405 for unsupported methods."
                    ),
                    evidence=f"OPTIONS {req.url} -> Allow: {allow!r} (not actively exercised — safe mode)",
                    confidence="low",  # advertised != exploitable; confirm with allow_mutation
                    cwe="CWE-650",
                )
            ]

        # allow_mutation: actively send write verbs. THIS CAN MODIFY DATA.
        findings: list[Finding] = []
        for verb in ("PUT", "DELETE"):
            self.audit.log("access.mutating_probe", target=req.url, module="method-tampering", result=verb)
            resp = self._replay(
                RecordedRequest(name=req.name, method=verb, url=req.url), ident, method=verb,
            )
            if not resp.is_denied and resp.status != 405:
                findings.append(
                    Finding(
                        check_id="access-method-tampering",
                        name=f"HTTP method tampering: {verb} accepted on '{req.name}'",
                        endpoint=f"{verb} {req.url}",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",  # 7.5 High
                        description=(
                            f"Sending {verb} to a GET endpoint returned HTTP {resp.status} instead "
                            "of being denied (401/403) or rejected (405). State-changing methods "
                            "are not authorized."
                        ),
                        remediation=(
                            "Authorize state-changing methods explicitly and return 405 for verbs "
                            "a route does not implement."
                        ),
                        evidence=f"{verb} {req.url} -> HTTP {resp.status} (active probe; allow_mutation enabled)",
                        confidence="high",
                        cwe="CWE-650",
                    )
                )
        return findings

    # -- helpers ------------------------------------------------------------

    def _baseline_identity(self, req: RecordedRequest) -> SessionIdentity | None:
        if req.recorded_as:
            ident = self.scope.identity(req.recorded_as)
            if ident is not None:
                return ident
        # Fall back to the most privileged identity available.
        return max(self.scope.identities, key=lambda i: i.privilege, default=None)

    def _other_identities(self, baseline: SessionIdentity) -> list[SessionIdentity]:
        # Every identity strictly less privileged than the baseline, plus no session.
        others = [i for i in self.scope.identities if i.privilege < baseline.privilege]
        if not baseline.is_anonymous:
            others.append(ANONYMOUS)
        return others

    def _replay(self, req: RecordedRequest, ident: SessionIdentity, *, method: str | None = None) -> ReplayResult:
        verb = (method or req.method).upper()
        kwargs: dict = {"headers": _identity_headers(ident, req.headers), "follow_redirects": False}
        if req.body is not None and verb not in ("GET", "HEAD", "OPTIONS"):
            kwargs["content"] = req.body
        resp = self.http.request(verb, req.url, **kwargs)
        return _to_result(ident.name, resp, is_options=(verb == "OPTIONS"))

    def _get(self, url: str, ident: SessionIdentity) -> ReplayResult:
        resp = self.http.request(
            "GET", url, headers=_identity_headers(ident), follow_redirects=False
        )
        return _to_result(ident.name, resp)

    def _length_matches(self, a: int, b: int) -> bool:
        return abs(a - b) <= max(self.length_tolerance_abs, int(b * self.length_tolerance_ratio))

    @staticmethod
    def _looks_like_other_record(original: ReplayResult, mutated: ReplayResult) -> bool:
        """True if the mutated response looks like a *different valid record*."""
        if mutated.body_len == 0:
            return False
        if mutated.body_preview == original.body_preview and mutated.body_len == original.body_len:
            return False  # identical -> same record echoed, not a new object
        # Structurally similar in size (same kind of object), but not identical.
        lo, hi = sorted((original.body_len or 1, mutated.body_len or 1))
        return (hi / lo) <= 4.0


def _identity_headers(ident: SessionIdentity, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build request headers for an identity: auth headers + a Cookie header.

    Cookies are folded into an explicit ``Cookie`` header rather than passed via
    httpx's per-request ``cookies=`` (deprecated, and ambiguous on a shared
    client), keeping each identity's credentials isolated to its own request.
    """
    headers: dict[str, str] = {**ident.headers, **(extra or {})}
    if ident.cookies:
        jar = "; ".join(f"{k}={v}" for k, v in ident.cookies.items())
        existing = headers.get("Cookie")
        headers["Cookie"] = f"{existing}; {jar}" if existing else jar
    return headers


def _to_result(identity: str, resp, *, is_options: bool = False) -> ReplayResult:
    text = resp.text or ""
    preview = resp.headers.get("allow", "") if is_options else text[:_PREVIEW_LEN]
    return ReplayResult(
        identity=identity,
        status=resp.status_code,
        body_len=len(resp.content or b""),
        content_type=resp.headers.get("content-type", ""),
        location=resp.headers.get("location", ""),
        body_preview=preview,
    )


def _idor_candidates(url: str) -> list[tuple[str, str]]:
    """Yield (label, mutated_url) for each numeric / UUID identifier in the URL.

    Numeric ids are incremented and decremented; UUIDs are noted but not guessed
    (increment is meaningless) — swap them in via a second recorded request if you
    need UUID coverage.
    """
    parsed = urlparse(url)
    out: list[tuple[str, str]] = []

    # Path segments.
    segments = parsed.path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit():
            for delta in (1, -1):
                n = int(seg) + delta
                if n < 0:
                    continue
                new_segs = segments[:]
                new_segs[i] = str(n)
                mutated = parsed._replace(path="/".join(new_segs))
                out.append((f"path[{i}]={seg}->{n}", urlunparse(mutated)))

    # Query parameters.
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for j, (k, v) in enumerate(pairs):
        if v.isdigit():
            for delta in (1, -1):
                n = int(v) + delta
                if n < 0:
                    continue
                new_pairs = pairs[:]
                new_pairs[j] = (k, str(n))
                mutated = parsed._replace(query=urlencode(new_pairs))
                out.append((f"{k}={v}->{n}", urlunparse(mutated)))
    return out


__all__ = ["AccessControlAuditor", "ANONYMOUS", "DEFAULT_ADMIN_PATHS"]
