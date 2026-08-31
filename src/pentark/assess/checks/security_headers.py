"""Check: missing HTTP security headers (OWASP: Security Misconfiguration).

Deterministic and passive — a single GET, then inspect response headers. Because
the signal is unambiguous (a header is present or it isn't), findings are
reported with **high** confidence. Each header carries its own CVSS vector so the
severity reflects that header's actual impact (e.g. a missing CSP outranks a
missing Referrer-Policy).
"""

from __future__ import annotations

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.models import Finding

# header -> (finding name, CVSS v3.1 vector, CWE, remediation)
_HEADERS = {
    "content-security-policy": (
        "Missing Content-Security-Policy header",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",  # 5.4 Medium
        "CWE-693",
        "Define a restrictive Content-Security-Policy to mitigate XSS and data injection.",
    ),
    "strict-transport-security": (
        "Missing HTTP Strict-Transport-Security (HSTS) header",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",  # 4.2 Medium
        "CWE-319",
        "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' over HTTPS.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # 3.1 Low
        "CWE-16",
        "Send 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "x-frame-options": (
        "Missing X-Frame-Options / frame-ancestors (clickjacking)",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  # 4.3 Medium
        "CWE-1021",
        "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        "Missing Referrer-Policy header",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",  # 3.1 Low
        "CWE-200",
        "Send 'Referrer-Policy: no-referrer' or 'strict-origin-when-cross-origin'.",
    ),
}


class SecurityHeadersCheck(Check):
    id = "security-headers"
    name = "HTTP security headers"

    def run(self, ctx: CheckContext) -> list[Finding]:
        resp = ctx.http.get(ctx.target)
        present = {k.lower() for k in resp.headers.keys()}
        findings: list[Finding] = []
        for header, (name, vector, cwe, remediation) in _HEADERS.items():
            if header not in present:
                findings.append(
                    Finding(
                        check_id=self.id,
                        name=name,
                        endpoint=ctx.target,
                        cvss_vector=vector,
                        description=(
                            f"The response from {ctx.target} does not set the "
                            f"'{header}' header, weakening browser-side defenses."
                        ),
                        remediation=remediation,
                        evidence=f"Response headers present: {sorted(present)}",
                        confidence="high",
                        cwe=cwe,
                    )
                )
        return findings


__all__ = ["SecurityHeadersCheck"]
