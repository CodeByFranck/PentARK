"""Check: reflected Cross-Site Scripting (safe, non-destructive).

Approach (deliberately conservative to limit false positives):
  * Only tests query parameters that already exist on the target URL.
  * Injects a unique benign probe containing the characters that matter for
    breaking out of HTML contexts (``< > " '``) — but never a working script or
    any destructive payload. It proves *reflection without encoding*, i.e. the
    pre-condition for XSS, as a proof-of-concept only.
  * Confidence scoring:
      - **high**   : the probe (including the special characters) is reflected
                     verbatim, unencoded, in an HTML response.
      - **medium** : the probe is reflected but only some special characters
                     survive unencoded.
      - (no finding): not reflected, or reflected fully HTML-encoded.

CVSS uses the canonical reflected-XSS vector (6.1, Medium).
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.models import Finding

_XSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1 Medium
_SPECIALS = ["<", ">", '"', "'"]


def _looks_html(resp) -> bool:
    return "html" in resp.headers.get("content-type", "").lower()


class ReflectedXssCheck(Check):
    id = "reflected-xss"
    name = "Reflected XSS"

    def run(self, ctx: CheckContext) -> list[Finding]:
        parsed = urlparse(ctx.target)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []  # nothing to reflect; stay precise rather than noisy

        findings: list[Finding] = []
        for param in params:
            token = f"pentark{secrets.token_hex(4)}"
            probe = token + "".join(_SPECIALS)  # e.g. pentarkAABBCCDD<>"'
            mutated = {k: v[:] for k, v in params.items()}
            mutated[param] = [probe]
            query = urlencode(mutated, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))

            resp = ctx.http.get(test_url)
            body = resp.text

            if token not in body:
                continue  # not reflected at all
            if not _looks_html(resp):
                continue  # reflected but not in an HTML context -> not XSS here

            # How many special chars survived unencoded, right after the token?
            survived = _specials_survived(body, token)
            if not survived:
                continue  # token echoed but special chars were encoded -> safe

            confidence = "high" if len(survived) == len(_SPECIALS) else "medium"
            findings.append(
                Finding(
                    check_id=self.id,
                    name=f"Reflected XSS via '{param}' parameter",
                    endpoint=test_url,
                    cvss_vector=_XSS_VECTOR,
                    description=(
                        f"The '{param}' parameter is reflected into the HTML response "
                        "without output encoding, so attacker-controlled markup executes "
                        "in the victim's browser (reflected XSS)."
                    ),
                    remediation=(
                        "Context-aware output encoding of user input; apply a strong CSP; "
                        "validate/allowlist input where feasible."
                    ),
                    evidence=(
                        f"Probe {probe!r} reflected unencoded; special chars surviving: "
                        f"{''.join(survived)}"
                    ),
                    confidence=confidence,
                    cwe="CWE-79",
                )
            )
        return findings


def _specials_survived(body: str, token: str) -> list[str]:
    """Return the special chars that appear unencoded immediately after the token."""
    idx = body.find(token)
    if idx == -1:
        return []
    tail = body[idx + len(token): idx + len(token) + len(_SPECIALS)]
    return [c for c in _SPECIALS if c in tail]


__all__ = ["ReflectedXssCheck"]
