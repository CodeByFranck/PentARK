"""A04 – Cryptographic Failures: the concrete Check implementations."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.cvss import base_score
from pentark.assess.crypto.secrets_scan import scan_secrets, scan_url_for_tokens
from pentark.assess.crypto.tls import TlsAnalyzer, TlsInfo
from pentark.assess.models import Finding

# --- CVSS vectors (v3.1) ---------------------------------------------------
_V_CLEARTEXT_CREDS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"    # 5.9 Medium
_V_CLEARTEXT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"          # 5.9 Medium
_V_MIXED_ACTIVE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"       # 4.7 Medium
_V_MIXED_PASSIVE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"      # 3.1 Low
_V_SECRET_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"        # 7.5 High
_V_SECRET_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"         # 5.3 Medium
_V_TLS_CERT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"           # 6.8 Medium
_V_TLS_WEAK = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"           # 5.9 Medium
_V_COOKIE_SECURE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"      # 3.7 Low
_V_COOKIE_HTTPONLY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"    # 4.3 Medium
_V_COOKIE_SAMESITE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"    # 4.3 Medium

_HTTP_ATTR_ACTIVE = re.compile(
    r"""<(script|iframe|form|link|object|embed)\b[^>]*?\b(?:src|href|action|data)\s*=\s*['"](http://[^'"]+)""",
    re.I,
)
_HTTP_ATTR_PASSIVE = re.compile(
    r"""<(img|video|audio|source|track)\b[^>]*?\bsrc\s*=\s*['"](http://[^'"]+)""", re.I
)
_URL_ATTR = re.compile(r"""\b(?:src|href|action)\s*=\s*['"]([^'"]+)['"]""", re.I)


def _safe_get(ctx: CheckContext, url: str):
    try:
        return ctx.http.get(url)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Transport security: cleartext HTTP, insecure forms, mixed content
# ---------------------------------------------------------------------------

class TransportSecurityCheck(Check):
    id = "transport-security"
    name = "Insecure transport (cleartext / mixed content)"

    def run(self, ctx: CheckContext) -> list[Finding]:
        resp = ctx.http.get(ctx.target)
        html = resp.text
        scheme = urlparse(ctx.target).scheme.lower()
        has_password = bool(re.search(r"""<input\b[^>]*type\s*=\s*['"]password['"]""", html, re.I))
        findings: list[Finding] = []

        if scheme == "http":
            creds = has_password
            findings.append(Finding(
                check_id=self.id,
                name="Sensitive data over cleartext HTTP" + (" (login form)" if creds else ""),
                endpoint=ctx.target,
                cvss_vector=_V_CLEARTEXT_CREDS if creds else _V_CLEARTEXT,
                description=(
                    "The page is served over unencrypted HTTP"
                    + (", and it contains a password field — credentials are submitted in cleartext"
                       if creds else "") + ". Traffic can be read or modified by a network attacker."
                ),
                remediation="Serve the site exclusively over HTTPS and redirect HTTP to HTTPS; set HSTS.",
                evidence=f"GET {ctx.target} served over http://",
                confidence="high", cwe="CWE-319",
            ))

        # Insecure form action (regardless of page scheme).
        for _tag, url in _HTTP_ATTR_ACTIVE.findall(html):
            if _tag.lower() == "form":
                findings.append(Finding(
                    check_id=self.id, name="Form submits over cleartext HTTP",
                    endpoint=url, cvss_vector=_V_CLEARTEXT_CREDS,
                    description="A form posts to an http:// URL, exposing submitted data in transit.",
                    remediation="Point the form action at an https:// endpoint.",
                    evidence=f"<form action=\"{url}\">", confidence="high", cwe="CWE-319",
                ))

        # Mixed content only matters when the page itself is HTTPS.
        if scheme == "https":
            for tag, url in _HTTP_ATTR_ACTIVE.findall(html):
                findings.append(Finding(
                    check_id=self.id, name=f"Active mixed content (<{tag.lower()}> over HTTP)",
                    endpoint=url, cvss_vector=_V_MIXED_ACTIVE,
                    description=(
                        f"An HTTPS page loads an active sub-resource (<{tag.lower()}>) over http://, "
                        "which an attacker can tamper with to run code in the page."
                    ),
                    remediation="Load all sub-resources over HTTPS; add a CSP 'upgrade-insecure-requests'.",
                    evidence=f"<{tag.lower()} ...=\"{url}\"> on an HTTPS page",
                    confidence="high", cwe="CWE-311",
                ))
            for tag, url in _HTTP_ATTR_PASSIVE.findall(html):
                findings.append(Finding(
                    check_id=self.id, name=f"Passive mixed content (<{tag.lower()}> over HTTP)",
                    endpoint=url, cvss_vector=_V_MIXED_PASSIVE,
                    description=f"An HTTPS page loads a passive resource (<{tag.lower()}>) over http://.",
                    remediation="Load all sub-resources over HTTPS.",
                    evidence=f"<{tag.lower()} src=\"{url}\"> on an HTTPS page",
                    confidence="high", cwe="CWE-311",
                ))
        return findings


# ---------------------------------------------------------------------------
# Weak TLS (protocol / cipher / certificate)
# ---------------------------------------------------------------------------

class WeakTlsCheck(Check):
    id = "weak-tls"
    name = "Weak TLS configuration / certificate"

    def __init__(self, analyzer: TlsAnalyzer | None = None) -> None:
        self._analyzer = analyzer

    def run(self, ctx: CheckContext) -> list[Finding]:
        parsed = urlparse(ctx.target)
        if parsed.scheme.lower() != "https":
            return []  # nothing to analyze on a cleartext endpoint
        host = parsed.hostname
        if not host:
            return []
        port = parsed.port or 443
        analyzer = self._analyzer or TlsAnalyzer()
        info = analyzer.analyze(host, port)
        return _tls_findings(ctx.target, info)


def _tls_findings(target: str, info: TlsInfo) -> list[Finding]:
    if info.error and not info.connected:
        return []  # not reachable / not a TLS service — don't guess
    findings: list[Finding] = []

    def add(name, vector, desc, remediation, evidence, cwe, confidence="high"):
        findings.append(Finding(
            check_id="weak-tls", name=name, endpoint=target, cvss_vector=vector,
            description=desc, remediation=remediation, evidence=evidence,
            confidence=confidence, cwe=cwe,
        ))

    if info.expired:
        add("Expired TLS certificate", _V_TLS_CERT,
            "The server's TLS certificate has expired; clients cannot validate the connection.",
            "Renew the certificate and automate renewal (e.g. ACME).",
            info.verify_error or (f"notAfter={info.not_after.isoformat()}" if info.not_after else "expired"),
            "CWE-298")
    if info.self_signed:
        add("Self-signed / untrusted TLS certificate", _V_TLS_CERT,
            "The certificate is self-signed or not chained to a trusted CA, so MITM cannot be detected.",
            "Install a certificate issued by a trusted CA.",
            info.verify_error or "self-signed", "CWE-295")
    if info.hostname_mismatch:
        add("TLS certificate hostname mismatch", _V_TLS_CERT,
            "The certificate does not match the requested hostname.",
            "Issue a certificate whose SAN covers this hostname.",
            info.verify_error or "hostname mismatch", "CWE-297")
    if info.weak_protocols:
        add(f"Deprecated TLS protocol(s) enabled: {', '.join(info.weak_protocols)}", _V_TLS_WEAK,
            "The server still negotiates obsolete TLS versions vulnerable to downgrade/known attacks.",
            "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
            f"accepted: {', '.join(info.weak_protocols)}", "CWE-326")
    elif info.negotiated_below_tls12:
        add(f"Obsolete TLS version negotiated ({info.protocol})", _V_TLS_WEAK,
            "The connection negotiated a TLS version below 1.2.",
            "Require TLS 1.2 or higher.", f"negotiated {info.protocol}", "CWE-326")
    if info.weak_cipher:
        add(f"Weak TLS cipher negotiated ({info.weak_cipher})", _V_TLS_WEAK,
            f"The negotiated cipher suite {info.cipher!r} uses weak primitives ({info.weak_cipher}).",
            "Restrict ciphers to strong AEAD suites (e.g. AES-GCM, ChaCha20-Poly1305).",
            f"cipher={info.cipher}", "CWE-327")
    return findings


# ---------------------------------------------------------------------------
# Secret exposure in responses / JS / URLs
# ---------------------------------------------------------------------------

class SecretsExposureCheck(Check):
    id = "secrets-exposure"
    name = "Secrets / tokens exposed in content or URLs"

    def __init__(self, *, max_scripts: int = 8) -> None:
        self.max_scripts = max_scripts

    def run(self, ctx: CheckContext) -> list[Finding]:
        resp = ctx.http.get(ctx.target)
        html = resp.text
        target_host = urlparse(ctx.target).hostname
        findings: list[Finding] = []

        # Secrets in the page itself.
        for hit in scan_secrets(html, context=ctx.target):
            findings.append(_secret_finding(hit))

        # Secrets in same-origin JS files + tokens in the URLs the page references.
        urls = _URL_ATTR.findall(html)
        fetched = 0
        for raw in urls:
            abs_url = urljoin(ctx.target, raw)
            for hit in scan_url_for_tokens(abs_url):
                findings.append(_secret_finding(hit))
            if (
                fetched < self.max_scripts
                and abs_url.lower().endswith(".js")
                and urlparse(abs_url).hostname == target_host
            ):
                r = _safe_get(ctx, abs_url)
                if r is not None and r.status_code == 200:
                    fetched += 1
                    for hit in scan_secrets(r.text, context=abs_url):
                        findings.append(_secret_finding(hit))

        # Tokens in the target URL itself.
        for hit in scan_url_for_tokens(ctx.target):
            findings.append(_secret_finding(hit))

        return _dedupe(findings)


def _secret_finding(hit) -> Finding:
    high = hit.confidence == "high" and hit.kind == "hardcoded"
    vector = _V_SECRET_HIGH if high else _V_SECRET_MED
    return Finding(
        check_id="secrets-exposure",
        name=hit.name,
        endpoint=hit.context or "response",
        cvss_vector=vector,
        description=(
            f"{hit.name} was found exposed to the client ({hit.kind}). Secrets delivered to the "
            "browser or placed in URLs can be harvested and reused."
        ),
        remediation=(
            "Never ship secrets to the client or put them in URLs; move them server-side, rotate any "
            "exposed value, and use short-lived tokens sent in headers/POST bodies."
        ),
        evidence=f"{hit.name}: {hit.masked}" + (f" @ {hit.context}" if hit.context else ""),
        confidence=hit.confidence,
        cwe=hit.cwe,
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())


# ---------------------------------------------------------------------------
# Cookie security flags
# ---------------------------------------------------------------------------

_SESSIONISH = ("session", "sess", "sid", "auth", "token", "jwt", "csrf", "login")


class CookieSecurityCheck(Check):
    id = "cookie-security"
    name = "Cookies missing security flags"

    def run(self, ctx: CheckContext) -> list[Finding]:
        resp = ctx.http.get(ctx.target)
        findings: list[Finding] = []
        for raw in resp.headers.get_list("set-cookie"):
            name, missing = _cookie_gaps(raw)
            if not missing:
                continue
            sessionish = any(s in name.lower() for s in _SESSIONISH)
            vector = max(
                (_FLAG_VECTOR[f] for f in missing), key=lambda v: base_score(v)
            )
            findings.append(Finding(
                check_id=self.id,
                name=f"Cookie '{name}' missing {', '.join(missing)}",
                endpoint=ctx.target,
                cvss_vector=vector,
                description=(
                    f"The cookie {name!r} is set without the {', '.join(missing)} attribute(s), "
                    "weakening it against interception, theft via XSS, or CSRF."
                ),
                remediation="Set Secure, HttpOnly, and an explicit SameSite (Lax/Strict) on session cookies.",
                evidence=f"Set-Cookie: {raw[:120]}",
                confidence="high" if sessionish else "medium",
                cwe=_FLAG_CWE[missing[0]],
            ))
        return findings


_FLAG_VECTOR = {
    "Secure": _V_COOKIE_SECURE,
    "HttpOnly": _V_COOKIE_HTTPONLY,
    "SameSite": _V_COOKIE_SAMESITE,
}
_FLAG_CWE = {"Secure": "CWE-614", "HttpOnly": "CWE-1004", "SameSite": "CWE-1275"}


def _cookie_gaps(raw: str) -> tuple[str, list[str]]:
    name = raw.split("=", 1)[0].strip()
    low = raw.lower()
    missing = []
    if "secure" not in low:
        missing.append("Secure")
    if "httponly" not in low:
        missing.append("HttpOnly")
    if "samesite" not in low:
        missing.append("SameSite")
    return name, missing


__all__ = [
    "TransportSecurityCheck",
    "WeakTlsCheck",
    "SecretsExposureCheck",
    "CookieSecurityCheck",
]
