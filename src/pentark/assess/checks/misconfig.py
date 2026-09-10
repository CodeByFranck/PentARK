"""Checks: A02 – Security Misconfiguration.

A family of focused, mostly-passive checks (each a :class:`Check`, so the runner
picks them up automatically):

* :class:`WeakHeadersCheck`        — security headers present but weak (the
  *presence* of headers is handled by :class:`SecurityHeadersCheck`; this looks at
  their *values*) plus version-disclosing ``Server`` / ``X-Powered-By``.
* :class:`SensitiveFileExposureCheck` — ``.git/``, ``.env``, backups, key files,
  confirmed by a content signature (not a bare 200) to keep false positives down.
* :class:`DirectoryListingCheck`   — Apache/nginx/Python autoindex pages.
* :class:`VerboseErrorCheck`       — stack traces / framework debug pages.
* :class:`HttpMethodsCheck`        — HTTP TRACE enabled (Cross-Site Tracing).
* :class:`DefaultCredentialsCheck` — a small built-in credential list against a
  discovered login form. **Active** (submits logins), so it is NOT in the default
  registry — opt in with ``assess --default-creds``.

Every finding quotes the exact header value or URL path it fired on as evidence.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import urljoin, urlparse

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.models import Finding

# Reusable CVSS vectors (v3.1).
_V_INFO_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"       # 3.7 Low
_V_INFO_MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"       # 5.3 Medium
_V_DISCLOSE_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5 High
_V_WEAK_CSP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"       # 5.4 Medium
_V_DEFAULT_CREDS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 Critical


def _base(target: str) -> str:
    """The scheme://host[:port]/ root, for probing absolute paths."""
    p = urlparse(target)
    return f"{p.scheme}://{p.netloc}/"


def _safe_get(ctx: CheckContext, url: str):
    """GET that never lets one dead endpoint abort a whole check."""
    try:
        return ctx.http.get(url)
    except Exception:  # network hiccup on a probe path is not fatal here
        return None


# ---------------------------------------------------------------------------
# Weak header values + version disclosure
# ---------------------------------------------------------------------------

class WeakHeadersCheck(Check):
    id = "weak-headers"
    name = "Weak security header values"

    def run(self, ctx: CheckContext) -> list[Finding]:
        resp = ctx.http.get(ctx.target)
        h = {k.lower(): v for k, v in resp.headers.items()}
        findings: list[Finding] = []

        def add(name, value, vector, cwe, remediation, confidence="high"):
            findings.append(
                Finding(
                    check_id=self.id, name=name, endpoint=ctx.target,
                    cvss_vector=vector, description=name + ".",
                    remediation=remediation,
                    evidence=f"{value}", confidence=confidence, cwe=cwe,
                )
            )

        csp = h.get("content-security-policy")
        if csp:
            weak = [t for t in ("unsafe-inline", "unsafe-eval") if t in csp.lower()]
            if "default-src *" in csp.lower() or re.search(r"script-src[^;]*\*", csp.lower()):
                weak.append("wildcard source")
            if weak:
                add(
                    "Weak Content-Security-Policy",
                    f"Content-Security-Policy: {csp}  (weak: {', '.join(weak)})",
                    _V_WEAK_CSP, "CWE-693",
                    "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; use nonces/hashes.",
                )

        hsts = h.get("strict-transport-security")
        if hsts is not None:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts.lower())
            age = int(m.group(1)) if m else 0
            if age < 15552000:  # < 180 days
                add(
                    "Weak HTTP Strict-Transport-Security (low/absent max-age)",
                    f"Strict-Transport-Security: {hsts}  (max-age={age})",
                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", "CWE-319",
                    "Set 'max-age=31536000; includeSubDomains' (and preload where appropriate).",
                )

        xcto = h.get("x-content-type-options")
        if xcto is not None and xcto.strip().lower() != "nosniff":
            add(
                "Weak X-Content-Type-Options value",
                f"X-Content-Type-Options: {xcto}",
                _V_INFO_LOW, "CWE-16",
                "Set exactly 'X-Content-Type-Options: nosniff'.",
            )

        xfo = h.get("x-frame-options")
        if xfo is not None and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
            add(
                "Weak X-Frame-Options value (clickjacking)",
                f"X-Frame-Options: {xfo}",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "CWE-1021",
                "Use 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            )

        for header in ("server", "x-powered-by"):
            val = h.get(header)
            if val and re.search(r"\d", val):  # a version number leaks the stack
                add(
                    f"Technology/version disclosure via '{header}' header",
                    f"{header.title()}: {val}",
                    _V_INFO_LOW, "CWE-200",
                    f"Suppress or genericize the '{header}' header to hide software versions.",
                    confidence="medium",
                )
        return findings


# ---------------------------------------------------------------------------
# Sensitive file / path exposure
# ---------------------------------------------------------------------------

def _sig_git_head(r) -> bool:
    return r.text.strip().startswith("ref:") or "refs/heads" in r.text


def _sig_env(r) -> bool:
    body = r.text
    return bool(re.search(r"^[A-Z0-9_]{2,}=", body, re.M)) and any(
        k in body for k in ("APP_KEY", "SECRET", "PASSWORD", "DB_", "API_KEY", "TOKEN")
    )


def _sig_sql(r) -> bool:
    up = r.text.upper()
    return any(s in up for s in ("INSERT INTO", "CREATE TABLE", "MYSQL DUMP", "DROP TABLE"))


def _sig_private_key(r) -> bool:
    return "-----BEGIN" in r.text and "PRIVATE KEY" in r.text


def _sig_code_backup(r) -> bool:
    # A backup of server-side source served as text (not rendered).
    ct = r.headers.get("content-type", "").lower()
    if "html" in ct:
        return False
    return any(m in r.text for m in ("<?php", "<%", "def ", "function ", "password", "SECRET"))


# path, human name, signature predicate, (vector, cwe, confidence, remediation)
_SENSITIVE = [
    (".git/HEAD", "Exposed Git repository (.git/HEAD)", _sig_git_head,
     _V_DISCLOSE_HIGH, "CWE-538", "high",
     "Block access to .git/ at the web server; never deploy the VCS directory."),
    (".git/config", "Exposed Git config (.git/config)", lambda r: "[core]" in r.text,
     _V_DISCLOSE_HIGH, "CWE-538", "high",
     "Block access to .git/ at the web server."),
    (".env", "Exposed environment file (.env)", _sig_env,
     _V_DISCLOSE_HIGH, "CWE-538", "high",
     "Move secrets out of web root; deny access to dotfiles; rotate any leaked secrets."),
    ("config.php.bak", "Exposed backup of config.php", _sig_code_backup,
     _V_DISCLOSE_HIGH, "CWE-530", "medium",
     "Remove editor/backup files from the web root; deny .bak/.old/~ extensions."),
    ("index.php.bak", "Exposed backup source (index.php.bak)", _sig_code_backup,
     _V_DISCLOSE_HIGH, "CWE-530", "medium",
     "Remove editor/backup files from the web root."),
    ("backup.zip", "Exposed backup archive (backup.zip)", lambda r: r.content[:2] == b"PK",
     _V_DISCLOSE_HIGH, "CWE-530", "medium",
     "Remove archive backups from the web root."),
    ("database.sql", "Exposed database dump (database.sql)", _sig_sql,
     _V_DISCLOSE_HIGH, "CWE-538", "high",
     "Remove SQL dumps from the web root; rotate exposed data/credentials."),
    ("dump.sql", "Exposed database dump (dump.sql)", _sig_sql,
     _V_DISCLOSE_HIGH, "CWE-538", "high",
     "Remove SQL dumps from the web root."),
    (".htaccess", "Exposed .htaccess", lambda r: "RewriteEngine" in r.text or "Order " in r.text,
     _V_INFO_MED, "CWE-538", "medium",
     "Deny access to .htaccess."),
    ("web.config", "Exposed web.config", lambda r: "<configuration" in r.text.lower(),
     _V_INFO_MED, "CWE-538", "medium",
     "Deny access to web.config."),
    ("id_rsa", "Exposed SSH private key (id_rsa)", _sig_private_key,
     _V_DISCLOSE_HIGH, "CWE-538", "high",
     "Remove private keys from the web root and rotate them immediately."),
    ("phpinfo.php", "Exposed phpinfo()", lambda r: "phpinfo()" in r.text or "PHP Version" in r.text,
     _V_INFO_MED, "CWE-200", "high",
     "Remove phpinfo pages from production."),
    (".DS_Store", "Exposed .DS_Store (directory metadata)", lambda r: r.content[:4] == b"\x00\x00\x00\x01",
     _V_INFO_LOW, "CWE-538", "high",
     "Remove .DS_Store files and deny dotfiles."),
]


class SensitiveFileExposureCheck(Check):
    id = "sensitive-file-exposure"
    name = "Sensitive file / path exposure"

    def run(self, ctx: CheckContext) -> list[Finding]:
        base = _base(ctx.target)
        # Baseline: a random path. If the app 200s everything (SPA catch-all),
        # only a real signature match should count — and never one that matches
        # the baseline body.
        baseline = _safe_get(ctx, urljoin(base, f"pentark-{secrets.token_hex(6)}"))
        baseline_body = baseline.text if baseline is not None else None

        findings: list[Finding] = []
        for path, name, sig, vector, cwe, confidence, remediation in _SENSITIVE:
            url = urljoin(base, path)
            resp = _safe_get(ctx, url)
            if resp is None or resp.status_code != 200:
                continue
            if baseline_body is not None and resp.text == baseline_body:
                continue  # catch-all echo, not a real file
            try:
                if not sig(resp):
                    continue
            except Exception:
                continue
            snippet = resp.text[:120].replace("\n", " ").strip()
            findings.append(
                Finding(
                    check_id=self.id, name=name, endpoint=url, cvss_vector=vector,
                    description=(
                        f"{name} is retrievable at {path!r} (HTTP 200 with matching content)."
                    ),
                    remediation=remediation,
                    evidence=f"GET {url} -> 200; body starts: {snippet!r}",
                    confidence=confidence, cwe=cwe,
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Directory listing
# ---------------------------------------------------------------------------

_LISTING_MARKERS = ("Index of /", "<title>Index of", "Directory listing for", "[To Parent Directory]")
_DIR_PATHS = ("", "uploads/", "images/", "files/", "backup/", "assets/", "static/", "data/")


class DirectoryListingCheck(Check):
    id = "directory-listing"
    name = "Directory listing enabled"

    def run(self, ctx: CheckContext) -> list[Finding]:
        base = _base(ctx.target)
        findings: list[Finding] = []
        for rel in _DIR_PATHS:
            url = urljoin(base, rel)
            resp = _safe_get(ctx, url)
            if resp is None or resp.status_code != 200:
                continue
            marker = next((m for m in _LISTING_MARKERS if m in resp.text), None)
            if marker is None:
                continue
            findings.append(
                Finding(
                    check_id=self.id,
                    name=f"Directory listing enabled at /{rel}",
                    endpoint=url,
                    cvss_vector=_V_INFO_MED,
                    description=(
                        f"The server returns an automatic index for /{rel}, exposing the "
                        "names (and often contents) of files not meant to be browsable."
                    ),
                    remediation="Disable autoindex (Apache 'Options -Indexes', nginx 'autoindex off').",
                    evidence=f"GET {url} -> 200 containing {marker!r}",
                    confidence="high", cwe="CWE-548",
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Verbose errors / stack traces
# ---------------------------------------------------------------------------

# (regex, technology) — signatures of a leaked stack trace / debug page.
_ERROR_SIGNATURES = [
    (r"Traceback \(most recent call last\)", "Python"),
    (r"Werkzeug Debugger", "Flask/Werkzeug"),
    (r"django\.core|DisallowedHost|DEBUG = True", "Django"),
    (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java"),
    (r"javax?\.servlet|org\.springframework", "Java/Spring"),
    (r"System\.Web|Microsoft\.\w+Exception|at [\w.]+\+?<", ".NET"),
    (r"(PHP (Warning|Fatal error|Notice)|Stack trace:|Uncaught \w+Exception)", "PHP"),
    (r"(ORA-\d{5}|SQLSTATE\[|You have an error in your SQL syntax)", "SQL"),
    (r"Ruby on Rails|ActionController|app/controllers/", "Rails"),
]


class VerboseErrorCheck(Check):
    id = "verbose-errors"
    name = "Verbose error / stack-trace disclosure"

    def run(self, ctx: CheckContext) -> list[Finding]:
        base = _base(ctx.target)
        token = secrets.token_hex(4)
        probes = [
            urljoin(base, f"pentark-error-{token}"),          # missing path
            f"{ctx.target}{'&' if urlparse(ctx.target).query else '?'}pentark[]={token}",  # bad param shape
            f"{ctx.target}{'&' if urlparse(ctx.target).query else '?'}pentark={token}%27%22",  # quotes
        ]
        seen: set[str] = set()
        findings: list[Finding] = []
        for url in probes:
            resp = _safe_get(ctx, url)
            if resp is None:
                continue
            for pattern, tech in _ERROR_SIGNATURES:
                m = re.search(pattern, resp.text)
                if not m or tech in seen:
                    continue
                seen.add(tech)
                snippet = resp.text[max(0, m.start() - 20): m.start() + 100].replace("\n", " ").strip()
                findings.append(
                    Finding(
                        check_id=self.id,
                        name=f"Verbose {tech} error / stack trace disclosed",
                        endpoint=url,
                        cvss_vector=_V_INFO_MED,
                        description=(
                            f"An error response leaked a {tech} stack trace / debug page, "
                            "revealing internal paths, framework versions, or SQL. Debug mode "
                            "appears to be on in production."
                        ),
                        remediation=(
                            "Disable debug mode in production; return generic error pages; log "
                            "details server-side only."
                        ),
                        evidence=f"HTTP {resp.status_code} at {url} matched {tech}: ...{snippet}...",
                        confidence="high", cwe="CWE-209",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# HTTP TRACE (Cross-Site Tracing)
# ---------------------------------------------------------------------------

class HttpMethodsCheck(Check):
    id = "http-trace"
    name = "HTTP TRACE method enabled"

    def run(self, ctx: CheckContext) -> list[Finding]:
        token = f"Pentark-{secrets.token_hex(4)}"
        try:
            resp = ctx.http.request("TRACE", ctx.target, headers={"X-Pentark-Trace": token})
        except Exception:
            return []
        # XST: TRACE is honored (200) and the server echoes the request back.
        echoed = token in resp.text or "TRACE " in resp.text.upper()
        if resp.status_code != 200 or not echoed:
            return []
        return [
            Finding(
                check_id=self.id,
                name="HTTP TRACE method enabled (Cross-Site Tracing)",
                endpoint=ctx.target,
                cvss_vector=_V_INFO_MED,
                description=(
                    "The server responds to TRACE by echoing the request, enabling "
                    "Cross-Site Tracing (XST) to read headers such as cookies."
                ),
                remediation="Disable the TRACE method at the web server / load balancer.",
                evidence=f"TRACE {ctx.target} -> HTTP {resp.status_code}, echoed marker {token!r}",
                confidence="high", cwe="CWE-16",
            )
        ]


# ---------------------------------------------------------------------------
# Default credentials (ACTIVE — opt in via `assess --default-creds`)
# ---------------------------------------------------------------------------

_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("administrator", "administrator"), ("root", "root"), ("root", "toor"),
    ("test", "test"), ("guest", "guest"), ("admin", "changeme"), ("admin", ""),
]
_USER_FIELDS = ("username", "user", "email", "login", "userid", "name")
_PASS_FIELDS = ("password", "pass", "passwd", "pwd")


class DefaultCredentialsCheck(Check):
    id = "default-credentials"
    name = "Default credentials accepted"

    def run(self, ctx: CheckContext) -> list[Finding]:
        resp = ctx.http.get(ctx.target)
        form = _find_login_form(resp.text)
        if form is None:
            return []
        action, user_field, pass_field, hidden = form
        post_url = urljoin(ctx.target, action) if action else ctx.target

        baseline_len = len(resp.text)
        for username, password in _DEFAULT_CREDS:
            data = dict(hidden)
            data[user_field] = username
            data[pass_field] = password
            try:
                r = ctx.http.request("POST", post_url, data=data, follow_redirects=False)
            except Exception:
                continue
            if _login_succeeded(r, baseline_len):
                shown_pw = password or "<empty>"
                return [
                    Finding(
                        check_id=self.id,
                        name=f"Default credentials accepted ({username}/{shown_pw})",
                        endpoint=post_url,
                        cvss_vector=_V_DEFAULT_CREDS,
                        description=(
                            f"The login form at {post_url} accepted the well-known default "
                            f"credentials {username!r}/{shown_pw!r}, granting authenticated access."
                        ),
                        remediation=(
                            "Remove/rotate all default accounts and passwords; enforce a strong "
                            "password policy and lockout/rate-limiting on login."
                        ),
                        evidence=(
                            f"POST {post_url} as {username}/{shown_pw} -> HTTP {r.status_code}"
                            + (f", Location: {r.headers.get('location')}" if r.is_redirect else "")
                        ),
                        confidence="medium", cwe="CWE-1392",
                    )
                ]
        return []


_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""\baction\s*=\s*["']?([^"'\s>]+)""", re.I)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"""(\w+)\s*=\s*["']?([^"'\s>]*)""")


def _find_login_form(html: str):
    """Return (action, user_field, pass_field, hidden_fields) for the first form
    that has a password input, or None."""
    for fm in _FORM_RE.finditer(html):
        block = fm.group(0)
        inputs = [dict(_ATTR_RE.findall(tag)) for tag in _INPUT_RE.findall(block)]
        pass_field = _match_field(inputs, _PASS_FIELDS, prefer_type="password")
        if not pass_field:
            continue
        user_field = _match_field(inputs, _USER_FIELDS) or "username"
        hidden = {
            i["name"]: i.get("value", "")
            for i in inputs
            if i.get("type", "").lower() == "hidden" and i.get("name")
        }
        action_m = _ACTION_RE.search(block)
        return (action_m.group(1) if action_m else "", user_field, pass_field, hidden)
    return None


def _match_field(inputs, names, *, prefer_type: str | None = None) -> str | None:
    if prefer_type:
        for i in inputs:
            if i.get("type", "").lower() == prefer_type and i.get("name"):
                return i["name"]
    for i in inputs:
        nm = i.get("name", "").lower()
        if nm and any(n in nm for n in names):
            return i["name"]
    return None


def _login_succeeded(resp, baseline_len: int) -> bool:
    """Heuristic: a redirect away from the form, or a markedly different page
    that no longer shows the login form and hints at a session."""
    if resp.is_redirect:
        loc = resp.headers.get("location", "").lower()
        return not any(x in loc for x in ("login", "signin", "error", "denied"))
    body = resp.text.lower()
    if "logout" in body or "sign out" in body:
        return True
    if resp.headers.get("set-cookie") and _find_login_form(resp.text) is None:
        return abs(len(resp.text) - baseline_len) > max(64, baseline_len // 5)
    return False


__all__ = [
    "WeakHeadersCheck",
    "SensitiveFileExposureCheck",
    "DirectoryListingCheck",
    "VerboseErrorCheck",
    "HttpMethodsCheck",
    "DefaultCredentialsCheck",
]
