"""Secret / token detection in response bodies, JS, and URLs. Pure functions.

Findings quote a **masked** form of the secret (prefix + length + suffix), not the
raw value, so the audit log and reports don't themselves become a secrets leak.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

# High-signal, low-false-positive patterns for well-known credential formats.
_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", "CWE-798"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high", "CWE-798"),
    ("Google OAuth token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"), "high", "CWE-522"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high", "CWE-798"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"), "high", "CWE-798"),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"), "high", "CWE-798"),
    ("Stripe secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"), "high", "CWE-798"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "high", "CWE-321"),
    ("JSON Web Token (JWT)", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"),
     "medium", "CWE-522"),
]

# Generic "name = value" assignments — noisier, so guarded by a placeholder filter.
_ASSIGN_RE = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|secret|access[_-]?token|client[_-]?secret|auth[_-]?token|passwd|password)\b"""
    r"""\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
)
_PLACEHOLDERS = {
    "password", "changeme", "your_api_key", "yourapikey", "example", "placeholder",
    "xxxxxxxx", "test", "secret", "null", "none", "undefined",
}

# Query-string parameter names that should never carry a live secret in a URL.
_SENSITIVE_PARAMS = {
    "token", "access_token", "refresh_token", "id_token", "api_key", "apikey",
    "key", "auth", "authorization", "session", "sessionid", "sid", "password",
    "passwd", "pwd", "secret", "sig", "signature", "jwt",
}


@dataclass(frozen=True)
class SecretHit:
    kind: str          # "hardcoded" | "url-token"
    name: str          # human label, e.g. "AWS access key ID"
    masked: str        # masked secret value
    cwe: str
    confidence: str
    context: str = ""  # where it was found (URL / source location hint)


def mask(value: str) -> str:
    """Mask a secret for safe display: keep a short prefix/suffix + length."""
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}…({len(v)} chars)…{v[-2:]}"


def _looks_placeholder(value: str) -> bool:
    low = value.strip().lower()
    return (
        low in _PLACEHOLDERS
        or low.startswith(("${", "{{", "<", "your", "example"))
        or set(low) <= {"x"}
        or set(low) <= {"*"}
    )


def scan_secrets(text: str, context: str = "") -> list[SecretHit]:
    """Find hardcoded secrets/keys/tokens in a text/JS body."""
    hits: list[SecretHit] = []
    seen: set[str] = set()

    def add(name, value, cwe, confidence):
        if value in seen:
            return
        seen.add(value)
        hits.append(SecretHit("hardcoded", name, mask(value), cwe, confidence, context))

    for name, rx, confidence, cwe in _PATTERNS:
        for m in rx.finditer(text):
            add(name, m.group(0), cwe, confidence)

    for m in _ASSIGN_RE.finditer(text):
        value = m.group(2)
        if not _looks_placeholder(value):
            add(f"Hardcoded {m.group(1).lower()}", value, "CWE-798", "medium")
    return hits


def scan_url_for_tokens(url: str) -> list[SecretHit]:
    """Find secrets carried in a URL's query string (and JWTs anywhere in it)."""
    hits: list[SecretHit] = []
    try:
        parts = urlsplit(url)
    except ValueError:
        return hits
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _SENSITIVE_PARAMS and len(value) >= 6 and not _looks_placeholder(value):
            hits.append(SecretHit(
                "url-token", f"Secret in URL query parameter '{key}'",
                mask(value), "CWE-598", "high", context=_strip_query(url),
            ))
    # A JWT anywhere in the URL (path or query).
    m = re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}", url)
    if m:
        hits.append(SecretHit(
            "url-token", "JSON Web Token (JWT) in URL", mask(m.group(0)),
            "CWE-598", "high", context=_strip_query(url),
        ))
    return hits


def _strip_query(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}{p.path}" if p.scheme else url


__all__ = ["SecretHit", "scan_secrets", "scan_url_for_tokens", "mask"]
