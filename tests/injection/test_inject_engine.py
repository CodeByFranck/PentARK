"""Tests for the injection scanner (target mocked; timing injected via header)."""

from __future__ import annotations

import re

import httpx

from pentark.assess.injection.confirmers import SqlmapResult
from pentark.assess.injection.engine import InjectionScanner

TARGET = "http://localhost:3000/item?id=1"

_DELAY_RE = re.compile(
    r"SLEEP\((\d+)\)|PG_SLEEP\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'|sleep (\d+)|timeout /t (\d+)|ping -c (\d+)",
    re.I,
)


def _delay_for(blob: str) -> float:
    m = _DELAY_RE.search(blob)
    if not m:
        return 0.0
    nums = [g for g in m.groups() if g]
    return float(nums[0]) if nums else 0.0


def _html(text: str, delay: float = 0.0) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html", "x-elapsed": str(delay)}, text=text)


def _values(request) -> str:
    """Decoded parameter values (query + form body), as a real server sees them."""
    from urllib.parse import parse_qsl

    vals = [v for _, v in request.url.params.multi_items()]
    if request.content:
        vals += [v for _, v in parse_qsl(request.content.decode(errors="ignore"))]
    return " ".join(vals)


# Backwards-compatible alias used by the handlers below.
_blob = _values


def _scanner(http_factory, handler, **kw):
    http = http_factory(handler)
    return InjectionScanner(
        http, elapsed_of=lambda r: float(r.headers.get("x-elapsed", "0")), **kw
    )


# -- SQLi -------------------------------------------------------------------

def test_error_based_sqli(http_factory):
    def handler(request):
        if "'" in _values(request):
            return _html("You have an error in your SQL syntax; check MySQL server")
        return _html("<html>ok</html>")

    findings = _scanner(http_factory, handler).run(TARGET)
    assert any(f.check_id == "injection-sqli" and "error-based" in f.name for f in findings)
    assert all(f.cwe == "CWE-89" for f in findings if f.check_id == "injection-sqli")


def test_time_based_sqli(http_factory):
    def handler(request):
        blob = _blob(request)
        return _html("<html>ok</html>", delay=_delay_for(blob))

    findings = _scanner(http_factory, handler).run(TARGET)
    sqli = [f for f in findings if f.check_id == "injection-sqli"]
    assert sqli and "time-based" in sqli[0].name
    assert sqli[0].severity == "Critical"


def test_sqlmap_banner_included(http_factory):
    class StubSqlmap:
        def confirm(self, point, value):
            return SqlmapResult(True, banner="MySQL 5.7.29")

    def handler(request):
        if "'" in _values(request):
            return _html("SQL syntax error near MySQL")
        return _html("ok")

    findings = _scanner(http_factory, handler, sqlmap=StubSqlmap()).run(TARGET)
    sqli = next(f for f in findings if f.check_id == "injection-sqli")
    assert "MySQL 5.7.29" in sqli.evidence


# -- command injection ------------------------------------------------------

def test_command_injection(http_factory):
    def handler(request):
        return _html("<html>ok</html>", delay=_delay_for(_blob(request)))

    # This same handler delays on any sleep-like payload, so both SQLi-time and
    # cmd-injection can fire; assert the command-injection one is present.
    findings = _scanner(http_factory, handler).run(TARGET)
    assert any(f.check_id == "injection-cmd-injection" and f.cwe == "CWE-78" for f in findings)


# -- SSTI -------------------------------------------------------------------

def test_ssti(http_factory):
    def handler(request):
        blob = _blob(request)
        if "269*271" in blob:
            return _html("<p>result 72899</p>")   # evaluated
        return _html("<p>clean</p>")

    findings = _scanner(http_factory, handler).run(TARGET)
    ssti = [f for f in findings if f.check_id == "injection-ssti"]
    assert ssti and ssti[0].severity == "Critical"
    assert "72899" in ssti[0].evidence


def test_ssti_not_evaluated_is_clean(http_factory):
    def handler(request):
        # Reflects the expression literally -> NOT evaluated -> no SSTI.
        blob = _blob(request)
        m = re.search(r"269\*271", blob)
        return _html(f"<p>{'269*271' if m else 'clean'}</p>")

    findings = _scanner(http_factory, handler).run(TARGET)
    assert [f for f in findings if f.check_id == "injection-ssti"] == []


# -- XSS --------------------------------------------------------------------

def test_reflected_xss(http_factory):
    def handler(request):
        # Reflect the injected value unescaped.
        import urllib.parse as u
        val = u.parse_qs(u.urlsplit(str(request.url)).query).get("id", [""])[0]
        return _html(f"<div>{val}</div>")

    findings = _scanner(http_factory, handler).run(TARGET)
    xss = [f for f in findings if f.check_id == "injection-xss"]
    assert xss and "Reflected XSS" in xss[0].name
    assert xss[0].cwe == "CWE-79"


def test_xss_dom_confirmation(http_factory):
    class StubBrowser:
        def confirm(self, url):
            return True

    def handler(request):
        import urllib.parse as u
        val = u.parse_qs(u.urlsplit(str(request.url)).query).get("id", [""])[0]
        return _html(f"<div>{val}</div>")

    findings = _scanner(http_factory, handler, xss_confirmer=StubBrowser()).run(TARGET)
    xss = next(f for f in findings if f.check_id == "injection-xss")
    assert "DOM execution confirmed" in xss.evidence


# -- clean + safety ---------------------------------------------------------

def test_clean_app_has_no_findings(http_factory):
    def handler(request):
        import html as h
        import urllib.parse as u
        val = u.parse_qs(u.urlsplit(str(request.url)).query).get("id", [""])[0]
        return _html(f"<div>{h.escape(val)}</div>")   # escaped, no delay, no error

    assert _scanner(http_factory, handler).run(TARGET) == []


def test_post_forms_skipped_unless_opted_in(http_factory):
    def handler(request):
        if request.method == "GET" and not request.url.query:
            return _html("<form method='post' action='/submit'><input name='q'></form>")
        if "269*271" in _blob(request):
            return _html("<p>72899</p>")
        return _html("<p>ok</p>")

    base = "http://localhost:3000/"
    assert _scanner(http_factory, handler).run(base) == []                      # POST form skipped
    opted = _scanner(http_factory, handler, include_post_forms=True).run(base)
    assert any(f.check_id == "injection-ssti" for f in opted)                    # now tested
