"""Tests for the HTTP-layer A04 checks: transport, secrets, cookies."""

from __future__ import annotations

import httpx

from pentark.assess.checks.base import CheckContext
from pentark.assess.crypto.checks import (
    CookieSecurityCheck,
    SecretsExposureCheck,
    TransportSecurityCheck,
)

HTTP = "http://localhost:3000/"
HTTPS = "https://localhost:3000/"


def _ctx(http, target):
    return CheckContext(http=http, target=target)


# -- transport --------------------------------------------------------------

def test_cleartext_login_over_http(http_factory):
    def handler(request):
        return httpx.Response(200, text="<form><input type='password' name='p'></form>")

    findings = TransportSecurityCheck().run(_ctx(http_factory(handler), HTTP))
    f = next(f for f in findings if f.check_id == "transport-security")
    assert "cleartext HTTP" in f.name and "login form" in f.name
    assert f.cwe == "CWE-319"


def test_https_page_is_not_cleartext(http_factory):
    def handler(request):
        return httpx.Response(200, text="<html>secure</html>")

    findings = TransportSecurityCheck().run(_ctx(http_factory(handler), HTTPS))
    assert findings == []


def test_active_mixed_content_on_https(http_factory):
    def handler(request):
        return httpx.Response(200, text="<script src='http://cdn.evil/x.js'></script>")

    findings = TransportSecurityCheck().run(_ctx(http_factory(handler), HTTPS))
    assert any("Active mixed content" in f.name and f.cwe == "CWE-311" for f in findings)


def test_insecure_form_action(http_factory):
    def handler(request):
        return httpx.Response(200, text="<form action='http://api.test/login'></form>")

    findings = TransportSecurityCheck().run(_ctx(http_factory(handler), HTTPS))
    assert any("Form submits over cleartext HTTP" in f.name for f in findings)


# -- secrets ----------------------------------------------------------------

def test_secret_in_html_and_js(http_factory):
    js = "var awsKey='AKIAIOSFODNN7EXAMPLE';"

    def handler(request):
        if request.url.path == "/app.js":
            return httpx.Response(200, text=js)
        return httpx.Response(200, text="<script src='/app.js'></script><a href='/d?token=abcdef12'>x</a>")

    findings = SecretsExposureCheck().run(_ctx(http_factory(handler), HTTP))
    names = {f.name for f in findings}
    assert "AWS access key ID" in names
    assert any("URL query parameter 'token'" in n for n in names)
    # secret is masked in evidence
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.evidence for f in findings)


def test_no_secrets_is_clean(http_factory):
    def handler(request):
        return httpx.Response(200, text="<html>nothing sensitive here</html>")

    assert SecretsExposureCheck().run(_ctx(http_factory(handler), HTTP)) == []


# -- cookies ----------------------------------------------------------------

def test_cookie_missing_all_flags(http_factory):
    def handler(request):
        return httpx.Response(200, headers=[("set-cookie", "sessionid=abc; Path=/")], text="ok")

    findings = CookieSecurityCheck().run(_ctx(http_factory(handler), HTTPS))
    assert len(findings) == 1
    f = findings[0]
    assert "sessionid" in f.name
    assert "Secure" in f.name and "HttpOnly" in f.name and "SameSite" in f.name
    assert f.confidence == "high"  # session-like name


def test_fully_flagged_cookie_is_clean(http_factory):
    def handler(request):
        return httpx.Response(
            200,
            headers=[("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict")],
            text="ok",
        )

    assert CookieSecurityCheck().run(_ctx(http_factory(handler), HTTPS)) == []
