"""Tests for the A02 security-misconfiguration checks."""

from __future__ import annotations

import httpx

from pentark.assess.checks.base import CheckContext
from pentark.assess.checks.misconfig import (
    DefaultCredentialsCheck,
    DirectoryListingCheck,
    HttpMethodsCheck,
    SensitiveFileExposureCheck,
    VerboseErrorCheck,
    WeakHeadersCheck,
)

TARGET = "http://localhost:3000/"


def _ctx(http, target=TARGET):
    return CheckContext(http=http, target=target)


# -- weak headers -----------------------------------------------------------

def test_weak_csp_and_hsts_and_version(http_factory):
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
                "strict-transport-security": "max-age=3600",
                "server": "Apache/2.4.49",
            },
            text="ok",
        )

    findings = WeakHeadersCheck().run(_ctx(http_factory(handler)))
    names = [f.name for f in findings]
    assert any("Weak Content-Security-Policy" in n for n in names)
    assert any("Strict-Transport-Security" in n for n in names)
    assert any("version disclosure" in n for n in names)
    csp = next(f for f in findings if "Content-Security-Policy" in f.name)
    assert "unsafe-inline" in csp.evidence  # exact value quoted


def test_strong_headers_are_clean(http_factory):
    def handler(request):
        return httpx.Response(
            200,
            headers={
                "content-security-policy": "default-src 'self'",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
            text="ok",
        )

    assert WeakHeadersCheck().run(_ctx(http_factory(handler))) == []


# -- sensitive files --------------------------------------------------------

def test_exposed_git_head(http_factory):
    def handler(request):
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        return httpx.Response(404, text="nope")

    findings = SensitiveFileExposureCheck().run(_ctx(http_factory(handler)))
    git = [f for f in findings if ".git" in f.name]
    assert len(git) == 1
    assert git[0].severity == "High"
    assert git[0].cwe == "CWE-538"
    assert "/.git/HEAD" in git[0].endpoint


def test_exposed_env_file(http_factory):
    def handler(request):
        if request.url.path == "/.env":
            return httpx.Response(200, text="APP_KEY=base64:secret\nDB_PASSWORD=hunter2\n")
        return httpx.Response(404, text="nope")

    findings = SensitiveFileExposureCheck().run(_ctx(http_factory(handler)))
    assert any(f.check_id == "sensitive-file-exposure" and ".env" in f.endpoint for f in findings)


def test_spa_catch_all_is_not_flagged(http_factory):
    # Everything (including the random baseline) returns the same 200 SPA shell.
    def handler(request):
        return httpx.Response(200, text="<html><body><div id=app></div></body></html>")

    assert SensitiveFileExposureCheck().run(_ctx(http_factory(handler))) == []


def test_200_without_signature_is_not_flagged(http_factory):
    # .env exists (200) but content is not a real env file -> no finding.
    def handler(request):
        if request.url.path == "/.env":
            return httpx.Response(200, text="just some unrelated text")
        return httpx.Response(404, text="nope")

    findings = SensitiveFileExposureCheck().run(_ctx(http_factory(handler)))
    assert [f for f in findings if ".env" in f.endpoint] == []


# -- directory listing ------------------------------------------------------

def test_directory_listing(http_factory):
    def handler(request):
        if request.url.path == "/uploads/":
            return httpx.Response(200, text="<html><title>Index of /uploads</title>...")
        return httpx.Response(404, text="nope")

    findings = DirectoryListingCheck().run(_ctx(http_factory(handler)))
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-548"
    assert "uploads" in findings[0].endpoint


# -- verbose errors ---------------------------------------------------------

def test_python_traceback_disclosed(http_factory):
    def handler(request):
        return httpx.Response(
            500,
            text="Traceback (most recent call last):\n  File app.py line 10\nRuntimeError: boom",
        )

    findings = VerboseErrorCheck().run(_ctx(http_factory(handler)))
    assert any(f.cwe == "CWE-209" and "Python" in f.name for f in findings)


def test_no_error_signature_is_clean(http_factory):
    def handler(request):
        return httpx.Response(404, text="<h1>Not Found</h1>")

    assert VerboseErrorCheck().run(_ctx(http_factory(handler))) == []


# -- TRACE ------------------------------------------------------------------

def test_trace_enabled(http_factory):
    def handler(request):
        if request.method == "TRACE":
            echo = request.headers.get("x-pentark-trace", "")
            return httpx.Response(200, text=f"TRACE / HTTP/1.1\nX-Pentark-Trace: {echo}")
        return httpx.Response(200, text="ok")

    findings = HttpMethodsCheck().run(_ctx(http_factory(handler)))
    assert len(findings) == 1
    assert "TRACE" in findings[0].name


def test_trace_disabled_is_clean(http_factory):
    def handler(request):
        if request.method == "TRACE":
            return httpx.Response(405, text="method not allowed")
        return httpx.Response(200, text="ok")

    assert HttpMethodsCheck().run(_ctx(http_factory(handler))) == []


# -- default credentials ----------------------------------------------------

_LOGIN_FORM = (
    "<html><body><form action='/login' method='post'>"
    "<input type='hidden' name='csrf' value='tok123'>"
    "<input type='text' name='username'>"
    "<input type='password' name='password'>"
    "<button>Login</button></form></body></html>"
)


def test_default_credentials_accepted(http_factory):
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, text=_LOGIN_FORM)
        # POST /login: admin/admin works, everything else re-shows the form.
        body = request.content.decode()
        if "username=admin" in body and "password=admin&" in body + "&":
            return httpx.Response(302, headers={"location": "/dashboard"})
        return httpx.Response(200, text=_LOGIN_FORM)

    findings = DefaultCredentialsCheck().run(_ctx(http_factory(handler)))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "Critical"
    assert f.cwe == "CWE-1392"
    assert "admin/admin" in f.name


def test_no_login_form_means_no_finding(http_factory):
    def handler(request):
        return httpx.Response(200, text="<html><body>no forms here</body></html>")

    assert DefaultCredentialsCheck().run(_ctx(http_factory(handler))) == []


def test_default_credentials_rejected_is_clean(http_factory):
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, text=_LOGIN_FORM)
        return httpx.Response(200, text=_LOGIN_FORM)  # always re-show form -> no success

    assert DefaultCredentialsCheck().run(_ctx(http_factory(handler))) == []
