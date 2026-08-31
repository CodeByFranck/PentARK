"""Tests for the security-headers check."""

from __future__ import annotations

import httpx

from pentark.assess.checks.base import CheckContext
from pentark.assess.checks.security_headers import SecurityHeadersCheck

TARGET = "http://localhost:3000/"

_ALL_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def test_missing_headers_are_reported(http_factory):
    client = http_factory(lambda r: httpx.Response(200, text="hi"))  # no security headers
    findings = SecurityHeadersCheck().run(CheckContext(http=client, target=TARGET))
    names = {f.name for f in findings}
    assert len(findings) == 5
    assert any("Content-Security-Policy" in n for n in names)
    assert all(f.confidence == "high" for f in findings)     # deterministic signal
    assert all(f.cvss_score > 0 for f in findings)


def test_all_headers_present_yields_nothing(http_factory):
    client = http_factory(lambda r: httpx.Response(200, headers=_ALL_HEADERS, text="hi"))
    findings = SecurityHeadersCheck().run(CheckContext(http=client, target=TARGET))
    assert findings == []


def test_partial_headers(http_factory):
    client = http_factory(
        lambda r: httpx.Response(200, headers={"x-content-type-options": "nosniff"}, text="hi")
    )
    findings = SecurityHeadersCheck().run(CheckContext(http=client, target=TARGET))
    assert len(findings) == 4  # the one present is not flagged
