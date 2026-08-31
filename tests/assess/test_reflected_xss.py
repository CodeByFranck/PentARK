"""Tests for the safe reflected-XSS check."""

from __future__ import annotations

import html

import httpx

from pentark.assess.checks.base import CheckContext
from pentark.assess.checks.reflected_xss import ReflectedXssCheck


def _reflect_raw(request: httpx.Request) -> httpx.Response:
    # Echo the 'q' value verbatim into HTML (vulnerable).
    val = request.url.params.get("q", "")
    return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<p>{val}</p>")


def _reflect_encoded(request: httpx.Request) -> httpx.Response:
    # Echo the 'q' value HTML-encoded (safe).
    val = request.url.params.get("q", "")
    return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<p>{html.escape(val)}</p>")


def _reflect_plaintext(request: httpx.Request) -> httpx.Response:
    val = request.url.params.get("q", "")
    return httpx.Response(200, headers={"content-type": "text/plain"}, text=val)


def test_unencoded_reflection_is_high_confidence(http_factory):
    client = http_factory(_reflect_raw)
    target = "http://localhost:3000/search?q=hello"
    findings = ReflectedXssCheck().run(CheckContext(http=client, target=target))
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "high"
    assert f.cvss_score == 6.1
    assert f.cwe == "CWE-79"
    assert "q" in f.name


def test_encoded_reflection_is_not_a_finding(http_factory):
    client = http_factory(_reflect_encoded)
    target = "http://localhost:3000/search?q=hello"
    findings = ReflectedXssCheck().run(CheckContext(http=client, target=target))
    assert findings == []


def test_non_html_reflection_is_ignored(http_factory):
    client = http_factory(_reflect_plaintext)
    target = "http://localhost:3000/search?q=hello"
    findings = ReflectedXssCheck().run(CheckContext(http=client, target=target))
    assert findings == []


def test_no_params_means_no_requests(http_factory):
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200, text="x")

    client = http_factory(handler)
    findings = ReflectedXssCheck().run(
        CheckContext(http=client, target="http://localhost:3000/")
    )
    assert findings == []
    assert called["n"] == 0  # precise: no params -> no traffic
