"""Tests for the OSV.dev client (offline via MockTransport)."""

from __future__ import annotations

import json

import httpx
import pytest

from pentark.assess.supplychain.models import Component
from pentark.assess.supplychain.osv import OsvClient, OsvError

JQUERY = Component("jquery", "1.7.2", ecosystem="npm")


def _client(handler) -> OsvClient:
    return OsvClient(transport=httpx.MockTransport(handler))


def test_query_parses_cve_and_cvss():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "vulns": [{
                "id": "GHSA-xxxx",
                "aliases": ["CVE-2019-11358", "SNYK-JS-JQUERY"],
                "summary": "jQuery prototype pollution",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            }]
        })

    with _client(handler) as c:
        vulns = c.query(JQUERY)

    assert captured["url"].endswith("/v1/query")
    assert captured["body"] == {"version": "1.7.2", "package": {"name": "jquery", "ecosystem": "npm"}}
    assert len(vulns) == 1
    v = vulns[0]
    assert v.osv_id == "GHSA-xxxx"
    assert v.cve_ids == ("CVE-2019-11358",)   # non-CVE alias filtered out
    assert v.cvss_vector.startswith("CVSS:3.1")
    assert v.refs == "CVE-2019-11358"


def test_query_no_vulns():
    with _client(lambda r: httpx.Response(200, json={"vulns": []})) as c:
        assert c.query(JQUERY) == []


def test_query_ignores_cvss_v4_only():
    def handler(request):
        return httpx.Response(200, json={"vulns": [{
            "id": "OSV-1", "aliases": [],
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"}],
        }]})

    with _client(handler) as c:
        assert c.query(JQUERY)[0].cvss_vector is None  # v4 not consumed by v3.1 scorer


def test_query_http_error_raises_osverror():
    with _client(lambda r: httpx.Response(500, text="boom")) as c:
        with pytest.raises(OsvError):
            c.query(JQUERY)
