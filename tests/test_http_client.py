"""Tests for the scope-aware HTTP client."""

from __future__ import annotations

import httpx
import pytest

from pentark.core.audit import AuditLog, read_records
from pentark.core.errors import ScopeError


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="ok")


def test_in_scope_request_succeeds(http_factory):
    client = http_factory(_ok)
    resp = client.get("http://localhost:3000/rest/products")
    assert resp.status_code == 200


def test_off_scope_request_is_refused_and_logged(http_factory, tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(200)

    client = http_factory(handler, audit=audit)
    with pytest.raises(ScopeError):
        client.get("http://example.com/secret")

    assert called["n"] == 0  # transport never reached
    actions = [r["action"] for r in read_records(tmp_path / "a.jsonl")]
    assert "http.refused" in actions
