"""Tests for TLS finding mapping (analyzer stubbed — no real sockets)."""

from __future__ import annotations

import datetime as dt

from pentark.assess.checks.base import CheckContext
from pentark.assess.crypto.checks import WeakTlsCheck
from pentark.assess.crypto.tls import TlsInfo


class _StubAnalyzer:
    def __init__(self, info):
        self.info = info
        self.calls = []

    def analyze(self, host, port=443):
        self.calls.append((host, port))
        return self.info


def _ctx(http_factory):
    import httpx
    return CheckContext(http=http_factory(lambda r: httpx.Response(200)), target="https://localhost:3000/")


def test_expired_selfsigned_and_weak_protocol(http_factory):
    info = TlsInfo(
        host="localhost", port=3000, connected=True, protocol="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256", expired=True, self_signed=True,
        weak_protocols=["TLSv1", "TLSv1.1"],
    )
    findings = WeakTlsCheck(_StubAnalyzer(info)).run(_ctx(http_factory))
    names = " ".join(f.name for f in findings)
    assert "Expired TLS certificate" in names
    assert "Self-signed" in names
    assert "Deprecated TLS protocol" in names
    assert {f.cwe for f in findings} >= {"CWE-298", "CWE-295", "CWE-326"}


def test_weak_cipher_detected(http_factory):
    info = TlsInfo(host="localhost", port=3000, connected=True, protocol="TLSv1.2",
                   cipher="ECDHE-RSA-RC4-SHA")
    findings = WeakTlsCheck(_StubAnalyzer(info)).run(_ctx(http_factory))
    assert any("Weak TLS cipher" in f.name and "RC4" in f.name for f in findings)
    assert any(f.cwe == "CWE-327" for f in findings)


def test_healthy_tls_is_clean(http_factory):
    info = TlsInfo(host="localhost", port=3000, connected=True, protocol="TLSv1.3",
                   cipher="TLS_AES_256_GCM_SHA384",
                   not_after=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc))
    assert WeakTlsCheck(_StubAnalyzer(info)).run(_ctx(http_factory)) == []


def test_http_target_skips_tls(http_factory):
    import httpx
    stub = _StubAnalyzer(TlsInfo(host="localhost", port=3000))
    ctx = CheckContext(http=http_factory(lambda r: httpx.Response(200)), target="http://localhost:3000/")
    assert WeakTlsCheck(stub).run(ctx) == []
    assert stub.calls == []  # analyzer never invoked for cleartext targets


def test_unreachable_tls_service_is_silent(http_factory):
    info = TlsInfo(host="localhost", port=3000, connected=False, error="connection refused")
    assert WeakTlsCheck(_StubAnalyzer(info)).run(_ctx(http_factory)) == []
