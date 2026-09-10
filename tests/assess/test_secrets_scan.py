"""Tests for the pure secret/token scanner."""

from __future__ import annotations

from pentark.assess.crypto.secrets_scan import mask, scan_secrets, scan_url_for_tokens

_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


def test_masking_never_reveals_full_secret():
    assert mask("AKIAIOSFODNN7EXAMPLE") == "AKIA…(20 chars)…LE"
    assert "IOSFODNN7" not in mask("AKIAIOSFODNN7EXAMPLE")
    assert mask("short") == "*****"


def test_detects_aws_google_jwt():
    body = f"var k='AKIAIOSFODNN7EXAMPLE'; var g='AIza{'a'*35}'; var t='{_JWT}';"
    names = {h.name for h in scan_secrets(body)}
    assert "AWS access key ID" in names
    assert "Google API key" in names
    assert "JSON Web Token (JWT)" in names
    # No raw secret leaks into the masked output.
    assert all("AKIAIOSFODNN7EXAMPLE" != h.masked for h in scan_secrets(body))


def test_generic_assignment_skips_placeholders():
    assert scan_secrets("api_key = 'your_api_key'") == []
    assert scan_secrets('password: "changeme"') == []
    hits = scan_secrets("apiKey: 'a1b2c3d4e5f6g7h8'")
    assert len(hits) == 1 and hits[0].cwe == "CWE-798"


def test_url_token_detection():
    hits = scan_url_for_tokens("https://x.test/download?file=a&token=deadbeefcafe")
    assert len(hits) == 1
    assert "token" in hits[0].name
    assert hits[0].cwe == "CWE-598"
    assert "deadbeefcafe" not in hits[0].masked


def test_url_without_sensitive_params_is_clean():
    assert scan_url_for_tokens("https://x.test/page?ref=home&page=2") == []
