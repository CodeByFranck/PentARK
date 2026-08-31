"""Tests for the scope loader + authorization gate + allowlist."""

from __future__ import annotations

import datetime as dt

import pytest

from pentark.core.errors import AuthorizationError, ConfigError, ScopeError
from pentark.core.scope import load_scope

NOW = dt.date(2026, 8, 31)

_YAML = """
authorization:
  authorized: true
  operator: "Op <op@example.com>"
  acknowledgement: "authorized"
  signed: "Op, 2026-08-31"
  expires: "2099-12-31"
scope:
  hosts: ["localhost", "127.0.0.1"]
  url_prefixes: ["http://localhost:3000/"]
settings:
  rate_limit_rps: 3
  audit_path: "a.jsonl"
"""


def _write(tmp_path, text):
    p = tmp_path / "scope.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_and_authorize(tmp_path):
    sc = load_scope(_write(tmp_path, _YAML))
    sc.require_authorization(now=NOW)  # should not raise
    assert sc.hosts == ("localhost", "127.0.0.1")
    assert sc.settings.rate_limit_rps == 3


def test_missing_file_is_clear_error(tmp_path):
    with pytest.raises(ConfigError):
        load_scope(tmp_path / "nope.yaml")


def test_unauthorized_blocks(tmp_path):
    sc = load_scope(_write(tmp_path, _YAML.replace("authorized: true", "authorized: false")))
    with pytest.raises(AuthorizationError):
        sc.require_authorization(now=NOW)


def test_expired_blocks(tmp_path):
    sc = load_scope(_write(tmp_path, _YAML.replace('"2099-12-31"', '"2020-01-01"')))
    with pytest.raises(AuthorizationError):
        sc.require_authorization(now=NOW)


def test_empty_scope_is_default_deny(tmp_path):
    y = _YAML.replace('["localhost", "127.0.0.1"]', "[]").replace('["http://localhost:3000/"]', "[]")
    sc = load_scope(_write(tmp_path, y))
    with pytest.raises(AuthorizationError):
        sc.require_authorization(now=NOW)


def test_in_scope_matching(tmp_path):
    sc = load_scope(_write(tmp_path, _YAML))
    assert sc.is_in_scope("http://localhost/anything")           # host match
    assert sc.is_in_scope("http://127.0.0.1:8080/x")             # host match w/ port
    assert sc.is_in_scope("http://localhost:3000/rest/products") # url-prefix match
    assert not sc.is_in_scope("http://example.com/")             # off-scope
    with pytest.raises(ScopeError):
        sc.require_in_scope("http://example.com/")
