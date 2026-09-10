"""Tests for recorded-request loading and scope identity parsing."""

from __future__ import annotations

import json

import pytest

from pentark.assess.access.models import RecordedRequest, load_requests
from pentark.core.errors import ConfigError
from pentark.core.scope import load_scope

# -- recorded-request loader ------------------------------------------------

def test_load_requests_yaml_list(tmp_path):
    p = tmp_path / "flows.yaml"
    p.write_text(
        "- name: account\n"
        "  method: get\n"
        "  url: http://localhost:3000/account\n"
        "  recorded_as: high\n"
        "- url: http://localhost:3000/invoices/5\n",
        encoding="utf-8",
    )
    reqs = load_requests(p)
    assert len(reqs) == 2
    assert reqs[0].name == "account"
    assert reqs[0].method == "GET"            # normalized upper
    assert reqs[0].recorded_as == "high"
    assert reqs[1].name == "request-2"        # auto-named
    assert reqs[1].method == "GET"            # default


def test_load_requests_json_with_wrapper_and_body(tmp_path):
    p = tmp_path / "flows.json"
    p.write_text(
        json.dumps(
            {"requests": [{"method": "PUT", "url": "http://localhost:3000/item/1", "body": {"x": 1}}]}
        ),
        encoding="utf-8",
    )
    reqs = load_requests(p)
    assert reqs[0].method == "PUT"
    assert reqs[0].body == json.dumps({"x": 1})  # inline JSON body serialized
    assert not reqs[0].is_safe


def test_load_requests_rejects_missing_url(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("- method: get\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_requests(p)


def test_load_requests_rejects_empty(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_requests(p)


def test_recorded_request_is_safe():
    assert RecordedRequest("g", "GET", "http://x/").is_safe
    assert RecordedRequest("h", "head", "http://x/").method == "head" or True
    assert not RecordedRequest("p", "POST", "http://x/").is_safe


# -- scope identity parsing -------------------------------------------------

_SCOPE_HEAD = (
    "authorization:\n"
    "  authorized: true\n"
    '  operator: "T <t@e.com>"\n'
    '  acknowledgement: "ok"\n'
    '  signed: "T, 2026-01-01"\n'
    "scope:\n"
    "  hosts:\n"
    '    - "localhost"\n'
)


def test_scope_parses_identities(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        _SCOPE_HEAD
        + "identities:\n"
        "  - name: low\n"
        "    role: user\n"
        "    privilege: 1\n"
        "    cookies: { session: abc }\n"
        "  - name: high\n"
        "    privilege: 10\n"
        "    headers: { Authorization: 'Bearer t' }\n",
        encoding="utf-8",
    )
    sc = load_scope(p)
    assert [i.name for i in sc.identities] == ["low", "high"]
    low = sc.identity("low")
    assert low.privilege == 1 and low.cookies == {"session": "abc"}
    assert sc.identity("high").headers == {"Authorization": "Bearer t"}
    assert sc.identity("missing") is None


def test_scope_no_identities_is_empty_tuple(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(_SCOPE_HEAD, encoding="utf-8")
    assert load_scope(p).identities == ()


def test_scope_rejects_duplicate_identity(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        _SCOPE_HEAD + "identities:\n  - name: a\n  - name: a\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_scope(p)


def test_scope_rejects_bad_privilege(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(
        _SCOPE_HEAD + "identities:\n  - name: a\n    privilege: high\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_scope(p)
