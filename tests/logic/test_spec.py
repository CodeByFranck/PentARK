"""Tests for the business-logic spec loader."""

from __future__ import annotations

import pytest

from pentark.assess.logic.spec import spec_from_dict
from pentark.core.errors import ConfigError

_DATA = {
    "rate_limit": [
        {"name": "login", "url": "http://h/login", "body": {"u": "a", "p": "b"}, "attempts": 10}
    ],
    "numeric_fields": [
        {"name": "qty", "url": "http://h/cart", "field": "quantity", "extra": {"item": "1"}}
    ],
    "workflows": [
        {"name": "checkout", "protected_index": 2,
         "steps": [{"url": "http://h/s1"}, {"url": "http://h/s2"}, {"url": "http://h/confirm"}],
         "success_marker": "Order"}
    ],
    "race": [
        {"name": "coupon", "url": "http://h/redeem", "concurrency": 8, "expected_success": 1}
    ],
}


def test_parses_all_sections():
    spec = spec_from_dict(_DATA)
    assert spec.rate_limit[0].name == "login" and spec.rate_limit[0].attempts == 10
    assert spec.numeric[0].field == "quantity" and spec.numeric[0].extra == {"item": "1"}
    assert len(spec.workflows[0].steps) == 3 and spec.workflows[0].protected_index == 2
    assert spec.race[0].concurrency == 8
    assert not spec.is_empty


def test_all_urls_collects_every_declared_url():
    urls = spec_from_dict(_DATA).all_urls()
    assert "http://h/login" in urls and "http://h/confirm" in urls


def test_defaults_applied():
    spec = spec_from_dict({"numeric_fields": [{"url": "http://h/x", "field": "price"}]})
    nf = spec.numeric[0]
    assert nf.method == "POST" and nf.valid == "1"
    assert "-1" in nf.bad_values and "99999999999999999999" in nf.bad_values


def test_missing_required_key_raises():
    with pytest.raises(ConfigError):
        spec_from_dict({"rate_limit": [{"name": "x"}]})   # no url


def test_bad_protected_index_raises():
    with pytest.raises(ConfigError):
        spec_from_dict({"workflows": [{"name": "w", "protected_index": 5,
                                       "steps": [{"url": "http://h/a"}]}]})


def test_empty_spec():
    assert spec_from_dict({}).is_empty
