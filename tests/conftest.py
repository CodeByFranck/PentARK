"""Shared fixtures. HTTP is mocked with httpx.MockTransport — no live targets."""

from __future__ import annotations

import datetime as dt

import httpx
import pytest

from pentark.assess.http_client import HttpClient
from pentark.core.ratelimit import RateLimiter
from pentark.core.scope import Authorization, Scope, Settings

NOW = dt.date(2026, 8, 31)


@pytest.fixture
def scope() -> Scope:
    """An authorized scope covering localhost, with throttling disabled for tests."""
    return Scope(
        authorization=Authorization(
            authorized=True,
            operator="Tester <tester@example.com>",
            acknowledgement="I am authorized.",
            signed="Tester, 2026-08-31",
            expires=dt.date(2099, 12, 31),
        ),
        hosts=("localhost", "127.0.0.1"),
        url_prefixes=("http://localhost:3000/",),
        settings=Settings(rate_limit_rps=0.0),  # no real sleeping in tests
    )


@pytest.fixture
def http_factory(scope):
    """Return a builder: give it a request handler, get a scope-aware HttpClient."""

    def _build(handler, *, audit=None):
        transport = httpx.MockTransport(handler)
        return HttpClient(scope, rate_limiter=RateLimiter(0.0), audit=audit, transport=transport)

    return _build
