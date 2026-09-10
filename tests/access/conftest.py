"""Fixtures for A01 access-control tests. HTTP fully mocked (no live target).

The mock handler distinguishes identities by their credentials: the high-priv
identity sends `Authorization: Bearer high`, the low-priv identity sends a
`session=low` cookie, and the anonymous identity sends neither. Tests supply a
handler that returns different responses per identity to model (broken or
correct) server-side authorization.
"""

from __future__ import annotations

import datetime as dt

import httpx
import pytest

from pentark.assess.http_client import HttpClient
from pentark.core.ratelimit import RateLimiter
from pentark.core.scope import Authorization, Scope, Settings, SessionIdentity

LOW = SessionIdentity(name="low", role="user", privilege=1, cookies={"session": "low"})
HIGH = SessionIdentity(
    name="high", role="admin", privilege=10, headers={"Authorization": "Bearer high"}
)


@pytest.fixture
def scope() -> Scope:
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
        identities=(LOW, HIGH),
        settings=Settings(rate_limit_rps=0.0),
    )


@pytest.fixture
def http_factory(scope):
    def _build(handler, *, audit=None):
        transport = httpx.MockTransport(handler)
        return HttpClient(scope, rate_limiter=RateLimiter(0.0), audit=audit, transport=transport)

    return _build
