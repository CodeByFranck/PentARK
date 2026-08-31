"""A scope-aware, throttled, audited HTTP client.

This is the single choke point for outbound traffic, so the safety controls
can't be bypassed by individual checks: **every** request is (1) validated
against the scope allowlist — off-scope is refused and logged, (2) throttled by
the rate limiter, and (3) written to the audit log. The underlying transport is
injectable so tests run fully offline (``httpx.MockTransport``) with no live
target.
"""

from __future__ import annotations

from typing import Any

import httpx

from pentark.core.audit import AuditLog, NullAuditLog
from pentark.core.ratelimit import RateLimiter
from pentark.core.scope import Scope


class HttpClient:
    def __init__(
        self,
        scope: Scope,
        *,
        rate_limiter: RateLimiter | None = None,
        audit: AuditLog | NullAuditLog | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.scope = scope
        self.audit = audit or NullAuditLog()
        self.rate_limiter = rate_limiter or RateLimiter(scope.settings.rate_limit_rps)
        self._client = httpx.Client(
            transport=transport,
            timeout=scope.settings.timeout_seconds,
            headers={"User-Agent": scope.settings.user_agent},
            follow_redirects=True,
        )

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        # 1. Scope gate — refuse and log anything off the allowlist.
        if not self.scope.is_in_scope(url):
            self.audit.log("http.refused", target=url, method=method, result="off-scope")
            self.scope.require_in_scope(url)  # raises ScopeError
        # 2. Throttle.
        self.rate_limiter.acquire()
        # 3. Perform + audit.
        try:
            resp = self._client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            self.audit.log("http.error", target=url, method=method, result=str(exc))
            raise
        self.audit.log("http.request", target=url, method=method, result=resp.status_code)
        return resp

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["HttpClient"]
