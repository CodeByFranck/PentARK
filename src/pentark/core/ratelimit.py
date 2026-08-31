"""Client-side request throttling.

A minimum-interval limiter: it guarantees at least ``1/rps`` seconds between
requests so the tool can't accidentally hammer a target. The clock and sleep
function are injectable so the behavior is deterministic and fast to unit-test
(no real sleeping in tests).
"""

from __future__ import annotations

import time
from typing import Callable


class RateLimiter:
    def __init__(
        self,
        rps: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.min_interval = (1.0 / rps) if rps and rps > 0 else 0.0
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def acquire(self) -> float:
        """Block until the next request is allowed. Returns seconds slept."""
        if self.min_interval <= 0:
            return 0.0
        now = self._clock()
        slept = 0.0
        if self._last is not None:
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                self._sleep(wait)
                slept = wait
        self._last = self._clock()
        return slept


__all__ = ["RateLimiter"]
