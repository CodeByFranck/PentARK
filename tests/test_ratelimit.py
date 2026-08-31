"""Tests for the rate limiter (deterministic via injected clock + sleep)."""

from __future__ import annotations

from pentark.core.ratelimit import RateLimiter


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.slept = []

    def now(self):
        return self.t

    def sleep(self, secs):
        self.slept.append(secs)
        self.t += secs  # advancing time as if we slept


def test_first_call_does_not_sleep():
    c = FakeClock()
    rl = RateLimiter(2.0, clock=c.now, sleep=c.sleep)  # 0.5s interval
    assert rl.acquire() == 0.0
    assert c.slept == []


def test_second_call_waits_remaining_interval():
    c = FakeClock()
    rl = RateLimiter(2.0, clock=c.now, sleep=c.sleep)  # 0.5s interval
    rl.acquire()          # t=0
    c.t = 0.2             # only 0.2s elapsed
    slept = rl.acquire()  # must wait 0.3s more
    assert round(slept, 3) == 0.3


def test_rps_zero_is_unlimited():
    c = FakeClock()
    rl = RateLimiter(0.0, clock=c.now, sleep=c.sleep)
    rl.acquire()
    rl.acquire()
    assert c.slept == []
