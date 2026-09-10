"""Tests for the business-logic scanner (target mocked)."""

from __future__ import annotations

import threading

import httpx

from pentark.assess.logic.engine import LogicScanner
from pentark.assess.logic.spec import (
    LogicSpec,
    NumericFieldTarget,
    RaceTarget,
    RateLimitTarget,
    WorkflowStep,
    WorkflowTarget,
)

BASE = "http://localhost:3000"


def _scan(http_factory, handler, spec) -> list:
    return LogicScanner(http_factory(handler)).run(spec)


# -- rate limiting ----------------------------------------------------------

def test_missing_rate_limit_flagged(http_factory):
    def handler(request):
        return httpx.Response(401, text="bad creds")   # never throttles

    spec = LogicSpec(rate_limit=[RateLimitTarget("login", f"{BASE}/login", attempts=15)])
    findings = _scan(http_factory, handler, spec)
    assert len(findings) == 1
    assert findings[0].check_id == "logic-rate-limit" and findings[0].confidence == "low"
    assert "MANUAL REVIEW" in findings[0].description


def test_rate_limit_present_is_clean(http_factory):
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        return httpx.Response(429 if state["n"] > 5 else 401, text="x")

    spec = LogicSpec(rate_limit=[RateLimitTarget("login", f"{BASE}/login", attempts=15)])
    assert _scan(http_factory, handler, spec) == []


# -- numeric abuse ----------------------------------------------------------

def test_negative_value_accepted_flagged(http_factory):
    def handler(request):
        return httpx.Response(200, text="added to cart")   # accepts anything

    spec = LogicSpec(numeric=[NumericFieldTarget("qty", f"{BASE}/cart", "quantity")])
    findings = _scan(http_factory, handler, spec)
    assert len(findings) == 1
    assert findings[0].check_id == "logic-numeric" and findings[0].cwe == "CWE-20"
    assert "-1" in findings[0].evidence


def test_numeric_validation_present_is_clean(http_factory):
    def handler(request):
        from urllib.parse import parse_qs
        qty = parse_qs(request.content.decode()).get("quantity", [""])[0]
        # Accept only a positive small integer; reject negatives/overflow/etc.
        ok = qty.isdigit() and 0 < int(qty) < 1000
        return httpx.Response(200, text="ok") if ok else httpx.Response(400, text="invalid quantity")

    spec = LogicSpec(numeric=[NumericFieldTarget("qty", f"{BASE}/cart", "quantity")])
    assert _scan(http_factory, handler, spec) == []


# -- workflow step-skipping -------------------------------------------------

def test_step_skipping_flagged(http_factory):
    def handler(request):
        return httpx.Response(200, text="Order confirmed")   # protected step served directly

    spec = LogicSpec(workflows=[WorkflowTarget(
        "checkout",
        steps=(WorkflowStep(f"{BASE}/s1"), WorkflowStep(f"{BASE}/s2"), WorkflowStep(f"{BASE}/confirm")),
        protected_index=2, success_marker="Order confirmed",
    )])
    findings = _scan(http_factory, handler, spec)
    assert len(findings) == 1 and findings[0].check_id == "logic-workflow"


def test_workflow_protected_is_clean(http_factory):
    def handler(request):
        return httpx.Response(403, text="complete previous steps first")

    spec = LogicSpec(workflows=[WorkflowTarget(
        "checkout", steps=(WorkflowStep(f"{BASE}/s1"), WorkflowStep(f"{BASE}/confirm")),
        protected_index=1,
    )])
    assert _scan(http_factory, handler, spec) == []


# -- race conditions --------------------------------------------------------

def test_race_condition_flagged(http_factory):
    def handler(request):
        return httpx.Response(200, text="redeemed")   # every concurrent request "succeeds"

    spec = LogicSpec(race=[RaceTarget("coupon", f"{BASE}/redeem", concurrency=6,
                                      expected_success=1, success_marker="redeemed")])
    findings = _scan(http_factory, handler, spec)
    assert len(findings) == 1
    assert findings[0].check_id == "logic-race" and findings[0].cwe == "CWE-362"


def test_race_atomic_is_clean(http_factory):
    lock = threading.Lock()
    state = {"used": False}

    def handler(request):
        with lock:
            if state["used"]:
                return httpx.Response(409, text="already redeemed")
            state["used"] = True
            return httpx.Response(200, text="redeemed")

    spec = LogicSpec(race=[RaceTarget("coupon", f"{BASE}/redeem", concurrency=6,
                                      expected_success=1, success_marker="redeemed")])
    findings = _scan(http_factory, handler, spec)
    assert findings == []   # exactly one success -> atomic -> no anomaly
