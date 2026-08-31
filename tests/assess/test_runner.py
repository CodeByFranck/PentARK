"""Tests for the assessment runner: prioritization, dedup, resilience, scope."""

from __future__ import annotations

import httpx
import pytest

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.models import Finding
from pentark.assess.runner import AssessmentRunner
from pentark.core.errors import ScopeError

TARGET = "http://localhost:3000/"

_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8
_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"    # 3.1


def _finding(name, vector):
    return Finding(check_id="t", name=name, endpoint=TARGET, cvss_vector=vector,
                   description="d", remediation="r")


class _Fake(Check):
    id = "fake"
    name = "fake"

    def __init__(self, findings):
        self._f = findings

    def run(self, ctx):
        return list(self._f)


class _Boom(Check):
    id = "boom"
    name = "boom"

    def run(self, ctx):
        raise RuntimeError("check blew up")


def test_findings_are_prioritized_high_first(http_factory):
    client = http_factory(lambda r: httpx.Response(200))
    checks = [_Fake([_finding("low one", _LOW), _finding("high one", _HIGH)])]
    result = AssessmentRunner(client, checks=checks).run(TARGET)
    assert [f.name for f in result.findings] == ["high one", "low one"]
    assert result.summary()["Critical"] == 1


def test_duplicate_findings_are_deduped(http_factory):
    client = http_factory(lambda r: httpx.Response(200))
    dup = _finding("same", _HIGH)
    checks = [_Fake([dup, _finding("same", _HIGH)])]
    result = AssessmentRunner(client, checks=checks).run(TARGET)
    assert len(result.findings) == 1


def test_a_broken_check_does_not_abort_the_run(http_factory):
    client = http_factory(lambda r: httpx.Response(200))
    checks = [_Boom(), _Fake([_finding("survivor", _HIGH)])]
    result = AssessmentRunner(client, checks=checks).run(TARGET)
    assert [f.name for f in result.findings] == ["survivor"]


def test_off_scope_target_refused(http_factory):
    client = http_factory(lambda r: httpx.Response(200))
    with pytest.raises(ScopeError):
        AssessmentRunner(client, checks=[]).run("http://example.com/")
