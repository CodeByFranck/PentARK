"""Tests for loading findings JSON back into models (report input path)."""

from __future__ import annotations

import json

import pytest

from pentark.assess.models import AssessmentResult, Finding

_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"   # 6.1 Medium
_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 Critical


def _finding(name, vector, **kw):
    return Finding(check_id="c", name=name, endpoint="http://localhost:3000/",
                   cvss_vector=vector, description="d", remediation="r", **kw)


def test_assessment_result_survives_json_roundtrip():
    result = AssessmentResult(
        target="http://localhost:3000/",
        findings=[_finding("crit", _CRIT, cwe="CWE-1"), _finding("xss", _XSS, evidence="e")],
        meta={"checks_run": ["a", "b"], "total": 2, "generated_at": "2026-09-02 10:00:00Z"},
    )
    data = json.loads(json.dumps(result.to_dict()))
    back = AssessmentResult.from_dict(data)

    assert back.target == result.target
    assert back.meta == result.meta
    assert [f.id for f in back.findings] == [f.id for f in result.findings]
    assert [f.severity for f in back.findings] == [f.severity for f in result.findings]
    assert back.findings[1].evidence == "e"


def test_severity_is_recomputed_not_trusted():
    # Even if the file claims a wrong severity/score, the vector is authoritative.
    data = {
        "target": "http://x/",
        "findings": [
            {
                "check_id": "c",
                "name": "n",
                "endpoint": "http://x/",
                "cvss_vector": _CRIT,
                "severity": "Low",       # deliberately wrong
                "cvss_score": 0.1,       # deliberately wrong
                "confidence": "high",
                "cwe": None,
                "description": "d",
                "evidence": "",
                "remediation": "r",
            }
        ],
    }
    back = AssessmentResult.from_dict(data)
    assert back.findings[0].severity == "Critical"
    assert back.findings[0].cvss_score == pytest.approx(9.8)


def test_missing_required_field_raises():
    with pytest.raises(ValueError):
        Finding.from_dict({"name": "n"})  # no check_id / endpoint / cvss_vector


def test_findings_must_be_a_list():
    with pytest.raises(ValueError):
        AssessmentResult.from_dict({"target": "x", "findings": {"not": "a list"}})


def test_root_must_be_object():
    with pytest.raises(ValueError):
        AssessmentResult.from_dict([1, 2, 3])
