"""Tests for the Markdown report renderer (pure, deterministic)."""

from __future__ import annotations

import datetime as dt

from pentark.assess.models import AssessmentResult, Finding
from pentark.report import ReportMeta, render_markdown

_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"   # 6.1 Medium
_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8 Critical
_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"   # 3.1 Low
_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"  # 0.0 None

META = ReportMeta(
    tool_version="0.1.0",
    generated_at=dt.datetime(2026, 9, 2, 14, 30, 0, tzinfo=dt.timezone.utc),
    operator="Tester <t@example.com>",
    scope_hosts=("localhost",),
    scope_prefixes=("http://localhost:3000/",),
)


def _finding(name, vector, **kw):
    return Finding(
        check_id=kw.get("check_id", "c"),
        name=name,
        endpoint=kw.get("endpoint", "http://localhost:3000/"),
        cvss_vector=vector,
        description=kw.get("description", "desc"),
        remediation=kw.get("remediation", "fix it"),
        evidence=kw.get("evidence", ""),
        confidence=kw.get("confidence", "medium"),
        cwe=kw.get("cwe"),
    )


def _result(findings):
    ordered = sorted(findings, key=lambda f: f.sort_key())
    return AssessmentResult(
        target="http://localhost:3000/",
        findings=ordered,
        meta={"checks_run": ["security-headers", "reflected-xss"], "total": len(ordered)},
    )


def test_cover_includes_metadata():
    md = render_markdown(_result([_finding("A", _XSS)]), META)
    assert "# PentARK Assessment Report" in md
    assert "`http://localhost:3000/`" in md
    assert "2026-09-02 14:30:00Z" in md
    assert "Tester <t@example.com>" in md
    assert "PentARK v0.1.0" in md
    assert "security-headers, reflected-xss" in md


def test_executive_summary_counts_and_highest():
    md = render_markdown(_result([_finding("crit", _CRIT), _finding("low", _LOW)]), META)
    assert "**2 findings**" in md
    assert "highest severity observed is **Critical**" in md
    # severity table rows
    assert "| Critical | 1 |" in md
    assert "| Low | 1 |" in md
    assert "| **Total** | **2** |" in md


def test_findings_rendered_in_priority_order():
    md = render_markdown(_result([_finding("low", _LOW), _finding("crit", _CRIT)]), META)
    assert md.index("[Critical] crit") < md.index("[Low] low")


def test_finding_details_present():
    f = _finding("XSS", _XSS, cwe="CWE-79", confidence="high",
                 evidence="probe reflected", endpoint="http://localhost:3000/s?q=1")
    md = render_markdown(_result([f]), META)
    assert "Medium (CVSS 6.1)" in md
    assert f"`{_XSS}`" in md
    assert "CWE-79" in md
    assert "| Confidence | high |" in md
    assert "http://localhost:3000/s?q=1" in md
    assert "**Remediation**" in md
    assert "fix it" in md


def test_evidence_is_fenced():
    md = render_markdown(_result([_finding("A", _XSS, evidence="line1\nline2")]), META)
    assert "```\nline1\nline2\n```" in md


def test_evidence_fence_grows_past_backticks():
    md = render_markdown(_result([_finding("A", _XSS, evidence="a ``` b")]), META)
    assert "````" in md  # fence longer than the 3 backticks inside the evidence


def test_pipe_in_value_is_escaped():
    f = _finding("A", _XSS, endpoint="http://localhost:3000/?a=1|2")
    md = render_markdown(_result([f]), META)
    assert "1\\|2" in md


def test_informational_row_when_none_severity_present():
    md = render_markdown(_result([_finding("crit", _CRIT), _finding("info", _INFO)]), META)
    assert "| Informational | 1 |" in md
    assert "highest severity observed is **Critical**" in md


def test_empty_findings_report():
    md = render_markdown(_result([]), META)
    assert "No findings were identified" in md
    assert "_No findings to report._" in md
    # methodology / disclaimer appendix still present
    assert "## Methodology & scope" in md
    assert "## Disclaimer" in md
    assert "url prefix: `http://localhost:3000/`" in md


def test_render_is_deterministic():
    r = _result([_finding("A", _XSS), _finding("B", _CRIT)])
    assert render_markdown(r, META) == render_markdown(r, META)


def test_naive_generated_at_is_accepted():
    meta = ReportMeta(tool_version="0.1.0", generated_at=dt.datetime(2026, 9, 2, 14, 30, 0))
    md = render_markdown(_result([_finding("A", _XSS)]), meta)
    assert "2026-09-02 14:30:00Z" in md
