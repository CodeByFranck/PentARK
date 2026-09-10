"""Tests for the PDF report renderer.

These skip automatically if reportlab is not installed (it ships in the ``dev``
and ``report`` extras), so the suite still runs on a minimal install.
"""

from __future__ import annotations

import datetime as dt

import pytest

from pentark.assess.models import AssessmentResult, Finding
from pentark.report import ReportMeta, write_pdf

pytest.importorskip("reportlab")

_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

META = ReportMeta(
    tool_version="0.1.0",
    generated_at=dt.datetime(2026, 9, 2, 14, 30, 0, tzinfo=dt.timezone.utc),
    operator="Tester <t@example.com>",
    scope_hosts=("localhost",),
    scope_prefixes=("http://localhost:3000/",),
)


def _finding(**kw):
    base = dict(
        check_id="reflected-xss",
        name="Reflected XSS via 'q'",
        endpoint="http://localhost:3000/s?q=probe<>\"'",
        cvss_vector=_XSS,
        description="Reflected without encoding.",
        remediation="Encode output; add CSP.",
        evidence="probe reflected unencoded: <>\"'",
        confidence="high",
        cwe="CWE-79",
    )
    base.update(kw)
    return Finding(**base)


def _result(findings):
    return AssessmentResult(
        target="http://localhost:3000/",
        findings=findings,
        meta={"checks_run": ["reflected-xss"], "total": len(findings), "generated_at": "2026-09-02 10:00:00Z"},
    )


def _assert_is_pdf(path):
    data = path.read_bytes()
    assert data[:5] == b"%PDF-"
    assert len(data) > 1000  # a real, non-trivial document


def test_pdf_is_written(tmp_path):
    out = tmp_path / "report.pdf"
    write_pdf(_result([_finding()]), META, out)
    assert out.is_file()
    _assert_is_pdf(out)


def test_pdf_with_no_findings(tmp_path):
    out = tmp_path / "empty.pdf"
    write_pdf(_result([]), META, out)
    _assert_is_pdf(out)


def test_pdf_handles_long_evidence_and_specials(tmp_path):
    out = tmp_path / "long.pdf"
    evidence = "verylongtokenwithoutspaces" * 20 + "\n<script>&\"'</script>"
    write_pdf(_result([_finding(evidence=evidence)]), META, out)
    _assert_is_pdf(out)


def test_pdf_includes_informational_severity(tmp_path):
    out = tmp_path / "info.pdf"
    info = _finding(
        name="Informational note",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",  # 0.0 None
        cwe=None,
        evidence="",
    )
    write_pdf(_result([_finding(), info]), META, out)
    _assert_is_pdf(out)
