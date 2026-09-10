"""Tests for the `pentark report` CLI command and its helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pentark.assess.models import AssessmentResult, Finding
from pentark.cli import _report_meta, _report_paths, app

runner = CliRunner()

_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"


def _write_findings(tmp_path: Path) -> Path:
    result = AssessmentResult(
        target="http://localhost:3000/",
        findings=[
            Finding(check_id="reflected-xss", name="Reflected XSS via 'q'",
                    endpoint="http://localhost:3000/s?q=1", cvss_vector=_XSS,
                    description="d", remediation="r", evidence="e", confidence="high", cwe="CWE-79"),
        ],
        meta={"checks_run": ["reflected-xss"], "total": 1, "generated_at": "2026-09-02 10:00:00Z"},
    )
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return p


def _no_scope(tmp_path: Path) -> str:
    return str(tmp_path / "does-not-exist.yaml")


def test_report_writes_markdown(tmp_path):
    findings = _write_findings(tmp_path)
    out = tmp_path / "report"
    res = runner.invoke(app, ["report", str(findings), "-o", str(out), "-f", "md", "-c", _no_scope(tmp_path)])
    assert res.exit_code == 0, res.output
    md = (tmp_path / "report.md")
    assert md.is_file()
    assert "PentARK Assessment Report" in md.read_text(encoding="utf-8")


def test_report_both_formats(tmp_path):
    pytest.importorskip("reportlab")
    findings = _write_findings(tmp_path)
    out = tmp_path / "out"
    res = runner.invoke(app, ["report", str(findings), "-o", str(out), "-f", "both", "-c", _no_scope(tmp_path)])
    assert res.exit_code == 0, res.output
    assert (tmp_path / "out.md").is_file()
    pdf = tmp_path / "out.pdf"
    assert pdf.is_file()
    assert pdf.read_bytes()[:5] == b"%PDF-"


def test_report_missing_findings_file_fails(tmp_path):
    res = runner.invoke(app, ["report", str(tmp_path / "nope.json"), "-c", _no_scope(tmp_path)])
    assert res.exit_code != 0


def test_report_invalid_format_fails(tmp_path):
    findings = _write_findings(tmp_path)
    res = runner.invoke(app, ["report", str(findings), "-f", "xml", "-c", _no_scope(tmp_path)])
    assert res.exit_code != 0


def test_report_invalid_json_fails(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    res = runner.invoke(app, ["report", str(bad), "-c", _no_scope(tmp_path)])
    assert res.exit_code != 0


# --- helper unit tests --------------------------------------------------------

def test_report_paths_default_stem():
    assert _report_paths(None, "md") == [("md", Path("report.md"))]


def test_report_paths_both():
    assert _report_paths("out", "both") == [("md", Path("out.md")), ("pdf", Path("out.pdf"))]


def test_report_paths_strips_known_extension():
    # a stem given with an extension is normalized to the requested format
    assert _report_paths("r.pdf", "md") == [("md", Path("r.md"))]


def test_report_paths_rejects_bad_format():
    from pentark.core.errors import ConfigError

    with pytest.raises(ConfigError):
        _report_paths("r", "docx")


def test_report_meta_without_scope():
    meta = _report_meta(None)
    assert meta.operator is None
    assert meta.scope_hosts == ()
    assert meta.tool_version
