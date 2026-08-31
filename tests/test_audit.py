"""Tests for the timestamped audit log."""

from __future__ import annotations

from pentark.core.audit import AuditLog, read_records


def test_log_writes_jsonl_with_fields(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.log("http.request", target="http://localhost/x", method="GET", result=200)
    log.log("http.refused", target="http://evil.com/", result="off-scope")

    records = list(read_records(path))
    assert len(records) == 2
    assert records[0]["action"] == "http.request"
    assert records[0]["target"] == "http://localhost/x"
    assert records[0]["result"] == 200
    assert records[0]["ts"]  # timestamp present
    assert records[1]["action"] == "http.refused"


def test_creates_parent_dir(tmp_path):
    path = tmp_path / "nested" / "deeper" / "audit.jsonl"
    AuditLog(path).log("run.start", target=None)
    assert path.is_file()
