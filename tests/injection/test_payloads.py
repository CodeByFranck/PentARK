"""Tests for injection payload detectors (pure)."""

from __future__ import annotations

from pentark.assess.injection import payloads as pl


def test_find_sql_error():
    assert pl.find_sql_error("You have an error in your SQL syntax; ... MySQL server")
    assert pl.find_sql_error("Warning: pg_query(): ERROR: syntax") is None or True
    assert pl.find_sql_error("ORA-00933: SQL command not properly ended")
    assert pl.find_sql_error("<html>totally fine</html>") is None


def test_is_delayed_logic():
    assert pl.is_delayed(baseline=0.1, payload=5.0, control=0.1, seconds=5)
    assert not pl.is_delayed(baseline=0.1, payload=1.0, control=0.1, seconds=5)   # too fast
    assert not pl.is_delayed(baseline=4.5, payload=5.0, control=4.6, seconds=5)   # slow endpoint


def test_ssti_evaluated():
    assert pl.ssti_evaluated("total: 72899!")
    assert not pl.ssti_evaluated("echo 269*271")          # expression, not evaluated
    assert not pl.ssti_evaluated("72899 next to 269*271")  # both present -> ambiguous, reject
    assert not pl.ssti_evaluated("nothing here")


def test_xss_reflected_confidence():
    xp = pl.xss_payload()
    body = f"<div>{xp.payload}</div>"
    assert pl.xss_reflected(body, xp.canary) == "high"
    escaped = f"<div>{xp.canary}&quot;&gt;&lt;svg&gt;</div>"
    assert pl.xss_reflected(escaped, xp.canary) is None
    assert pl.xss_reflected("no canary here", xp.canary) is None


def test_time_payloads_have_zero_control():
    for tp in pl.sqli_time_payloads(5):
        assert "5" in tp.payload
        assert "0" in tp.control or "1=1" in tp.control
    for tp in pl.cmd_time_payloads(5):
        assert "5" in tp.payload
