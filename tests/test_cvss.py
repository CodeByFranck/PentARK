"""Tests for CVSS v3.1 scoring against published reference vectors."""

from __future__ import annotations

import pytest

from pentark.assess.cvss import base_score, parse_vector, severity_from_score


@pytest.mark.parametrize(
    "vector, expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # e.g. critical RCE
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # canonical reflected XSS
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # no impact
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local priv-esc
    ],
)
def test_known_base_scores(vector, expected):
    assert base_score(vector) == expected


def test_severity_bands():
    assert severity_from_score(0.0) == "None"
    assert severity_from_score(3.9) == "Low"
    assert severity_from_score(4.0) == "Medium"
    assert severity_from_score(6.9) == "Medium"
    assert severity_from_score(7.0) == "High"
    assert severity_from_score(9.0) == "Critical"
    assert severity_from_score(10.0) == "Critical"


def test_prefix_optional_and_parse():
    m = parse_vector("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert m["S"] == "C" and m["AV"] == "N"


def test_invalid_vectors_raise():
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.1/AV:N/AC:L")          # missing metrics
    with pytest.raises(ValueError):
        parse_vector("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # bad value
