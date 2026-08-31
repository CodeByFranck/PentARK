"""CVSS v3.1 base-score computation and qualitative rating.

Implements the official v3.1 base-metric formula so findings carry a real,
defensible score and a standard vector string (e.g.
``CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N``) — not an ad-hoc number.
Pure and deterministic, so it is straightforward to unit-test against the
published reference scores.
"""

from __future__ import annotations

import math

# Metric weights (CVSS v3.1 specification, section 7).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required depends on Scope (changed vs unchanged).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VALID = {
    "AV": set("NALP"), "AC": set("LH"), "PR": set("NLH"), "UI": set("NR"),
    "S": set("UC"), "C": set("HLN"), "I": set("HLN"), "A": set("HLN"),
}


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into its base metrics.

    Accepts an optional ``CVSS:3.x/`` prefix; ignores temporal/environmental
    metrics if present. Raises :class:`ValueError` on missing/invalid base metrics.
    """
    metrics: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if not part or part.upper().startswith("CVSS:"):
            continue
        if ":" not in part:
            raise ValueError(f"malformed CVSS metric: {part!r}")
        key, _, val = part.partition(":")
        key, val = key.upper(), val.upper()
        if key in _VALID:
            if val not in _VALID[key]:
                raise ValueError(f"invalid value {val!r} for CVSS metric {key}")
            metrics[key] = val
    missing = [m for m in _METRIC_ORDER if m not in metrics]
    if missing:
        raise ValueError(f"CVSS vector missing base metrics: {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Appendix A roundup: ceil to one decimal place, avoiding fp error."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score (0.0–10.0) from a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10.0))
    return _roundup(min(impact + exploitability, 10.0))


def severity_from_score(score: float) -> str:
    """Map a base score to the CVSS v3.1 qualitative rating."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


__all__ = ["parse_vector", "base_score", "severity_from_score"]
