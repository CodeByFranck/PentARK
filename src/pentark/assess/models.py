"""Data models for the assessment phase.

A :class:`Finding` is the unit that flows through the whole tool: checks produce
them, the prioritizer ranks them, and (later) the reporter and exploitation phase
consume them. Each carries a CVSS vector/score so severity is derived, not
guessed, plus a confidence level to keep false positives honest.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from pentark.assess.cvss import base_score, severity_from_score

# Ordering for prioritization (higher first).
_SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    """A single assessment finding."""

    check_id: str
    name: str
    endpoint: str                 # URL (and param, where relevant)
    cvss_vector: str
    description: str
    remediation: str
    evidence: str = ""
    confidence: str = "medium"    # high | medium | low
    cwe: str | None = None

    @property
    def cvss_score(self) -> float:
        return base_score(self.cvss_vector)

    @property
    def severity(self) -> str:
        return severity_from_score(self.cvss_score)

    @property
    def id(self) -> str:
        """Stable identifier for deduplication (check + endpoint + name)."""
        raw = f"{self.check_id}|{self.endpoint}|{self.name}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:12]

    def sort_key(self) -> tuple:
        return (
            _SEVERITY_RANK.get(self.severity, 9),
            -self.cvss_score,
            _CONFIDENCE_RANK.get(self.confidence, 9),
            self.name,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check_id": self.check_id,
            "name": self.name,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Rebuild a Finding from its stored dict (severity/score are re-derived
        from the CVSS vector, never trusted from the file)."""
        try:
            return cls(
                check_id=str(data["check_id"]),
                name=str(data["name"]),
                endpoint=str(data["endpoint"]),
                cvss_vector=str(data["cvss_vector"]),
                description=str(data.get("description", "")),
                remediation=str(data.get("remediation", "")),
                evidence=str(data.get("evidence", "")),
                confidence=str(data.get("confidence", "medium")),
                cwe=data.get("cwe"),
            )
        except KeyError as exc:
            raise ValueError(f"finding is missing required field: {exc.args[0]!r}") from exc


@dataclass
class AssessmentResult:
    """The prioritized output of an assessment run."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "meta": self.meta,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssessmentResult":
        """Rebuild an AssessmentResult from a previously saved findings JSON."""
        if not isinstance(data, dict):
            raise ValueError("findings JSON root must be an object")
        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list):
            raise ValueError("'findings' must be a list")
        return cls(
            target=str(data.get("target", "")),
            findings=[Finding.from_dict(f) for f in raw_findings],
            meta=dict(data.get("meta", {})),
        )


__all__ = ["Finding", "AssessmentResult"]
