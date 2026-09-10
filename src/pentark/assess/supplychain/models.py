"""Data models for supply-chain component analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Component:
    """A detected third-party component."""

    name: str
    version: str
    ecosystem: str = "npm"     # OSV ecosystem; only npm is queried by default
    source: str = ""           # how it was found (script/header/meta/package-lock)
    evidence: str = ""
    confidence: str = "high"   # exact resolved version = high; declared range = medium

    @property
    def queryable(self) -> bool:
        """True if this component can be looked up in OSV (needs ecosystem + version)."""
        return bool(self.ecosystem) and bool(self.version) and self.ecosystem.lower() == "npm"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem.lower(), self.name.lower(), self.version)


@dataclass(frozen=True)
class Vulnerability:
    """One OSV vulnerability record for a component."""

    osv_id: str
    cve_ids: tuple[str, ...] = ()
    summary: str = ""
    cvss_vector: str | None = None   # CVSS v3.x vector from OSV, if published

    @property
    def refs(self) -> str:
        """CVE IDs if present, else the OSV id — for human-readable output."""
        return ", ".join(self.cve_ids) if self.cve_ids else self.osv_id


@dataclass
class ComponentReport:
    """A component paired with the vulnerabilities OSV returned for it."""

    component: Component
    vulns: list[Vulnerability] = field(default_factory=list)
    checked: bool = False          # was OSV actually queried for this component?
    error: str | None = None       # OSV lookup error, if any

    @property
    def is_vulnerable(self) -> bool:
        return bool(self.vulns)

    def all_refs(self) -> list[str]:
        seen: list[str] = []
        for v in self.vulns:
            for ref in (v.cve_ids or (v.osv_id,)):
                if ref not in seen:
                    seen.append(ref)
        return seen


__all__ = ["Component", "Vulnerability", "ComponentReport"]
