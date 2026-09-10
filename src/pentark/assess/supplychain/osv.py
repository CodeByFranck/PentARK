"""Client for the OSV.dev vulnerability database.

Deliberately independent of the scope-gated :class:`HttpClient`: OSV.dev is a
third-party service we consult, not a target under test, so it must not be
subject to the target scope allowlist. The transport is injectable so tests run
fully offline. Every query is audit-logged.
"""

from __future__ import annotations

from typing import Any

import httpx

from pentark.assess.supplychain.models import Component, Vulnerability
from pentark.core.audit import AuditLog, NullAuditLog

OSV_BASE_URL = "https://api.osv.dev"


class OsvError(RuntimeError):
    """Raised when OSV cannot be reached or returns an unusable response."""


class OsvClient:
    def __init__(
        self,
        *,
        base_url: str = OSV_BASE_URL,
        timeout: float = 15.0,
        transport: httpx.BaseTransport | None = None,
        audit: AuditLog | NullAuditLog | None = None,
    ) -> None:
        self.audit = audit or NullAuditLog()
        self._client = httpx.Client(
            base_url=base_url,
            transport=transport,
            timeout=timeout,
            headers={"User-Agent": "PentARK/0.1 (authorized security testing)"},
        )

    def query(self, component: Component) -> list[Vulnerability]:
        """Return OSV vulnerabilities affecting ``component`` (empty if none)."""
        payload: dict[str, Any] = {
            "version": component.version,
            "package": {"name": component.name, "ecosystem": _osv_ecosystem(component.ecosystem)},
        }
        try:
            resp = self._client.post("/v1/query", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            self.audit.log("osv.error", target=component.name, result=str(exc))
            raise OsvError(f"OSV query failed for {component.name}@{component.version}: {exc}") from exc

        vulns = [_parse_vuln(v) for v in data.get("vulns", []) or []]
        self.audit.log(
            "osv.query", target=f"{component.ecosystem}:{component.name}@{component.version}",
            result=len(vulns),
        )
        return vulns

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "OsvClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _osv_ecosystem(name: str) -> str:
    # OSV expects "npm", "PyPI", "Packagist", ... Normalize the few we emit.
    return {"npm": "npm", "pypi": "PyPI", "packagist": "Packagist"}.get(name.lower(), name)


def _parse_vuln(v: dict[str, Any]) -> Vulnerability:
    aliases = v.get("aliases", []) or []
    cve_ids = tuple(a for a in aliases if isinstance(a, str) and a.startswith("CVE-"))
    return Vulnerability(
        osv_id=str(v.get("id", "")),
        cve_ids=cve_ids,
        summary=str(v.get("summary") or v.get("details", ""))[:200],
        cvss_vector=_pick_cvss_v3(v.get("severity", []) or []),
    )


def _pick_cvss_v3(severities: list[dict[str, Any]]) -> str | None:
    """Return a CVSS v3.x vector from an OSV severity list, if present.

    Only v3 is used because the local scorer implements CVSS v3.1; a v4-only
    record falls through to the caller's default severity.
    """
    for s in severities:
        if str(s.get("type", "")).upper().startswith("CVSS_V3"):
            score = s.get("score")
            if isinstance(score, str) and score.startswith("CVSS:3"):
                return score
    return None


__all__ = ["OsvClient", "OsvError", "OSV_BASE_URL"]
