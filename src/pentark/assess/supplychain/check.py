"""Orchestrate supply-chain component analysis into findings.

Reads the target through the scope-gated HttpClient (headers, HTML, same-origin
scripts, npm manifests), fingerprints components, then cross-references npm
components against OSV.dev via an injected :class:`OsvClient`. Detection only —
nothing is exploited.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.cvss import base_score
from pentark.assess.models import Finding
from pentark.assess.supplychain import fingerprint as fp
from pentark.assess.supplychain.models import Component, ComponentReport
from pentark.assess.supplychain.osv import OsvClient, OsvError

# Fallback vector for a component OSV flags as vulnerable but without a CVSS v3
# score published — a known-vulnerable dependency is at least this serious.
_V_DEFAULT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"  # 6.3 Medium
_PACKAGE_PATHS = ("package-lock.json", "package.json")


class SupplyChainCheck(Check):
    id = "supply-chain"
    name = "Vulnerable / outdated components"

    def __init__(
        self,
        osv: OsvClient | None = None,
        *,
        fetch_scripts: bool = True,
        max_scripts: int = 8,
        probe_package_files: bool = True,
    ) -> None:
        self.osv = osv
        self.fetch_scripts = fetch_scripts
        self.max_scripts = max_scripts
        self.probe_package_files = probe_package_files

    # -- fingerprint + OSV lookup ------------------------------------------

    def scan(self, ctx: CheckContext) -> list[ComponentReport]:
        components = self._fingerprint(ctx)
        reports: list[ComponentReport] = []
        for comp in components:
            report = ComponentReport(component=comp)
            if self.osv is not None and comp.queryable:
                try:
                    report.vulns = self.osv.query(comp)
                    report.checked = True
                except OsvError as exc:
                    report.error = str(exc)
            reports.append(report)
        return reports

    def run(self, ctx: CheckContext) -> list[Finding]:
        return build_findings(self.scan(ctx))

    # -- helpers -----------------------------------------------------------

    def _fingerprint(self, ctx: CheckContext) -> list[Component]:
        resp = ctx.http.get(ctx.target)
        html = resp.text
        components: list[Component] = []
        components += fp.from_headers(resp.headers)
        components += fp.from_meta_generator(html)

        target_host = urlparse(ctx.target).hostname
        srcs = fp.script_srcs(html)
        fetched = 0
        for src in srcs:
            abs_url = urljoin(ctx.target, src)
            comp = fp.from_script_url(src) or fp.from_script_url(abs_url)
            if comp is not None:
                components.append(comp)
            # Read the file body for a version banner, but only same-origin
            # (an external CDN is off-scope and would be refused).
            if (
                self.fetch_scripts
                and fetched < self.max_scripts
                and urlparse(abs_url).hostname == target_host
            ):
                body = _safe_get_text(ctx, abs_url)
                if body:
                    fetched += 1
                    components += fp.from_script_body(body, abs_url)

        for inline in fp.inline_scripts(html):
            components += fp.from_script_body(inline)

        if self.probe_package_files:
            components += self._package_files(ctx)

        return fp.dedupe(components)

    def _package_files(self, ctx: CheckContext) -> list[Component]:
        base = f"{urlparse(ctx.target).scheme}://{urlparse(ctx.target).netloc}/"
        out: list[Component] = []
        for path in _PACKAGE_PATHS:
            body = _safe_get_text(ctx, urljoin(base, path))
            if not body:
                continue
            parsed = (
                fp.parse_package_lock(body) if path.endswith("lock.json")
                else fp.parse_package_json(body)
            )
            out += parsed
            if parsed and path.endswith("lock.json"):
                break  # a resolved lockfile is authoritative; skip the range file
        return out


def _safe_get_text(ctx: CheckContext, url: str) -> str | None:
    try:
        resp = ctx.http.get(url)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    return resp.text


def build_findings(reports: list[ComponentReport]) -> list[Finding]:
    """One finding per vulnerable component, from an already-computed scan."""
    return [_finding(r) for r in reports if r.is_vulnerable]


def _finding(report: ComponentReport) -> Finding:
    comp = report.component
    vector = _worst_vector(report)
    refs = report.all_refs()
    worst = report.vulns[0]
    return Finding(
        check_id=SupplyChainCheck.id,
        name=f"Vulnerable component: {comp.name} {comp.version}",
        endpoint=comp.source or "component",
        cvss_vector=vector,
        description=(
            f"{comp.name}@{comp.version} ({comp.ecosystem}) has {len(report.vulns)} known "
            f"advisory/advisories in OSV: {', '.join(refs)}. "
            + (f"e.g. {worst.summary}" if worst.summary else "")
        ).strip(),
        remediation=(
            f"Upgrade {comp.name} to a patched release; review the referenced advisories "
            "and add automated dependency scanning to CI."
        ),
        evidence=f"{comp.evidence}; OSV refs: {', '.join(refs)}",
        confidence=comp.confidence,
        cwe="CWE-1395",  # Dependency on Vulnerable Third-Party Component
    )


def _worst_vector(report: ComponentReport) -> str:
    best_vector, best_score = _V_DEFAULT, -1.0
    for v in report.vulns:
        if not v.cvss_vector:
            continue
        try:
            score = base_score(v.cvss_vector)
        except ValueError:
            continue
        if score > best_score:
            best_vector, best_score = v.cvss_vector, score
    # Sort the component's vulns so the worst is first for the description.
    report.vulns.sort(key=lambda v: _safe_score(v.cvss_vector), reverse=True)
    return best_vector


def _safe_score(vector: str | None) -> float:
    if not vector:
        return -1.0
    try:
        return base_score(vector)
    except ValueError:
        return -1.0


__all__ = ["SupplyChainCheck", "build_findings"]
