"""Markdown report renderer — pure, deterministic, zero extra dependencies.

Given a prioritized :class:`AssessmentResult` and :class:`ReportMeta`, produce a
professional Markdown document: cover metadata, an executive summary with a
severity breakdown, one detailed section per finding (severity, CVSS score +
vector, confidence, CWE, endpoint, description, evidence, remediation), and a
methodology/scope + disclaimer appendix. Being a pure ``(result, meta) -> str``
function makes it trivially unit-testable and the single source of truth the PDF
renderer mirrors.
"""

from __future__ import annotations

import datetime as _dt
from typing import TYPE_CHECKING

from pentark.assess.models import AssessmentResult

if TYPE_CHECKING:  # avoid a circular import at runtime (package __init__ imports us)
    from pentark.report import ReportMeta

# Severity rows always shown, in priority order, so a clean report still proves
# the checks ran and found nothing at those levels.
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def render_markdown(result: AssessmentResult, meta: "ReportMeta") -> str:
    lines: list[str] = []
    lines += _cover(result, meta)
    lines += _executive_summary(result)
    lines += _findings(result)
    lines += _appendix(result, meta)
    return "\n".join(lines).rstrip() + "\n"


def _cover(result: AssessmentResult, meta: "ReportMeta") -> list[str]:
    checks = ", ".join(result.meta.get("checks_run", [])) or "—"
    out = [
        "# PentARK Assessment Report",
        "",
        f"- **Target:** `{result.target}`",
        f"- **Report generated (UTC):** {_fmt_dt(meta.generated_at)}",
        f"- **Operator:** {meta.operator or '—'}",
        f"- **Tool:** PentARK v{meta.tool_version}",
        f"- **Checks run:** {checks}",
    ]
    scan_time = result.meta.get("generated_at")
    if scan_time:
        out.append(f"- **Assessment run (UTC):** {scan_time}")
    out += [
        "",
        "> **Authorized-use notice.** This report documents testing performed under "
        "an explicit authorization and scope. It is confidential and intended only "
        "for the operator and the system owner.",
        "",
    ]
    return out


def _executive_summary(result: AssessmentResult) -> list[str]:
    counts = result.summary()
    total = len(result.findings)
    highest = next((s for s in _SEVERITY_ORDER if counts.get(s)), "None")

    out = ["## Executive summary", ""]
    if total == 0:
        out += [
            "No findings were identified by the checks that were run against the "
            "target. This is not a proof of absence of vulnerabilities — only that "
            "the executed checks did not flag any issues.",
            "",
        ]
        return out

    plural = "s" if total != 1 else ""
    out += [
        f"The assessment identified **{total} finding{plural}** against "
        f"`{result.target}`. The highest severity observed is **{highest}**.",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for sev in _SEVERITY_ORDER:
        out.append(f"| {sev} | {counts.get(sev, 0)} |")
    if counts.get("None"):
        out.append(f"| Informational | {counts['None']} |")
    out += [
        f"| **Total** | **{total}** |",
        "",
        "Findings are ranked by severity (CVSS v3.1 base score), then by "
        "confidence. Address higher-ranked items first.",
        "",
    ]
    return out


def _findings(result: AssessmentResult) -> list[str]:
    out = ["## Findings", ""]
    if not result.findings:
        out += ["_No findings to report._", ""]
        return out

    for i, f in enumerate(result.findings, start=1):
        out += [
            f"### {i}. [{f.severity}] {f.name}",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Severity | {f.severity} (CVSS {f.cvss_score:.1f}) |",
            f"| CVSS vector | `{_esc_cell(f.cvss_vector)}` |",
            f"| Confidence | {_esc_cell(f.confidence)} |",
            f"| CWE | {_esc_cell(f.cwe or '—')} |",
            f"| Endpoint | `{_esc_cell(f.endpoint)}` |",
            "",
            "**Description**",
            "",
            f.description.strip() or "_No description provided._",
            "",
        ]
        if f.evidence.strip():
            out += ["**Evidence**", "", _fence(f.evidence.strip()), ""]
        out += [
            "**Remediation**",
            "",
            f.remediation.strip() or "_No remediation provided._",
            "",
            "---",
            "",
        ]
    return out


def _appendix(result: AssessmentResult, meta: "ReportMeta") -> list[str]:
    out = [
        "## Methodology & scope",
        "",
        "PentARK performs passive, non-destructive assessment checks against the "
        "authorized target and scores each finding with CVSS v3.1. Every request "
        "is validated against the engagement scope allowlist, rate-limited, and "
        "written to an append-only audit log. No exploitation was performed.",
        "",
    ]
    if meta.scope_hosts or meta.scope_prefixes:
        out += ["**Authorized scope**", ""]
        for h in meta.scope_hosts:
            out.append(f"- host: `{h}`")
        for p in meta.scope_prefixes:
            out.append(f"- url prefix: `{p}`")
        out.append("")
    out += [
        "## Disclaimer",
        "",
        "This assessment reflects the state of the target at the time of testing "
        "and the specific checks executed. Absence of a finding is not a guarantee "
        "that a class of vulnerability is absent. Testing was authorized; the "
        "reader is responsible for lawful use of this information.",
        "",
    ]
    return out


# --- small formatting helpers -------------------------------------------------

def _fmt_dt(value: _dt.datetime) -> str:
    if value.tzinfo is not None:
        value = value.astimezone(_dt.timezone.utc)
    return value.strftime("%Y-%m-%d %H:%M:%SZ")


def _esc_cell(text: str) -> str:
    """Make a value safe to drop inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _fence(text: str) -> str:
    """Wrap ``text`` in a fenced code block, using a fence long enough to survive
    any run of backticks inside the content."""
    longest = 0
    run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


__all__ = ["render_markdown"]
