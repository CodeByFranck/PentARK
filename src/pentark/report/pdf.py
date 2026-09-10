"""PDF report renderer (reportlab).

Mirrors the Markdown report as a styled, paginated PDF suitable for handing to a
client: cover metadata, an executive summary with a severity breakdown, and one
colour-coded section per finding. reportlab is a heavy dependency, so it is
imported lazily and only when a PDF is actually requested; if it is not
installed, a clear, actionable error tells the user how to get it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from xml.sax.saxutils import escape

from pentark.assess.models import AssessmentResult, Finding
from pentark.core.errors import PreflightError

if TYPE_CHECKING:
    from pentark.report import ReportMeta

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]

# Severity → banner colour (white text reads on all of these).
_SEV_HEX = {
    "Critical": "#7f1d1d",
    "High": "#b91c1c",
    "Medium": "#b45309",
    "Low": "#1d4ed8",
    "None": "#4b5563",
}


def render_pdf(result: AssessmentResult, meta: "ReportMeta", path) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise PreflightError(
            "PDF reporting requires the 'reportlab' package. Install it with:\n"
            '    python -m pip install "pentark[report]"\n'
            "or generate the Markdown report instead (--format md)."
        ) from exc

    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("pk-title", parent=base["Title"], fontSize=22, spaceAfter=6),
        "h2": ParagraphStyle("pk-h2", parent=base["Heading2"], fontSize=14, spaceBefore=14, spaceAfter=6),
        "h3": ParagraphStyle("pk-h3", parent=base["Heading3"], fontSize=12, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("pk-body", parent=base["BodyText"], fontSize=9.5, leading=13),
        "label": ParagraphStyle("pk-label", parent=base["BodyText"], fontSize=9, textColor=colors.HexColor("#374151")),
        "value": ParagraphStyle("pk-value", parent=base["BodyText"], fontSize=9, leading=12),
        "value_light": ParagraphStyle(
            "pk-valuelight", parent=base["BodyText"], fontSize=9, leading=12, textColor=colors.white
        ),
        "code": ParagraphStyle(
            "pk-code", parent=base["BodyText"], fontName="Courier", fontSize=8, leading=11, wordWrap="CJK"
        ),
        "muted": ParagraphStyle("pk-muted", parent=base["BodyText"], fontSize=8, textColor=colors.HexColor("#6b7280")),
    }

    def P(text: str, style: str) -> "Paragraph":
        return Paragraph(escape(str(text)), styles[style])

    story: list = []

    # --- cover -------------------------------------------------------------
    story.append(P("PentARK Assessment Report", "title"))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#111827"), spaceAfter=8))
    checks = ", ".join(result.meta.get("checks_run", [])) or "—"
    meta_rows = [
        ["Target", result.target],
        ["Report generated (UTC)", _fmt_dt(meta.generated_at)],
        ["Operator", meta.operator or "—"],
        ["Tool", f"PentARK v{meta.tool_version}"],
        ["Checks run", checks],
    ]
    scan_time = result.meta.get("generated_at")
    if scan_time:
        meta_rows.append(["Assessment run (UTC)", str(scan_time)])
    story.append(_kv_table(meta_rows, styles, colors, cm, Table, TableStyle, Paragraph))
    story.append(Spacer(1, 6))
    story.append(
        P(
            "Authorized-use notice. This report documents testing performed under an "
            "explicit authorization and scope. It is confidential and intended only "
            "for the operator and the system owner.",
            "muted",
        )
    )

    # --- executive summary -------------------------------------------------
    story.append(P("Executive summary", "h2"))
    counts = result.summary()
    total = len(result.findings)
    if total == 0:
        story.append(
            P(
                "No findings were identified by the checks that were run against the "
                "target. This is not a proof of absence of vulnerabilities — only that "
                "the executed checks did not flag any issues.",
                "body",
            )
        )
    else:
        highest = next((s for s in _SEVERITY_ORDER if counts.get(s)), "None")
        plural = "s" if total != 1 else ""
        story.append(
            P(
                f"The assessment identified {total} finding{plural} against "
                f"{result.target}. The highest severity observed is {highest}.",
                "body",
            )
        )
        story.append(Spacer(1, 6))
        story.append(_summary_table(counts, total, styles, colors, cm, Table, TableStyle))

    # --- findings ----------------------------------------------------------
    story.append(P("Findings", "h2"))
    if not result.findings:
        story.append(P("No findings to report.", "body"))
    else:
        for i, f in enumerate(result.findings, start=1):
            story.extend(_finding_flowables(i, f, styles, colors, cm, Table, TableStyle, Paragraph, HRFlowable, Spacer))

    # --- appendix ----------------------------------------------------------
    story.append(P("Methodology & scope", "h2"))
    story.append(
        P(
            "PentARK performs passive, non-destructive assessment checks against the "
            "authorized target and scores each finding with CVSS v3.1. Every request "
            "is validated against the engagement scope allowlist, rate-limited, and "
            "written to an append-only audit log. No exploitation was performed.",
            "body",
        )
    )
    if meta.scope_hosts or meta.scope_prefixes:
        story.append(P("Authorized scope", "h3"))
        for h in meta.scope_hosts:
            story.append(P(f"• host: {h}", "body"))
        for p in meta.scope_prefixes:
            story.append(P(f"• url prefix: {p}", "body"))
    story.append(P("Disclaimer", "h2"))
    story.append(
        P(
            "This assessment reflects the state of the target at the time of testing "
            "and the specific checks executed. Absence of a finding is not a guarantee "
            "that a class of vulnerability is absent. Testing was authorized; the reader "
            "is responsible for lawful use of this information.",
            "body",
        )
    )

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title="PentARK Assessment Report",
        author="PentARK",
    )
    doc.build(story)


# --- flowable builders --------------------------------------------------------

def _kv_table(rows, styles, colors, cm, Table, TableStyle, Paragraph):
    data = [[Paragraph(f"<b>{escape(k)}</b>", styles["label"]), Paragraph(escape(str(v)), styles["value"])] for k, v in rows]
    t = Table(data, colWidths=[4.5 * cm, None], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#e5e7eb")),
            ]
        )
    )
    return t


def _summary_table(counts, total, styles, colors, cm, Table, TableStyle):
    header = ["Severity", "Count"]
    data = [header]
    rows_meta = list(_SEVERITY_ORDER)
    if counts.get("None"):
        rows_meta.append("None")
    for sev in rows_meta:
        label = "Informational" if sev == "None" else sev
        data.append([label, str(counts.get(sev, 0))])
    data.append(["Total", str(total)])

    t = Table(data, colWidths=[6 * cm, 3 * cm], hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f3f4f6")),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    # tint each severity label cell
    for r, sev in enumerate(rows_meta, start=1):
        style.append(("TEXTCOLOR", (0, r), (0, r), colors.HexColor(_SEV_HEX.get(sev, "#111827"))))
        style.append(("FONTNAME", (0, r), (0, r), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _finding_flowables(i, f: Finding, styles, colors, cm, Table, TableStyle, Paragraph, HRFlowable, Spacer):
    out: list = [HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb"), spaceBefore=8, spaceAfter=6)]
    out.append(Paragraph(f"{i}. {escape(f.name)}", styles["h3"]))

    sev_hex = _SEV_HEX.get(f.severity, "#111827")
    rows = [
        ("Severity", f"{f.severity} — CVSS {f.cvss_score:.1f}", True),
        ("CVSS vector", f.cvss_vector, False),
        ("Confidence", f.confidence, False),
        ("CWE", f.cwe or "—", False),
        ("Endpoint", f.endpoint, False),
    ]
    data = []
    for label, value, colored in rows:
        vstyle = styles["value_light"] if colored else styles["value"]
        data.append([Paragraph(f"<b>{escape(label)}</b>", styles["label"]), Paragraph(escape(str(value)), vstyle)])
    t = Table(data, colWidths=[3.5 * cm, None], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor(sev_hex)),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    out += [Spacer(1, 4), t, Spacer(1, 6)]

    out.append(Paragraph("<b>Description</b>", styles["body"]))
    out.append(Paragraph(escape(f.description.strip() or "No description provided."), styles["body"]))

    if f.evidence.strip():
        out.append(Spacer(1, 4))
        out.append(Paragraph("<b>Evidence</b>", styles["body"]))
        code = Paragraph(escape(f.evidence.strip()).replace("\n", "<br/>"), styles["code"])
        box = Table([[code]], colWidths=[None], hAlign="LEFT")
        box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
                    ("BOX", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        out.append(box)

    out.append(Spacer(1, 4))
    out.append(Paragraph("<b>Remediation</b>", styles["body"]))
    out.append(Paragraph(escape(f.remediation.strip() or "No remediation provided."), styles["body"]))
    out.append(Spacer(1, 4))
    return out


def _fmt_dt(value) -> str:
    import datetime as _dt

    if isinstance(value, _dt.datetime) and value.tzinfo is not None:
        value = value.astimezone(_dt.timezone.utc)
    if isinstance(value, _dt.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%SZ")
    return str(value)


__all__ = ["render_pdf"]
