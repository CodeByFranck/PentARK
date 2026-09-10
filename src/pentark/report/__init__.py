"""Phase 3 — reporting.

Turns the prioritized :class:`~pentark.assess.models.AssessmentResult` into a
professional deliverable: a **Markdown** report (pure stdlib, always available)
and an optional **PDF** (via reportlab, installed with the ``report`` extra).

Design mirrors the rest of PentARK: the Markdown renderer is a *pure* function of
``(result, meta)`` so it is deterministic and fully unit-testable offline; the
PDF renderer lazily imports its heavy dependency and raises a clear, actionable
error if it is missing, rather than making every install pay for it.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from pentark.assess.models import AssessmentResult
from pentark.report.markdown import render_markdown


@dataclass(frozen=True)
class ReportMeta:
    """Report-level metadata (who/when/with-what), separate from the findings.

    Kept distinct from :class:`AssessmentResult.meta` (which describes the *scan*)
    because this describes the *report* — its author and the moment it was
    produced — and both belong in a professional deliverable.
    """

    tool_version: str
    generated_at: _dt.datetime
    operator: str | None = None
    scope_hosts: tuple[str, ...] = ()
    scope_prefixes: tuple[str, ...] = ()

    @classmethod
    def now(
        cls,
        tool_version: str,
        *,
        operator: str | None = None,
        scope_hosts: tuple[str, ...] = (),
        scope_prefixes: tuple[str, ...] = (),
    ) -> "ReportMeta":
        return cls(
            tool_version=tool_version,
            generated_at=_dt.datetime.now(_dt.timezone.utc),
            operator=operator,
            scope_hosts=scope_hosts,
            scope_prefixes=scope_prefixes,
        )


def write_markdown(result: AssessmentResult, meta: ReportMeta, path) -> None:
    """Render and write the Markdown report to ``path``."""
    from pathlib import Path

    Path(path).write_text(render_markdown(result, meta), encoding="utf-8")


def write_pdf(result: AssessmentResult, meta: ReportMeta, path) -> None:
    """Render and write the PDF report to ``path`` (needs the ``report`` extra)."""
    from pentark.report.pdf import render_pdf

    render_pdf(result, meta, path)


__all__ = ["ReportMeta", "render_markdown", "write_markdown", "write_pdf"]
