"""Assessment orchestrator: run checks, deduplicate, and prioritize.

The value here is not the individual checks but the orchestration around them:
run each check safely (one failing check never aborts the assessment), collapse
duplicate findings, and rank the rest by severity so the output is a clean,
prioritized list that feeds both reporting and (later) exploitation.
"""

from __future__ import annotations

from pentark.assess.checks import ALL_CHECKS
from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.http_client import HttpClient
from pentark.assess.models import AssessmentResult, Finding
from pentark.core.audit import AuditLog, NullAuditLog
from pentark.core.errors import ScopeError


class AssessmentRunner:
    def __init__(
        self,
        http: HttpClient,
        *,
        checks: list[Check] | None = None,
        audit: AuditLog | NullAuditLog | None = None,
    ) -> None:
        self.http = http
        self.checks = checks if checks is not None else ALL_CHECKS
        self.audit = audit or NullAuditLog()

    def run(self, target: str) -> AssessmentResult:
        # Fail fast and clearly if the target itself is off-scope.
        self.http.scope.require_in_scope(target)

        ctx = CheckContext(http=self.http, target=target)
        collected: list[Finding] = []
        for check in self.checks:
            self.audit.log("assess.check_start", target=target, module=check.id)
            try:
                found = check.run(ctx)
            except ScopeError:
                raise  # scope violations must surface, never be swallowed
            except Exception as exc:  # a broken check shouldn't kill the whole run
                self.audit.log("assess.check_error", target=target, module=check.id, result=str(exc))
                continue
            self.audit.log(
                "assess.check_complete", target=target, module=check.id, result=len(found)
            )
            collected.extend(found)

        findings = _prioritize(_dedupe(collected))
        result = AssessmentResult(
            target=target,
            findings=findings,
            meta={"checks_run": [c.id for c in self.checks], "total": len(findings)},
        )
        self.audit.log(
            "assess.complete", target=target, result=result.summary(), total=len(findings)
        )
        return result


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)  # first occurrence wins
    return list(seen.values())


def _prioritize(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: f.sort_key())


__all__ = ["AssessmentRunner"]
