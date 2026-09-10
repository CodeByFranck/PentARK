"""The business-logic test spec: operator-declared checks loaded from YAML/JSON."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pentark.core.errors import ConfigError


@dataclass(frozen=True)
class RateLimitTarget:
    name: str
    url: str
    method: str = "POST"
    body: dict[str, str] = field(default_factory=dict)
    attempts: int = 20
    throttle_status: int = 429
    throttle_marker: str = ""       # body text that indicates throttling/lockout


@dataclass(frozen=True)
class NumericFieldTarget:
    name: str
    url: str
    field: str
    method: str = "POST"
    location: str = "body"          # "body" | "query"
    valid: str = "1"
    extra: dict[str, str] = field(default_factory=dict)
    # Values that a well-designed field should reject.
    bad_values: tuple[str, ...] = ("-1", "-1000", "0", "99999999999999999999", "2147483648", "1e309")


@dataclass(frozen=True)
class WorkflowStep:
    url: str
    method: str = "GET"
    body: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkflowTarget:
    name: str
    steps: tuple[WorkflowStep, ...]
    protected_index: int            # the step that should require the earlier ones
    success_marker: str = ""        # body text proving the step was served
    blocked_statuses: tuple[int, ...] = (401, 403)


@dataclass(frozen=True)
class RaceTarget:
    name: str
    url: str
    method: str = "POST"
    body: dict[str, str] = field(default_factory=dict)
    concurrency: int = 10
    expected_success: int = 1       # how many of the burst *should* succeed
    success_status: int = 200
    success_marker: str = ""


@dataclass
class LogicSpec:
    rate_limit: list[RateLimitTarget] = field(default_factory=list)
    numeric: list[NumericFieldTarget] = field(default_factory=list)
    workflows: list[WorkflowTarget] = field(default_factory=list)
    race: list[RaceTarget] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.rate_limit or self.numeric or self.workflows or self.race)

    def all_urls(self) -> list[str]:
        urls = [t.url for t in self.rate_limit]
        urls += [t.url for t in self.numeric]
        urls += [t.url for t in self.race]
        urls += [s.url for w in self.workflows for s in w.steps]
        return urls


def _d(raw: Any, key: str, where: str) -> dict[str, str]:
    v = raw.get(key, {}) or {}
    if not isinstance(v, dict):
        raise ConfigError(f"[{where}] {key}: expected a mapping")
    return {str(k): str(val) for k, val in v.items()}


def _req(raw: dict, key: str, where: str) -> Any:
    if key not in raw:
        raise ConfigError(f"[{where}] missing required key {key!r}")
    return raw[key]


def load_spec(path: str | Path) -> LogicSpec:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"logic spec not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid logic spec {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("logic spec root must be a mapping")
    return spec_from_dict(data)


def spec_from_dict(data: dict) -> LogicSpec:
    spec = LogicSpec()
    for i, raw in enumerate(data.get("rate_limit", []) or []):
        w = f"rate_limit[{i}]"
        spec.rate_limit.append(RateLimitTarget(
            name=str(raw.get("name") or f"rate-{i}"),
            url=str(_req(raw, "url", w)),
            method=str(raw.get("method", "POST")).upper(),
            body=_d(raw, "body", w),
            attempts=int(raw.get("attempts", 20)),
            throttle_status=int(raw.get("throttle_status", 429)),
            throttle_marker=str(raw.get("throttle_marker", "")),
        ))
    for i, raw in enumerate(data.get("numeric_fields", []) or []):
        w = f"numeric_fields[{i}]"
        spec.numeric.append(NumericFieldTarget(
            name=str(raw.get("name") or f"numeric-{i}"),
            url=str(_req(raw, "url", w)),
            field=str(_req(raw, "field", w)),
            method=str(raw.get("method", "POST")).upper(),
            location=str(raw.get("location", "body")),
            valid=str(raw.get("valid", "1")),
            extra=_d(raw, "extra", w),
            bad_values=tuple(str(v) for v in raw["bad_values"]) if raw.get("bad_values")
            else NumericFieldTarget.bad_values,
        ))
    for i, raw in enumerate(data.get("workflows", []) or []):
        w = f"workflows[{i}]"
        steps_raw = _req(raw, "steps", w)
        if not isinstance(steps_raw, list) or not steps_raw:
            raise ConfigError(f"[{w}] steps must be a non-empty list")
        steps = tuple(
            WorkflowStep(url=str(_req(s, "url", f"{w}.steps")),
                         method=str(s.get("method", "GET")).upper(),
                         body=_d(s, "body", f"{w}.steps"))
            for s in steps_raw
        )
        idx = int(raw.get("protected_index", len(steps) - 1))
        if not 0 <= idx < len(steps):
            raise ConfigError(f"[{w}] protected_index {idx} out of range")
        spec.workflows.append(WorkflowTarget(
            name=str(raw.get("name") or f"workflow-{i}"),
            steps=steps, protected_index=idx,
            success_marker=str(raw.get("success_marker", "")),
            blocked_statuses=tuple(int(s) for s in raw.get("blocked_statuses", (401, 403))),
        ))
    for i, raw in enumerate(data.get("race", []) or []):
        w = f"race[{i}]"
        spec.race.append(RaceTarget(
            name=str(raw.get("name") or f"race-{i}"),
            url=str(_req(raw, "url", w)),
            method=str(raw.get("method", "POST")).upper(),
            body=_d(raw, "body", w),
            concurrency=int(raw.get("concurrency", 10)),
            expected_success=int(raw.get("expected_success", 1)),
            success_status=int(raw.get("success_status", 200)),
            success_marker=str(raw.get("success_marker", "")),
        ))
    return spec


__all__ = [
    "LogicSpec", "RateLimitTarget", "NumericFieldTarget", "WorkflowStep",
    "WorkflowTarget", "RaceTarget", "load_spec", "spec_from_dict",
]
