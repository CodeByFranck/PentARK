"""Data models for access-control testing: recorded requests + replay results.

A :class:`RecordedRequest` is one HTTP request captured from a legitimate,
authorized session (e.g. exported from a proxy) that we replay under other
identities. Requests are loaded from a small YAML/JSON "flows" file so the
credentials in scope.yaml and the traffic to replay stay separate concerns.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pentark.core.errors import ConfigError

# Methods that cannot change server state. In the default (safe) mode the auditor
# sends nothing outside this set, so "do not modify data" holds by construction.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class RecordedRequest:
    """One request captured under an authorized session, to be replayed."""

    name: str
    method: str
    url: str
    recorded_as: str | None = None   # identity name this was captured under
    body: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.method.upper() in SAFE_METHODS


@dataclass
class ReplayResult:
    """The outcome of replaying a request under one identity."""

    identity: str
    status: int
    body_len: int
    content_type: str = ""
    location: str = ""          # Location header for 3xx (login redirects matter)
    body_preview: str = ""      # truncated, for PoC evidence only

    @property
    def is_ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def is_denied(self) -> bool:
        """A response that indicates access control actually fired."""
        return self.status in (401, 403) or 300 <= self.status < 400


def load_requests(path: str | Path) -> list[RecordedRequest]:
    """Load recorded requests from a YAML or JSON flows file.

    Accepted shapes: a top-level list of request mappings, or a mapping with a
    ``requests:`` key holding that list. Each request needs at least ``method``
    and ``url``.
    """
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"requests file not found: {p}")
    text = p.read_text(encoding="utf-8")
    try:
        data: Any = yaml.safe_load(text)  # YAML is a JSON superset, covers both
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid requests file {p}: {exc}") from exc

    if isinstance(data, dict):
        data = data.get("requests", [])
    if not isinstance(data, list):
        raise ConfigError("requests file must be a list (or a mapping with a 'requests' list)")

    out: list[RecordedRequest] = []
    for i, raw in enumerate(data):
        if not isinstance(raw, dict):
            raise ConfigError(f"requests[{i}]: expected a mapping")
        url = raw.get("url")
        method = raw.get("method", "GET")
        if not isinstance(url, str) or not url.strip():
            raise ConfigError(f"requests[{i}]: 'url' is required and must be a string")
        if not isinstance(method, str) or not method.strip():
            raise ConfigError(f"requests[{i}]: 'method' must be a string")
        headers = raw.get("headers", {}) or {}
        if not isinstance(headers, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
        ):
            raise ConfigError(f"requests[{i}]: 'headers' must be a mapping of string -> string")
        body = raw.get("body")
        if body is not None and not isinstance(body, str):
            body = json.dumps(body)  # allow inline JSON bodies
        out.append(
            RecordedRequest(
                name=str(raw.get("name") or f"request-{i + 1}"),
                method=method.strip().upper(),
                url=url.strip(),
                recorded_as=(str(raw["recorded_as"]) if raw.get("recorded_as") else None),
                body=body,
                headers={k: v for k, v in headers.items()},
            )
        )
    if not out:
        raise ConfigError(f"requests file {p} contained no requests")
    return out


__all__ = ["RecordedRequest", "ReplayResult", "SAFE_METHODS", "load_requests"]
