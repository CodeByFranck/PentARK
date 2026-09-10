"""Discover injectable parameters from a URL query string and from HTML forms.

Pure functions — the engine does the HTTP. An :class:`InjectionPoint` bundles
everything needed to re-issue a request with one parameter replaced by a payload,
keeping the other fields at benign defaults.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class InjectionPoint:
    method: str                       # "GET" | "POST"
    action: str                       # URL to send to (no injected query)
    param: str                        # the field under test
    fields: dict[str, str] = field(default_factory=dict)   # all fields + defaults
    location: str = "query"           # "query" | "form"

    @property
    def is_mutating(self) -> bool:
        # A POST form may create/modify data; GET/query is read-only.
        return self.method.upper() == "POST"

    def label(self) -> str:
        return f"{self.method} {self.action} [{self.location}:{self.param}]"


def _base_url(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def points_from_url(url: str) -> list[InjectionPoint]:
    """One GET injection point per existing query parameter."""
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if not pairs:
        return []
    fields = {k: v for k, v in pairs}
    action = _base_url(url)
    return [InjectionPoint("GET", action, name, dict(fields), "query") for name in fields]


_FORM_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
_ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*["']?([^"'\s>]*)""")
_SKIP_TYPES = {"submit", "button", "image", "reset", "file"}


def points_from_forms(html: str, base_url: str) -> list[InjectionPoint]:
    """One injection point per editable field of each form in the HTML."""
    points: list[InjectionPoint] = []
    for fm in _FORM_RE.finditer(html):
        attrs = dict(_ATTR_RE.findall(fm.group("attrs")))
        method = (attrs.get("method") or "GET").upper()
        action = urljoin(base_url, attrs.get("action") or base_url)
        action = _base_url(action)

        fields: dict[str, str] = {}
        editable: list[str] = []
        for tag in _INPUT_RE.findall(fm.group("body")):
            a = dict(_ATTR_RE.findall(tag))
            name = a.get("name")
            if not name:
                continue
            fields[name] = a.get("value", "") or "1"
            if a.get("type", "").lower() not in _SKIP_TYPES:
                editable.append(name)
        for name in editable:
            points.append(InjectionPoint(method, action, name, dict(fields), "form"))
    return points


def build_request(point: InjectionPoint, value: str) -> tuple[str, str, dict[str, str] | None]:
    """Return (method, url, data) for a request with ``point.param`` set to ``value``."""
    fields = dict(point.fields)
    fields[point.param] = value
    if point.method.upper() == "GET":
        sep = "&" if urlsplit(point.action).query else "?"
        return "GET", point.action + sep + urlencode(fields), None
    return "POST", point.action, fields


__all__ = ["InjectionPoint", "points_from_url", "points_from_forms", "build_request"]
