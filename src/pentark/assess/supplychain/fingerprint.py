"""Fingerprint third-party components from headers, HTML, scripts, and manifests.

Pure functions (no I/O) so they are trivially unit-testable; the check module
does the HTTP fetching and feeds strings in here.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from pentark.assess.supplychain.models import Component

# Pre-release is introduced by '-' (semver), never '.', so a filename like
# "jquery-1.7.2.min.js" yields "1.7.2" rather than swallowing ".min".
_SEMVER = r"(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)"

# Friendly / file names -> canonical npm package name.
_NPM_ALIASES = {
    "angularjs": "angular",
    "jquery.min": "jquery",
    "jquery-ui": "jquery-ui",
    "bootstrap.min": "bootstrap",
    "vue.min": "vue",
    "react-dom": "react-dom",
    "lodash.min": "lodash",
    "underscore.min": "underscore",
    "moment.min": "moment",
    "d3.min": "d3",
}
_KNOWN_NPM = {
    "jquery", "jquery-ui", "bootstrap", "angular", "react", "react-dom", "vue",
    "lodash", "underscore", "moment", "d3", "axios", "handlebars", "backbone",
    "ember", "knockout", "dojo", "ckeditor", "tinymce", "select2", "chart.js",
}


def _canon_npm(name: str) -> str:
    name = name.strip().lower().removesuffix(".js")
    return _NPM_ALIASES.get(name, name)


# ---------------------------------------------------------------------------
# Response headers + cookies
# ---------------------------------------------------------------------------

def from_headers(headers) -> list[Component]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[Component] = []

    def add(name, version, source, ecosystem=""):
        out.append(Component(
            name=name, version=version or "", ecosystem=ecosystem,
            source=source, evidence=f"{source}: {name} {version}".strip(),
            confidence="medium",
        ))

    for header in ("server", "x-powered-by"):
        val = h.get(header)
        if not val:
            continue
        for part in re.split(r"[ ,]+", val):
            m = re.match(rf"([A-Za-z][\w.+-]*)/{_SEMVER}", part)
            if m:
                add(m.group(1).lower(), m.group(2), f"header:{header}")

    if h.get("x-aspnet-version"):
        add("asp.net", h["x-aspnet-version"], "header:x-aspnet-version")
    gen = h.get("x-generator") or ""
    m = re.match(rf"(\w+)\s+{_SEMVER}", gen)
    if m:
        add(m.group(1).lower(), m.group(2), "header:x-generator")

    # Framework cookies (no version, inventory only).
    cookie = h.get("set-cookie", "")
    for needle, fw in (
        ("laravel_session", "laravel"), ("ci_session", "codeigniter"),
        ("JSESSIONID", "java-servlet"), ("connect.sid", "express"),
        ("PHPSESSID", "php"), ("django", "django"),
    ):
        if needle.lower() in cookie.lower():
            out.append(Component(
                name=fw, version="", source="cookie",
                evidence=f"cookie {needle}", confidence="low",
            ))
    return out


# ---------------------------------------------------------------------------
# HTML: script srcs, inline banners, <meta generator>
# ---------------------------------------------------------------------------

_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_INLINE_SCRIPT_RE = re.compile(r"<script\b(?![^>]*\bsrc)[^>]*>(.*?)</script>", re.I | re.S)
_GENERATOR_RE = re.compile(
    r"""<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*\bcontent\s*=\s*["']([^"']+)["']""",
    re.I,
)
_GENERATOR_RE_REV = re.compile(
    r"""<meta\b[^>]*\bcontent\s*=\s*["']([^"']+)["'][^>]*\bname\s*=\s*["']generator["']""",
    re.I,
)


def script_srcs(html: str) -> list[str]:
    return _SCRIPT_SRC_RE.findall(html)


def inline_scripts(html: str) -> list[str]:
    return _INLINE_SCRIPT_RE.findall(html)


def from_meta_generator(html: str) -> list[Component]:
    out: list[Component] = []
    for rx in (_GENERATOR_RE, _GENERATOR_RE_REV):
        for content in rx.findall(html):
            m = re.match(rf"([A-Za-z][\w .-]*?)\s+v?{_SEMVER}", content.strip())
            if m:
                out.append(Component(
                    name=m.group(1).strip().lower(), version=m.group(2),
                    ecosystem="",  # a CMS/generator is not an npm package -> inventory only
                    source="meta:generator", evidence=f"<meta generator> {content}",
                    confidence="medium",
                ))
    return out


# script URL / filename version extraction
_CDNJS_RE = re.compile(rf"/ajax/libs/([\w.-]+)/{_SEMVER}/")
_NPM_AT_RE = re.compile(rf"/(?:npm/|gh/[^/]+/)?((?:@[\w.-]+/)?[\w.-]+)@{_SEMVER}")
_FILENAME_RE = re.compile(rf"/([\w.-]+?)[-.]v?{_SEMVER}(?:[.-]min)?\.js(?:$|[?#])", re.I)


def from_script_url(url: str) -> Component | None:
    path = urlparse(url).path or url
    for rx in (_CDNJS_RE, _NPM_AT_RE, _FILENAME_RE):
        m = rx.search(url if rx is _NPM_AT_RE else path)
        if m:
            name = _canon_npm(m.group(1))
            return Component(
                name=name, version=m.group(2),
                ecosystem="npm" if name in _KNOWN_NPM else "npm",
                source="script", evidence=f"<script src={url}>",
                confidence="high",
            )
    return None


# inline version banners in JS bodies
_BANNERS = [
    ("jquery", re.compile(rf"jQuery(?: JavaScript Library)?\s+v?{_SEMVER}")),
    ("jquery", re.compile(rf"\.jquery\s*=\s*[\"']{_SEMVER}")),
    ("bootstrap", re.compile(rf"Bootstrap\s+v{_SEMVER}")),
    ("angular", re.compile(rf"AngularJS\s+v{_SEMVER}")),
    ("react", re.compile(rf"React\s+v{_SEMVER}")),
    ("vue", re.compile(rf"Vue\.js\s+v{_SEMVER}")),
    ("moment", re.compile(rf"moment(?:\.js)?\s+version\s*:?\s*{_SEMVER}")),
]


def from_script_body(text: str, url: str = "") -> list[Component]:
    out: list[Component] = []
    seen: set[str] = set()
    for name, rx in _BANNERS:
        m = rx.search(text)
        if m and name not in seen:
            seen.add(name)
            out.append(Component(
                name=name, version=m.group(1), source="script-banner",
                evidence=f"{name} banner {m.group(0)!r}" + (f" in {url}" if url else ""),
                confidence="high",
            ))
    return out


# ---------------------------------------------------------------------------
# package.json / package-lock.json
# ---------------------------------------------------------------------------

def _clean_range(spec: str) -> str | None:
    """Best-effort concrete version from an npm range ('^4.17.4' -> '4.17.4')."""
    spec = spec.strip().lstrip("^~=v><* ")
    m = re.match(r"(\d+\.\d+\.\d+)", spec)
    return m.group(1) if m else None


def parse_package_json(text: str) -> list[Component]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Component] = []
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            version = _clean_range(spec)
            if version:
                out.append(Component(
                    name=str(name).lower(), version=version, source="package.json",
                    evidence=f"package.json {section}: {name}@{spec}",
                    confidence="medium",  # declared range, not the resolved version
                ))
    return out


def parse_package_lock(text: str) -> list[Component]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[Component] = []

    # Lockfile v2/v3: {"packages": {"node_modules/jquery": {"version": "..."}}}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            name = str(path).split("node_modules/")[-1]
            version = meta.get("version")
            if name and isinstance(version, str):
                out.append(_locked(name, version))

    # Lockfile v1: {"dependencies": {"jquery": {"version": "..."}}}
    if not out:
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            _walk_lock_v1(deps, out)
    return out


def _walk_lock_v1(deps: dict, out: list[Component]) -> None:
    for name, meta in deps.items():
        if isinstance(meta, dict) and isinstance(meta.get("version"), str):
            out.append(_locked(str(name), meta["version"]))
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                _walk_lock_v1(nested, out)


def _locked(name: str, version: str) -> Component:
    return Component(
        name=name.lower(), version=version, source="package-lock.json",
        evidence=f"package-lock.json: {name}@{version}", confidence="high",
    )


def dedupe(components: list[Component]) -> list[Component]:
    """Collapse duplicates by (ecosystem, name, version); prefer higher confidence."""
    rank = {"high": 0, "medium": 1, "low": 2}
    best: dict[tuple, Component] = {}
    for c in components:
        cur = best.get(c.key)
        if cur is None or rank.get(c.confidence, 9) < rank.get(cur.confidence, 9):
            best[c.key] = c
    return list(best.values())


__all__ = [
    "from_headers", "script_srcs", "inline_scripts", "from_meta_generator",
    "from_script_url", "from_script_body", "parse_package_json",
    "parse_package_lock", "dedupe",
]
