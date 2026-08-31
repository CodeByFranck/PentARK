"""Authorization gate + scope allowlist — the hard boundary every active action
passes through.

Design: authorization (*are we allowed to run at all?*) and scope (*is this
specific target allowed?*) are separated, mirroring how a real engagement works.
The gate is default-deny: an empty or missing allowlist means nothing is in
scope, and no active operation proceeds without an explicit, non-expired,
signed attestation.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml

from pentark.core.errors import AuthorizationError, ConfigError, ScopeError


@dataclass(frozen=True)
class Authorization:
    authorized: bool
    operator: str
    acknowledgement: str
    signed: str
    expires: _dt.date | None = None


@dataclass(frozen=True)
class Settings:
    rate_limit_rps: float = 5.0
    timeout_seconds: float = 15.0
    user_agent: str = "PentARK/0.1 (authorized security testing)"
    audit_path: str = "pentark-audit.jsonl"


@dataclass(frozen=True)
class Scope:
    """The full engagement scope: who is authorized, what is in scope, settings."""

    authorization: Authorization
    hosts: tuple[str, ...] = ()
    url_prefixes: tuple[str, ...] = ()
    settings: Settings = field(default_factory=Settings)
    source_path: Path | None = None

    @property
    def is_empty(self) -> bool:
        return not (self.hosts or self.url_prefixes)

    def require_authorization(self, *, now: _dt.date | None = None) -> None:
        """Enforce the gate, or raise :class:`AuthorizationError`."""
        a = self.authorization
        if not a.authorized:
            raise AuthorizationError(
                "authorization gate: scope.yaml has authorized=false. Set it true only "
                "when you hold written permission to test every listed target."
            )
        if not a.operator.strip():
            raise AuthorizationError("authorization gate: [authorization] operator must not be empty.")
        if not a.acknowledgement.strip():
            raise AuthorizationError("authorization gate: [authorization] acknowledgement must not be empty.")
        if not a.signed.strip():
            raise AuthorizationError(
                "authorization gate: [authorization] signed must not be empty "
                "(sign the acknowledgement: name + date / reference)."
            )
        if self.is_empty:
            raise AuthorizationError(
                "authorization gate: scope is empty (default-deny). List the authorized "
                "hosts / url_prefixes before running any active operation."
            )
        today = now or _dt.date.today()
        if a.expires is not None and today > a.expires:
            raise AuthorizationError(
                f"authorization gate: authorization expired on {a.expires.isoformat()} "
                f"(today is {today.isoformat()}). Renew it before continuing."
            )

    def is_in_scope(self, url: str) -> bool:
        """True if ``url``'s host is allow-listed or it matches a URL prefix."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False
        host = (parsed.hostname or "").lower()
        if host and host in {h.lower() for h in self.hosts}:
            return True
        return any(url.startswith(p) for p in self.url_prefixes)

    def require_in_scope(self, url: str) -> None:
        """Raise :class:`ScopeError` if ``url`` is not authorized."""
        if not self.is_in_scope(url):
            raise ScopeError(
                f"off-scope target refused: {url!r} is not in the authorized scope. "
                "Add its host or URL prefix to scope.yaml only if you are authorized to test it."
            )


def _coerce_date(value, field_name: str) -> _dt.date | None:
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError(f"[authorization] {field_name}: not a valid ISO date (YYYY-MM-DD): {value!r}") from exc
    raise ConfigError(f"[authorization] {field_name}: expected a date, got {type(value).__name__}")


def _as_str(value, where: str, key: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"[{where}] {key}: expected a string, got {type(value).__name__}")
    return value


def _as_str_tuple(value, where: str, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"[{where}] {key}: expected a list of strings")
    return tuple(v.strip() for v in value if v.strip())


def load_scope(path: str | Path) -> Scope:
    """Load and validate ``scope.yaml`` into a :class:`Scope`."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(
            f"scope file not found: {p}. Copy scope.example.yaml to {p.name} and edit it "
            "(this is the authorization allowlist; nothing active runs without it)."
        )
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("scope file root must be a mapping")

    auth_raw = data.get("authorization")
    if not isinstance(auth_raw, dict):
        raise ConfigError("missing or invalid [authorization] section")
    authorized = auth_raw.get("authorized", False)
    if not isinstance(authorized, bool):
        raise ConfigError("[authorization] authorized: expected true/false")

    authorization = Authorization(
        authorized=authorized,
        operator=_as_str(auth_raw.get("operator"), "authorization", "operator"),
        acknowledgement=_as_str(auth_raw.get("acknowledgement"), "authorization", "acknowledgement"),
        signed=_as_str(auth_raw.get("signed"), "authorization", "signed"),
        expires=_coerce_date(auth_raw.get("expires"), "expires"),
    )

    scope_raw = data.get("scope") or {}
    if not isinstance(scope_raw, dict):
        raise ConfigError("[scope] must be a mapping")

    set_raw = data.get("settings") or {}
    if not isinstance(set_raw, dict):
        raise ConfigError("[settings] must be a mapping")
    settings = Settings(
        rate_limit_rps=float(set_raw.get("rate_limit_rps", 5.0)),
        timeout_seconds=float(set_raw.get("timeout_seconds", 15.0)),
        user_agent=_as_str(set_raw.get("user_agent"), "settings", "user_agent")
        or Settings.user_agent,
        audit_path=_as_str(set_raw.get("audit_path"), "settings", "audit_path")
        or Settings.audit_path,
    )

    return Scope(
        authorization=authorization,
        hosts=_as_str_tuple(scope_raw.get("hosts"), "scope", "hosts"),
        url_prefixes=_as_str_tuple(scope_raw.get("url_prefixes"), "scope", "url_prefixes"),
        settings=settings,
        source_path=p,
    )


__all__ = ["Authorization", "Settings", "Scope", "load_scope"]
