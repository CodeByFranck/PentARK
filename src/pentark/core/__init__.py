"""Core: authorization gate, scope allowlist, audit log, rate limiting, banner."""

from pentark.core.audit import AuditLog, NullAuditLog, read_records
from pentark.core.banner import render_banner
from pentark.core.errors import (
    AuthorizationError,
    ConfigError,
    PentarkError,
    PreflightError,
    ScopeError,
)
from pentark.core.ratelimit import RateLimiter
from pentark.core.scope import Authorization, Scope, Settings, load_scope

__all__ = [
    "AuditLog",
    "NullAuditLog",
    "read_records",
    "render_banner",
    "RateLimiter",
    "Authorization",
    "Scope",
    "Settings",
    "load_scope",
    "PentarkError",
    "ConfigError",
    "AuthorizationError",
    "ScopeError",
    "PreflightError",
]
