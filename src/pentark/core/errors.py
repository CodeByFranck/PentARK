"""Typed exception hierarchy for PentARK.

A single base (:class:`PentarkError`) lets the CLI catch everything we raise
deliberately and print a clean message, while callers can still catch a precise
subclass (bad config vs. missing authorization vs. an off-scope target).
"""

from __future__ import annotations


class PentarkError(Exception):
    """Base class for all errors PentARK raises intentionally."""


class ConfigError(PentarkError):
    """The scope/config file is missing, malformed, or fails validation."""


class AuthorizationError(PentarkError):
    """The authorization gate refused to run (not authorized / expired / incomplete)."""


class ScopeError(PentarkError):
    """A request/action targeted something outside the authorized scope."""


class PreflightError(PentarkError):
    """A required external tool or dependency is missing."""


__all__ = [
    "PentarkError",
    "ConfigError",
    "AuthorizationError",
    "ScopeError",
    "PreflightError",
]
