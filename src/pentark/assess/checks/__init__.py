"""Check registry.

Adding a new vulnerability class is a one-line append here — the runner discovers
checks from this list, so breadth grows without touching the orchestration.
"""

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.checks.misconfig import (
    DefaultCredentialsCheck,
    DirectoryListingCheck,
    HttpMethodsCheck,
    SensitiveFileExposureCheck,
    VerboseErrorCheck,
    WeakHeadersCheck,
)
from pentark.assess.checks.reflected_xss import ReflectedXssCheck
from pentark.assess.checks.security_headers import SecurityHeadersCheck
from pentark.assess.crypto import (
    CookieSecurityCheck,
    SecretsExposureCheck,
    TransportSecurityCheck,
    WeakTlsCheck,
)

# Instantiated checks the runner executes, in order. Passive/safe checks only —
# DefaultCredentialsCheck is active (submits logins) and is added on demand via
# `assess --default-creds`, never by default. WeakTlsCheck no-ops on non-HTTPS
# targets and degrades gracefully if the TLS handshake fails.
ALL_CHECKS: list[Check] = [
    SecurityHeadersCheck(),
    WeakHeadersCheck(),
    ReflectedXssCheck(),
    SensitiveFileExposureCheck(),
    DirectoryListingCheck(),
    VerboseErrorCheck(),
    HttpMethodsCheck(),
    TransportSecurityCheck(),
    WeakTlsCheck(),
    SecretsExposureCheck(),
    CookieSecurityCheck(),
]

__all__ = [
    "Check",
    "CheckContext",
    "ALL_CHECKS",
    "SecurityHeadersCheck",
    "WeakHeadersCheck",
    "ReflectedXssCheck",
    "SensitiveFileExposureCheck",
    "DirectoryListingCheck",
    "VerboseErrorCheck",
    "HttpMethodsCheck",
    "DefaultCredentialsCheck",
    "TransportSecurityCheck",
    "WeakTlsCheck",
    "SecretsExposureCheck",
    "CookieSecurityCheck",
]
