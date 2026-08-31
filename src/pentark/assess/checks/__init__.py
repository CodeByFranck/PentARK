"""Check registry.

Adding a new vulnerability class is a one-line append here — the runner discovers
checks from this list, so breadth grows without touching the orchestration.
"""

from pentark.assess.checks.base import Check, CheckContext
from pentark.assess.checks.reflected_xss import ReflectedXssCheck
from pentark.assess.checks.security_headers import SecurityHeadersCheck

# Instantiated checks the runner executes, in order.
ALL_CHECKS: list[Check] = [
    SecurityHeadersCheck(),
    ReflectedXssCheck(),
]

__all__ = ["Check", "CheckContext", "ALL_CHECKS", "SecurityHeadersCheck", "ReflectedXssCheck"]
