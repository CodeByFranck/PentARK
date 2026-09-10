"""A01 – Broken Access Control auditing.

A dedicated sub-module rather than a :class:`~pentark.assess.checks.base.Check`,
because access-control testing is inherently *multi-identity* and *multi-request*
(replay the same recorded traffic under different sessions and compare), which the
stateless single-target Check interface does not model. Every request still goes
through the :class:`~pentark.assess.http_client.HttpClient` choke point, so scope,
throttling, and the audit log are enforced exactly as elsewhere.
"""

from pentark.assess.access.engine import AccessControlAuditor
from pentark.assess.access.models import RecordedRequest, ReplayResult, load_requests

__all__ = ["AccessControlAuditor", "RecordedRequest", "ReplayResult", "load_requests"]
