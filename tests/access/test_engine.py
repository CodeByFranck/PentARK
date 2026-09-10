"""Tests for the A01 access-control auditor."""

from __future__ import annotations

import httpx

from pentark.assess.access.engine import AccessControlAuditor
from pentark.assess.access.models import RecordedRequest

BASE = "http://localhost:3000"


def identity_of(request: httpx.Request) -> str:
    """Recover which identity a mocked request came from (see conftest creds)."""
    if request.headers.get("authorization") == "Bearer high":
        return "high"
    if "session=low" in request.headers.get("cookie", ""):
        return "low"
    return "anonymous"


def _auditor(http, scope, **kw) -> AccessControlAuditor:
    return AccessControlAuditor(http, scope, **kw)


# -- cross-identity replay --------------------------------------------------

def test_cross_identity_leak_flags_lower_privilege(http_factory, scope):
    # /account returns the same body to everyone -> broken access control.
    def handler(request):
        return httpx.Response(200, text="SECRET ACCOUNT DATA")

    http = http_factory(handler)
    req = RecordedRequest(name="account", method="GET", url=f"{BASE}/account", recorded_as="high")
    findings = _auditor(http, scope).run([req])

    names = [f.name for f in findings if f.check_id == "access-broken"]
    # low-priv AND anonymous both see high-priv data.
    assert any("lower-privileged" in n for n in names)
    assert any("unauthenticated" in n for n in names)
    top = next(f for f in findings if f.check_id == "access-broken")
    assert top.cwe == "CWE-863"
    assert top.confidence == "high"  # identical length


def test_cross_identity_properly_controlled_is_clean(http_factory, scope):
    # Only high-priv gets the data; everyone else is denied.
    def handler(request):
        if identity_of(request) == "high":
            return httpx.Response(200, text="SECRET ACCOUNT DATA")
        return httpx.Response(403, text="forbidden")

    http = http_factory(handler)
    req = RecordedRequest(name="account", method="GET", url=f"{BASE}/account", recorded_as="high")
    findings = _auditor(http, scope).run([req])
    assert [f for f in findings if f.check_id == "access-broken"] == []


def test_redirect_to_login_is_not_a_leak(http_factory, scope):
    # Unauthed request is redirected to login (302) -> access control worked.
    def handler(request):
        if identity_of(request) == "high":
            return httpx.Response(200, text="SECRET ACCOUNT DATA")
        return httpx.Response(302, headers={"location": "/login"})

    http = http_factory(handler)
    req = RecordedRequest(name="account", method="GET", url=f"{BASE}/account", recorded_as="high")
    findings = _auditor(http, scope).run([req])
    assert [f for f in findings if f.check_id == "access-broken"] == []


# -- IDOR -------------------------------------------------------------------

def test_idor_numeric_id_retrieves_other_record(http_factory, scope):
    # Any invoice id returns a distinct, valid record -> IDOR (read-only PoC).
    def handler(request):
        n = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, text=f"invoice #{n} for customer {n}0000")

    http = http_factory(handler)
    req = RecordedRequest(name="invoice", method="GET", url=f"{BASE}/invoices/5", recorded_as="low")
    findings = _auditor(http, scope).run([req])

    idor = [f for f in findings if f.check_id == "access-idor"]
    assert len(idor) == 1
    assert idor[0].cwe == "CWE-639"
    assert "invoice #" in idor[0].evidence  # PoC shows the retrieved record


def test_idor_query_param(http_factory, scope):
    def handler(request):
        uid = request.url.params.get("id", "?")
        return httpx.Response(200, text=f"profile of user {uid}")

    http = http_factory(handler)
    req = RecordedRequest(name="profile", method="GET", url=f"{BASE}/profile?id=42", recorded_as="low")
    findings = _auditor(http, scope).run([req])
    assert any(f.check_id == "access-idor" for f in findings)


def test_idor_denied_neighbor_is_clean(http_factory, scope):
    # Only record 5 is accessible; neighbours are 403 -> access enforced.
    def handler(request):
        n = request.url.path.rsplit("/", 1)[-1]
        if n == "5":
            return httpx.Response(200, text="invoice #5")
        return httpx.Response(403, text="forbidden")

    http = http_factory(handler)
    req = RecordedRequest(name="invoice", method="GET", url=f"{BASE}/invoices/5", recorded_as="low")
    findings = _auditor(http, scope).run([req])
    assert [f for f in findings if f.check_id == "access-idor"] == []


def test_idor_identical_body_is_not_flagged(http_factory, scope):
    # Every id returns the exact same body -> not a distinct record, no IDOR.
    def handler(request):
        return httpx.Response(200, text="static page, same for all ids")

    http = http_factory(handler)
    req = RecordedRequest(name="thing", method="GET", url=f"{BASE}/things/5", recorded_as="low")
    findings = _auditor(http, scope).run([req])
    assert [f for f in findings if f.check_id == "access-idor"] == []


# -- forced browsing --------------------------------------------------------

def test_forced_browsing_admin_open_to_anon(http_factory, scope):
    def handler(request):
        if request.url.path.rstrip("/") == "/admin":
            return httpx.Response(200, text="admin dashboard")
        return httpx.Response(404, text="nope")

    http = http_factory(handler)
    findings = _auditor(http, scope, admin_paths=("/admin",)).run([], forced_browsing_base=f"{BASE}/")
    fb = [f for f in findings if f.check_id == "access-forced-browsing"]
    assert len(fb) == 1
    assert fb[0].cwe == "CWE-425"
    assert "unauthenticated" in fb[0].name


def test_forced_browsing_protected_is_clean(http_factory, scope):
    def handler(request):
        return httpx.Response(403, text="forbidden")

    http = http_factory(handler)
    findings = _auditor(http, scope, admin_paths=("/admin",)).run([], forced_browsing_base=f"{BASE}/")
    assert [f for f in findings if f.check_id == "access-forced-browsing"] == []


# -- method tampering -------------------------------------------------------

def test_method_tampering_safe_mode_uses_options(http_factory, scope):
    sent = []

    def handler(request):
        sent.append(request.method)
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"allow": "GET, PUT, DELETE, OPTIONS"})
        return httpx.Response(200, text="data")

    http = http_factory(handler)
    req = RecordedRequest(name="item", method="GET", url=f"{BASE}/item/1", recorded_as="low")
    findings = _auditor(http, scope, allow_mutation=False).run([req])

    mt = [f for f in findings if f.check_id == "access-method-tampering"]
    assert len(mt) == 1
    assert mt[0].confidence == "low"       # advertised, not exercised
    assert "PUT" in mt[0].description and "DELETE" in mt[0].description
    assert "PUT" not in sent and "DELETE" not in sent  # nothing mutating was sent


def test_method_tampering_active_requires_opt_in(http_factory, scope):
    sent = []

    def handler(request):
        sent.append(request.method)
        if request.method in ("PUT", "DELETE"):
            return httpx.Response(200, text="modified")  # accepted -> bad
        return httpx.Response(200, text="data")

    http = http_factory(handler)
    req = RecordedRequest(name="item", method="GET", url=f"{BASE}/item/1", recorded_as="low")
    findings = _auditor(http, scope, allow_mutation=True).run([req])

    mt = [f for f in findings if f.check_id == "access-method-tampering"]
    assert {f.endpoint.split()[0] for f in mt} == {"PUT", "DELETE"}
    assert all(f.confidence == "high" for f in mt)
    assert "PUT" in sent and "DELETE" in sent


def test_method_tampering_405_is_clean(http_factory, scope):
    def handler(request):
        if request.method in ("PUT", "DELETE"):
            return httpx.Response(405, text="method not allowed")
        return httpx.Response(200, text="data")

    http = http_factory(handler)
    req = RecordedRequest(name="item", method="GET", url=f"{BASE}/item/1", recorded_as="low")
    findings = _auditor(http, scope, allow_mutation=True).run([req])
    assert [f for f in findings if f.check_id == "access-method-tampering"] == []


# -- safety -----------------------------------------------------------------

def test_mutating_flow_skipped_in_safe_mode(http_factory, scope):
    sent = []

    def handler(request):
        sent.append(request.method)
        return httpx.Response(200, text="ok")

    http = http_factory(handler)
    # A recorded POST should not be replayed at all in safe mode.
    req = RecordedRequest(name="create", method="POST", url=f"{BASE}/items", recorded_as="high")
    findings = _auditor(http, scope, allow_mutation=False).run([req])
    assert [f for f in findings if f.check_id == "access-broken"] == []
    assert "POST" not in sent  # nothing state-changing was sent
