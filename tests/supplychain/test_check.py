"""Tests for the supply-chain check orchestration (target mocked, OSV stubbed)."""

from __future__ import annotations

import httpx

from pentark.assess.checks.base import CheckContext
from pentark.assess.supplychain.check import SupplyChainCheck
from pentark.assess.supplychain.models import Vulnerability

TARGET = "http://localhost:3000/"

_VULN = Vulnerability(
    osv_id="GHSA-jquery",
    cve_ids=("CVE-2012-6708",),
    summary="jQuery XSS via selector",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  # 6.1 Medium
)


class StubOsv:
    """Returns canned vulns for jquery@1.7.2, nothing for anything else."""

    def __init__(self):
        self.queried = []

    def query(self, component):
        self.queried.append((component.name, component.version))
        if component.name == "jquery" and component.version == "1.7.2":
            return [_VULN]
        return []


_PAGE = (
    "<html><head>"
    "<script src='/static/jquery-1.7.2.min.js'></script>"
    "<script src='https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js'></script>"
    "</head><body>ok</body></html>"
)


def _handler(request):
    path = request.url.path
    if path == "/":
        return httpx.Response(200, headers={"X-Powered-By": "PHP/7.2.1"}, text=_PAGE)
    if path == "/static/jquery-1.7.2.min.js":
        return httpx.Response(200, text="/*! jQuery v1.7.2 */")
    return httpx.Response(404, text="nope")


def test_scan_fingerprints_and_flags_vulnerable(http_factory):
    osv = StubOsv()
    check = SupplyChainCheck(osv)
    reports = check.scan(CheckContext(http=http_factory(_handler), target=TARGET))

    names = {r.component.name for r in reports}
    assert {"jquery", "bootstrap", "php"} <= names

    jq = next(r for r in reports if r.component.name == "jquery")
    assert jq.component.version == "1.7.2"
    assert jq.is_vulnerable and jq.checked

    # bootstrap is queryable (npm) but the stub returns nothing -> not vulnerable.
    bs = next(r for r in reports if r.component.name == "bootstrap")
    assert bs.checked and not bs.is_vulnerable
    # php came from a header, is not npm -> never queried.
    assert ("php", "7.2.1") not in osv.queried


def test_run_emits_finding_with_cve_and_severity(http_factory):
    check = SupplyChainCheck(StubOsv())
    findings = check.run(CheckContext(http=http_factory(_handler), target=TARGET))

    assert len(findings) == 1
    f = findings[0]
    assert "jquery" in f.name and "1.7.2" in f.name
    assert f.cwe == "CWE-1395"
    assert f.cvss_score == 6.1                 # from the OSV CVSS vector
    assert "CVE-2012-6708" in f.evidence


def test_package_lock_is_parsed_and_queried(http_factory):
    osv = StubOsv()

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text="<html><body>no scripts</body></html>")
        if request.url.path == "/package-lock.json":
            return httpx.Response(200, text='{"packages": {"node_modules/jquery": {"version": "1.7.2"}}}')
        return httpx.Response(404, text="nope")

    check = SupplyChainCheck(osv)
    findings = check.run(CheckContext(http=http_factory(handler), target=TARGET))
    assert ("jquery", "1.7.2") in osv.queried
    assert len(findings) == 1


def test_offline_mode_skips_osv(http_factory):
    # No OSV client -> fingerprint only, nothing queried, no vuln findings.
    check = SupplyChainCheck(None)
    ctx = CheckContext(http=http_factory(_handler), target=TARGET)
    reports = check.scan(ctx)
    assert reports and all(not r.checked for r in reports)
    assert check.run(ctx) == []
