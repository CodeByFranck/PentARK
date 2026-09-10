"""Tests for component fingerprinting (pure functions)."""

from __future__ import annotations

from pentark.assess.supplychain import fingerprint as fp


def test_script_url_cdnjs():
    c = fp.from_script_url("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js")
    assert c and c.name == "jquery" and c.version == "3.4.1" and c.ecosystem == "npm"


def test_script_url_jsdelivr_npm():
    c = fp.from_script_url("https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js")
    assert c and c.name == "bootstrap" and c.version == "4.3.1"


def test_script_url_unpkg():
    c = fp.from_script_url("https://unpkg.com/vue@2.6.10/dist/vue.js")
    assert c and c.name == "vue" and c.version == "2.6.10"


def test_script_url_local_filename():
    c = fp.from_script_url("/static/js/jquery-1.7.2.min.js")
    assert c and c.name == "jquery" and c.version == "1.7.2"


def test_script_url_no_version_is_none():
    assert fp.from_script_url("/static/js/app.bundle.js") is None


def test_script_body_jquery_banner():
    body = "/*! jQuery JavaScript Library v1.12.4\n * https://jquery.com/ */"
    comps = fp.from_script_body(body)
    assert any(c.name == "jquery" and c.version == "1.12.4" for c in comps)


def test_headers_server_and_powered_by():
    comps = fp.from_headers({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.2.1"})
    names = {(c.name, c.version) for c in comps}
    assert ("nginx", "1.18.0") in names
    assert ("php", "7.2.1") in names
    # Non-npm -> not queried against OSV.
    assert all(not c.queryable for c in comps)


def test_meta_generator_wordpress():
    html = '<head><meta name="generator" content="WordPress 5.8.1" /></head>'
    comps = fp.from_meta_generator(html)
    assert comps and comps[0].name == "wordpress" and comps[0].version == "5.8.1"


def test_parse_package_json_strips_ranges():
    text = '{"dependencies": {"lodash": "^4.17.4", "star": "*"}, "devDependencies": {"jquery": "~3.4.1"}}'
    comps = {c.name: c.version for c in fp.parse_package_json(text)}
    assert comps == {"lodash": "4.17.4", "jquery": "3.4.1"}  # "star": "*" skipped


def test_parse_package_lock_v2():
    text = '{"lockfileVersion": 2, "packages": {"": {"name": "app"}, "node_modules/jquery": {"version": "3.4.1"}}}'
    comps = fp.parse_package_lock(text)
    assert len(comps) == 1
    assert comps[0].name == "jquery" and comps[0].version == "3.4.1"
    assert comps[0].confidence == "high"  # resolved version


def test_parse_package_lock_v1_nested():
    text = '{"dependencies": {"jquery": {"version": "1.7.2", "dependencies": {"sizzle": {"version": "1.0.0"}}}}}'
    comps = {c.name: c.version for c in fp.parse_package_lock(text)}
    assert comps == {"jquery": "1.7.2", "sizzle": "1.0.0"}


def test_dedupe_prefers_high_confidence():
    from pentark.assess.supplychain.models import Component

    low = Component("jquery", "3.4.1", source="package.json", confidence="medium")
    high = Component("jquery", "3.4.1", source="package-lock.json", confidence="high")
    out = fp.dedupe([low, high])
    assert len(out) == 1 and out[0].confidence == "high"
