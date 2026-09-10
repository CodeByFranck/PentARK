"""Tests for injection-point discovery."""

from __future__ import annotations

from pentark.assess.injection.params import (
    build_request,
    points_from_forms,
    points_from_url,
)


def test_points_from_url_query():
    pts = points_from_url("http://h.test/search?q=1&page=2")
    assert {p.param for p in pts} == {"q", "page"}
    assert all(p.method == "GET" and p.action == "http://h.test/search" for p in pts)
    assert all(p.location == "query" for p in pts)


def test_points_from_url_no_query():
    assert points_from_url("http://h.test/search") == []


def test_points_from_forms_post():
    html = (
        "<form method='post' action='/login'>"
        "<input type='hidden' name='csrf' value='t'>"
        "<input type='text' name='user'>"
        "<input type='password' name='pass'>"
        "<button type='submit'>go</button></form>"
    )
    pts = points_from_forms(html, "http://h.test/page")
    names = {p.param for p in pts}
    assert {"csrf", "user", "pass"} <= names
    assert all(p.method == "POST" and p.action == "http://h.test/login" for p in pts)
    assert all(p.is_mutating for p in pts)


def test_build_request_get_and_post():
    [p] = points_from_url("http://h.test/s?q=1")
    method, url, data = build_request(p, "PAYLOAD")
    assert method == "GET" and "q=PAYLOAD" in url and data is None

    [fp] = [x for x in points_from_forms("<form method=post action=/x><input name=q></form>",
                                         "http://h.test/") if x.param == "q"]
    method, url, data = build_request(fp, "PAYLOAD")
    assert method == "POST" and data == {"q": "PAYLOAD"} and url == "http://h.test/x"
