"""Tests for the interactive scope.yaml scaffolding."""

from __future__ import annotations

import datetime as dt

from pentark.core.scope import load_scope
from pentark.scaffold import build_scope_yaml, normalize_targets, run_init

TODAY = dt.date(2026, 8, 31)


def test_normalize_url_target():
    hosts, prefixes = normalize_targets(["http://localhost:3000/app"])
    assert prefixes == ["http://localhost:3000/app/"]
    assert hosts == ["localhost"]


def test_normalize_bare_host_gets_host_and_prefix():
    hosts, prefixes = normalize_targets(["192.168.56.101"])
    assert hosts == ["192.168.56.101"]
    assert prefixes == ["http://192.168.56.101/"]


def test_normalize_dedupes_and_skips_blanks():
    hosts, prefixes = normalize_targets(["localhost", "localhost", "", "  "])
    assert hosts == ["localhost"]


def test_build_scope_yaml_round_trips_through_loader(tmp_path):
    text = build_scope_yaml(
        operator="Op <op@example.com>",
        acknowledgement="authorized",
        signed="Op, 2026-08-31",
        expires="2099-12-31",
        hosts=["192.168.56.101"],
        url_prefixes=["http://192.168.56.101/"],
    )
    p = tmp_path / "scope.yaml"
    p.write_text(text, encoding="utf-8")
    sc = load_scope(p)                      # must be valid YAML the loader accepts
    sc.require_authorization(now=TODAY)     # and pass the gate
    assert sc.is_in_scope("http://192.168.56.101/mutillidae/")


class ScriptedIO:
    def __init__(self, answers, confirms):
        self._answers = list(answers)
        self._confirms = list(confirms)
        self.out: list[str] = []

    def ask(self, prompt, default):
        return self._answers.pop(0)

    def confirm(self, prompt):
        return self._confirms.pop(0)

    def say(self, msg):
        self.out.append(str(msg))


def test_run_init_writes_authorized_scope(tmp_path):
    path = tmp_path / "scope.yaml"
    io = ScriptedIO(
        # operator, target1, target2, blank(finish), expires, signer
        answers=["Franck <f@example.com>", "192.168.56.101",
                 "http://localhost:3000/", "", "2099-12-31", "Franck"],
        confirms=[True],  # attest authorized
    )
    assert run_init(io.ask, io.confirm, io.say, path=path, today=TODAY, exists=False) is True

    sc = load_scope(path)
    sc.require_authorization(now=TODAY)
    assert "192.168.56.101" in sc.hosts
    assert sc.is_in_scope("http://localhost:3000/rest")
    assert sc.is_in_scope("http://192.168.56.101/mutillidae/")


def test_run_init_declined_authorization(tmp_path):
    path = tmp_path / "scope.yaml"
    io = ScriptedIO(
        answers=["Op <o@e.com>", "192.168.56.101", "", "2099-12-31", "Op"],
        confirms=[False],  # not attested
    )
    assert run_init(io.ask, io.confirm, io.say, path=path, today=TODAY, exists=False) is True
    sc = load_scope(path)
    assert sc.authorization.authorized is False
