"""SARIF 2.1.0 export tests."""
from __future__ import annotations

import json

from peregrinestoop import cli
from peregrinestoop.common import ScopeChecker, StoopHTTP
from peregrinestoop.sarif import to_sarif
from conftest import FakeSession, make_response


_FINDINGS = [
    {"severity": "high", "kind": "open-redirect", "detail": "param next", "confidence": "medium"},
    {"severity": "medium", "kind": "reflected-input", "detail": "context html"},
    {"severity": "info", "kind": "reachable-path", "detail": "/robots.txt -> 200"},
    {"severity": "high", "kind": "open-redirect", "detail": "param url"},  # dup kind
]


def test_sarif_structure_and_levels():
    doc = to_sarif("a.target.com", _FINDINGS)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "PeregrineStoop"
    # one rule per distinct kind (3), results for all (4)
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 4
    levels = [r["level"] for r in run["results"]]
    assert levels[0] == "error" and levels[1] == "warning" and levels[2] == "note"
    assert all("candidate to verify" in r["message"]["text"] for r in run["results"])
    assert run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "https://a.target.com/"


def test_sarif_empty_findings():
    doc = to_sarif("x.com", [])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_cli_report_sarif(monkeypatch, tmp_path):
    def handler(method, url, kw):
        if method == "OPTIONS":
            return make_response(200, {"Allow": "GET"}, b"")
        return make_response(200, {"Server": "nginx"}, b"<html></html>")

    def fake_build(args, scope, sid):
        return StoopHTTP(scope, rate=0, session=FakeSession(handler))
    monkeypatch.setattr(cli, "_build_http", fake_build)

    db = str(tmp_path / "s.sqlite")
    cli.main(["run", "https://a.target.com/", "--scope", "*.target.com",
              "--budget", "60", "--state-db", db,
              "--audit-log", str(tmp_path / "a.jsonl"),
              "--json", str(tmp_path / "r.json")])
    out = tmp_path / "out.sarif"
    rc = cli.main(["report", "https://a.target.com/", "--state-db", db,
                   "--sarif", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "PeregrineStoop"
