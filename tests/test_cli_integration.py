"""End-to-end CLI runs with HTTP fully mocked (no real network).

Monkeypatches ``_build_http`` so the orchestrator drives a fake session.
"""
from __future__ import annotations

import json

from peregrinestoop import cli
from peregrinestoop.common import ScopeChecker, StoopHTTP
from conftest import FakeSession, make_response


def _patch_http(monkeypatch, handler):
    def fake_build(args, scope, sid):
        return StoopHTTP(scope, rate=0, session=FakeSession(handler))
    monkeypatch.setattr(cli, "_build_http", fake_build)


def test_run_pipeline_offline(monkeypatch, tmp_path):
    def handler(method, url, kw):
        if url.endswith("/"):  # the base fingerprint GET
            return make_response(
                200, {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/8.1"},
                b"<html>wp-content</html>")
        if url.endswith("/robots.txt"):
            return make_response(200, {}, b"User-agent: *")
        return make_response(404, {}, b"nope")

    _patch_http(monkeypatch, handler)
    out = tmp_path / "run.json"
    rc = cli.main([
        "run", "https://app.target.com/",
        "--scope", "*.target.com",
        "--budget", "60",
        "--state-db", str(tmp_path / "s.sqlite"),
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["target"] == "app.target.com"
    assert data["fingerprint"]["server"].startswith("Apache")
    assert any("php" in (data["fingerprint"]["language"] or "") for _ in [0])
    # robots.txt reachable -> recorded as a finding
    assert any(f["kind"] == "reachable-path" for f in data["findings"])
    # CVE candidate for Apache 2.4.49 routed
    assert any(c["cve"] == "CVE-2021-41773"
               for c in data["fingerprint"]["cve_candidates"])


def test_run_refuses_out_of_scope_target(monkeypatch, tmp_path):
    _patch_http(monkeypatch, lambda m, u, kw: make_response(200, {}, b""))
    rc = cli.main([
        "run", "https://evil.com/",
        "--scope", "*.target.com",
        "--state-db", str(tmp_path / "s.sqlite"),
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(tmp_path / "r.json"),
    ])
    assert rc == 3  # ScopeViolation surfaced as exit code


def test_fingerprint_cmd_offline(monkeypatch, tmp_path):
    _patch_http(monkeypatch, lambda m, u, kw: make_response(
        200, {"Set-Cookie": "JSESSIONID=abc"}, b""))
    out = tmp_path / "fp.json"
    rc = cli.main([
        "fingerprint", "https://a.target.com/",
        "--scope", "*.target.com",
        "--state-db", str(tmp_path / "s.sqlite"),
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(out),
    ])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["language"] == "java"
    assert "deserialization" in data["vuln_classes"]


def test_diff_cmd_baseline_then_change(monkeypatch, tmp_path):
    # first snapshot: only /home
    _patch_http(monkeypatch, lambda m, u, kw: make_response(
        200, {}, b'<a href="/home">h</a>'))
    base = tmp_path / "base.json"
    rc = cli.main([
        "diff", "https://a.target.com/",
        "--scope", "*.target.com",
        "--snapshot", str(base),
        "--state-db", str(tmp_path / "s.sqlite"),
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(tmp_path / "d1.json"),
    ])
    assert rc == 0 and base.exists()

    # second run: new admin endpoint appears -> diff reports it
    _patch_http(monkeypatch, lambda m, u, kw: make_response(
        200, {}, b'<a href="/home">h</a><a href="/admin/panel?token=1">x</a>'))
    out2 = tmp_path / "d2.json"
    rc = cli.main([
        "diff", "https://a.target.com/",
        "--scope", "*.target.com",
        "--baseline", str(base),
        "--snapshot", str(tmp_path / "snap2.json"),
        "--state-db", str(tmp_path / "s.sqlite"),
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(out2),
    ])
    assert rc == 0
    diff = json.loads(out2.read_text())["diff"]
    paths = [e["path"] for e in diff["new_endpoints"]]
    assert "/admin/panel" in paths
    assert "token" in diff["new_params"]


def test_resume_after_run(monkeypatch, tmp_path):
    db = str(tmp_path / "s.sqlite")
    _patch_http(monkeypatch, lambda m, u, kw: make_response(200, {}, b""))
    cli.main([
        "run", "https://a.target.com/",
        "--scope", "*.target.com",
        "--budget", "30",
        "--state-db", db,
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(tmp_path / "r.json"),
    ])
    out = tmp_path / "resume.json"
    rc = cli.main(["resume", "--state-db", db, "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["session"]["target"] == "a.target.com"
