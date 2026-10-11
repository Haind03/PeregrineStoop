"""Markdown report rendering tests (pure + via CLI, no network)."""
from __future__ import annotations

import json

from peregrinestoop import cli
from peregrinestoop.report import render_report
from peregrinestoop.common import StoopHTTP
from conftest import FakeSession, make_response


def _fp():
    return {
        "host": "a.target.com", "server": "Apache/2.4.49", "language": "php",
        "cdn": None, "waf": "Cloudflare", "allowed_methods": ["GET", "PUT"],
        "tech": [{"name": "PHP", "confidence": "high", "evidence": "cookie"}],
        "vuln_classes": ["lfi", "missing-hsts", "clickjacking"],
        "cve_candidates": [{"cve": "CVE-2021-41773", "for": "Apache httpd",
                            "confidence": "low", "verify": "check 2.4.49"}],
        "security_headers": {"x-frame-options": "DENY"},
    }


def test_render_contains_core_sections():
    md = render_report("a.target.com", _fp(), [
        {"severity": "high", "kind": "open-redirect", "detail": "param next"},
        {"severity": "info", "kind": "reachable-path", "detail": "/robots.txt"},
    ])
    assert "# PeregrineStoop recon report — a.target.com" in md
    assert "Post and Telecommunication Institute of Technology" in md
    assert "## Technology fingerprint" in md
    assert "Cloudflare" in md
    assert "CVE-2021-41773" in md
    assert "## Findings" in md
    # high severity sorts above info
    assert md.index("open-redirect") < md.index("reachable-path")
    assert "candidate" in md.lower()


def test_render_includes_cvss_templates():
    md = render_report("a.target.com", None, [
        {"severity": "medium", "kind": "reflected-input", "detail": "ctx html"},
        {"severity": "high", "kind": "open-redirect", "detail": "param next"},
        {"severity": "info", "kind": "reachable-path", "detail": "/robots"},
    ])
    assert "Suggested CVSS 3.1 starting vectors" in md
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in md  # reflected-input
    assert "verify before use" in md.lower()
    # reachable-path has no CVSS hint -> not listed in the vector table
    assert md.count("reachable-path") == 1  # only in findings table


def test_no_cvss_section_when_no_hintable_kinds():
    md = render_report("x.com", None,
                       [{"severity": "info", "kind": "reachable-path", "detail": "/x"}])
    assert "Suggested CVSS" not in md


def test_render_handles_empty():
    md = render_report("x.com", None, [])
    assert "No findings recorded yet." in md
    assert "none detected" in md  # waf/cdn fallback


def test_detail_pipes_escaped():
    md = render_report("x.com", None,
                       [{"severity": "low", "kind": "k", "detail": "a|b|c"}])
    assert "a\\|b\\|c" in md


def test_cli_report_roundtrip(monkeypatch, tmp_path):
    # run first to populate state, then report from it
    def handler(method, url, kw):
        if method == "OPTIONS":
            return make_response(200, {"Allow": "GET, DELETE"}, b"")
        return make_response(200, {"Server": "nginx/1.18.0"}, b"<html></html>")

    def fake_build(args, scope, sid):
        return StoopHTTP(scope, rate=0, session=FakeSession(handler))
    monkeypatch.setattr(cli, "_build_http", fake_build)

    db = str(tmp_path / "s.sqlite")
    cli.main([
        "run", "https://a.target.com/", "--scope", "*.target.com",
        "--budget", "60", "--state-db", db,
        "--audit-log", str(tmp_path / "a.jsonl"), "--json", str(tmp_path / "r.json"),
    ])
    out = tmp_path / "report.md"
    rc = cli.main(["report", "https://a.target.com/", "--state-db", db,
                   "--out", str(out)])
    assert rc == 0
    md = out.read_text()
    assert "a.target.com" in md
    assert "nginx" in md
    assert "## Findings" in md
