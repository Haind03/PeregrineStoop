"""Audit-log analysis tests. Pure/offline, no network."""
from __future__ import annotations

import json

from peregrinestoop import cli
from peregrinestoop.audit import load_audit, summarize_audit


def _entry(**kw):
    base = {"ts": 1000.0, "session_id": "s1", "method": "GET",
            "url": "https://a.target.com/", "scope_check": "in-scope:a.target.com",
            "status": 200, "note": ""}
    base.update(kw)
    return base


def _write(tmp_path, entries):
    p = tmp_path / "audit.jsonl"
    with open(p, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")
    return str(p)


def test_summary_counts_sent_blocked_unsafe(tmp_path):
    entries = [
        _entry(),
        _entry(status=404, url="https://a.target.com/x"),
        _entry(scope_check="out-of-scope", status=None,
               url="https://evil.com/", note="blocked by scope gate"),
        _entry(scope_check="blocked-unsafe", status=None, method="DELETE",
               note="unsafe method without --allow-unsafe"),
        _entry(status=None, note="error: ConnectionError: boom"),
    ]
    s = summarize_audit(entries).to_dict()
    assert s["total"] == 5
    assert s["sent"] == 3          # 2 in-scope GET + the error one (still in-scope)
    assert s["blocked"] == 1
    assert s["unsafe_blocked"] == 1
    assert s["errors"] == 1
    # 2 in-scope + the unsafe-blocked (same default url) + the error one
    assert s["hosts"]["a.target.com"] == 4
    assert s["hosts"]["evil.com"] == 1
    assert s["status_distribution"]["200"] == 1
    assert s["status_distribution"]["404"] == 1


def test_load_audit_skips_malformed(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"ts":1}\nnot-json\n\n{"ts":2}\n', encoding="utf-8")
    assert len(load_audit(str(p))) == 2


def test_load_audit_missing_file():
    assert load_audit("/nonexistent/path/audit.jsonl") == []


def test_time_span_and_sessions(tmp_path):
    entries = [_entry(ts=100.0, session_id="s1"),
               _entry(ts=160.0, session_id="s2")]
    s = summarize_audit(entries).to_dict()
    assert s["time_span_seconds"] == 60.0
    assert s["sessions"] == 2


def test_cli_audit(tmp_path):
    path = _write(tmp_path, [
        _entry(),
        _entry(scope_check="out-of-scope", status=None, url="https://evil.com/"),
    ])
    out = tmp_path / "summary.json"
    rc = cli.main(["audit", "--audit-log", path, "--json", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["total"] == 2 and data["blocked"] == 1


# --- filters + CSV --------------------------------------------------------- #

def test_filter_entries_by_host_and_session():
    from peregrinestoop.audit import filter_entries
    entries = [
        _entry(session_id="s1"),
        _entry(scope_check="out-of-scope", url="https://evil.com/", session_id="s2"),
        _entry(session_id="s1", url="https://a.target.com/x"),
    ]
    assert len(filter_entries(entries, host="a.target.com")) == 2
    assert len(filter_entries(entries, host="evil.com")) == 1
    assert len(filter_entries(entries, session="s1")) == 2
    assert len(filter_entries(entries, host="a.target.com", session="s1")) == 2


def test_to_csv_header_and_rows():
    from peregrinestoop.audit import to_csv
    csv_text = to_csv([_entry(iso="2026-01-01T00:00:00Z")])
    lines = csv_text.strip().splitlines()
    assert lines[0] == "iso,session_id,method,url,scope_check,status,note"
    assert "a.target.com" in lines[1]


def test_cli_audit_csv_and_filter(tmp_path):
    path = _write(tmp_path, [
        _entry(session_id="s1"),
        _entry(scope_check="out-of-scope", status=None,
               url="https://evil.com/", session_id="s2"),
    ])
    csv_out = tmp_path / "rows.csv"
    rc = cli.main(["audit", "--audit-log", path, "--host", "a.target.com",
                   "--csv", str(csv_out)])
    assert rc == 0
    rows = csv_out.read_text().strip().splitlines()
    assert len(rows) == 2          # header + 1 filtered row (a.target.com only)
    assert "evil.com" not in csv_out.read_text()
