"""Snapshot + diff tests (no network)."""
from __future__ import annotations

from peregrinestoop.diff import (
    diff_snapshots,
    extract_surface,
    sensitivity,
    snapshot_from_items,
)


def test_extract_surface_finds_endpoints_and_params():
    body = (
        b'<a href="/api/v2/users?page=1">u</a>'
        b'<script>fetch("/internal/debug?token=x")</script>'
    )
    eps, params = extract_surface("https://t.com/", body)
    assert "/api/v2/users" in eps
    assert "/internal/debug" in eps
    assert "page" in params
    assert "token" in params


def test_sensitivity_promotes_interesting_paths():
    assert sensitivity("/admin/panel") > sensitivity("/about")
    assert sensitivity("/api/v1/users") > sensitivity("/home")


def test_diff_reports_only_new_parts():
    a_items = {"https://t.com/": b'<a href="/home">h</a>'}
    b_items = {
        "https://t.com/": b'<a href="/home">h</a><a href="/admin/secret?key=1">x</a>',
        "https://t.com/app.js": b'fetch("/api/internal?debug=1")',
    }
    snap_a = snapshot_from_items("t.com", a_items)
    snap_b = snapshot_from_items("t.com", b_items)
    diff = diff_snapshots(snap_a, snap_b)

    new_paths = [e["path"] for e in diff.new_endpoints]
    assert "/admin/secret" in new_paths
    assert "/api/internal" in new_paths
    assert "/home" not in new_paths          # unchanged → not reported
    assert "key" in diff.new_params
    assert "debug" in diff.new_params
    assert "https://t.com/app.js" in diff.new_pages
    # most sensitive endpoint ranked first
    assert diff.new_endpoints[0]["score"] >= diff.new_endpoints[-1]["score"]


def test_diff_detects_changed_content_same_url():
    a = snapshot_from_items("t.com", {"https://t.com/x": b"v1"})
    b = snapshot_from_items("t.com", {"https://t.com/x": b"v2-changed"})
    diff = diff_snapshots(a, b)
    assert len(diff.changed_js) == 1
    assert diff.changed_js[0]["url"] == "https://t.com/x"


def test_identical_snapshots_empty_diff():
    items = {"https://t.com/": b'<a href="/home">h</a>'}
    a = snapshot_from_items("t.com", items)
    b = snapshot_from_items("t.com", items)
    assert diff_snapshots(a, b).empty


def test_snapshot_roundtrip(tmp_path):
    from peregrinestoop.diff import Snapshot

    snap = snapshot_from_items("t.com", {"https://t.com/": b'<a href="/api/v1/x">a</a>'})
    p = tmp_path / "snap.json"
    snap.save(str(p))
    loaded = Snapshot.load(str(p))
    assert loaded.all_endpoints() == snap.all_endpoints()
