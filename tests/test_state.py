"""Dedup / URL-normalization / state-store tests."""
from __future__ import annotations

from peregrinestoop.state import StateStore, normalize_url


def test_normalize_drops_values_keeps_sorted_keys():
    a = normalize_url("https://t.com/search?id=1&q=abc")
    b = normalize_url("https://t.com/search?q=xyz&id=999")
    assert a == b  # same endpoint + same param keys, different values
    assert a == "https://t.com/search?id&q"  # keys only, sorted, no values


def test_normalize_trailing_slash_and_case():
    assert normalize_url("HTTP://T.com/path/") == normalize_url("http://t.com/path")


def test_normalize_different_endpoint_differs():
    assert normalize_url("https://t.com/a?x=1") != normalize_url("https://t.com/b?x=1")


def test_seen_and_mark(tmp_path):
    db = StateStore(str(tmp_path / "s.sqlite"))
    url1 = "https://t.com/item?id=1"
    url2 = "https://t.com/item?id=2"  # same endpoint, different value
    assert not db.seen("GET", url1)
    db.mark_tested("GET", url1)
    assert db.seen("GET", url1)
    assert db.seen("GET", url2)      # dedup collapses the two
    assert not db.seen("POST", url1) # method is part of the key
    db.close()


def test_findings_roundtrip(tmp_path):
    db = StateStore(str(tmp_path / "s.sqlite"))
    db.record_finding("t.com", "open-redirect", "/go?url=", "medium")
    rows = db.findings("t.com")
    assert len(rows) == 1 and rows[0]["kind"] == "open-redirect"
    db.close()


def test_resume_returns_latest_session(tmp_path):
    db = StateStore(str(tmp_path / "s.sqlite"))
    db.touch_session("sess1", "a.com")
    db.touch_session("sess2", "b.com")
    assert db.resume()["session_id"] == "sess2"
    db.close()


def test_fingerprint_persist(tmp_path):
    db = StateStore(str(tmp_path / "s.sqlite"))
    db.save_fingerprint("t.com", {"server": "nginx"})
    assert db.get_fingerprint("t.com") == {"server": "nginx"}
    db.close()
