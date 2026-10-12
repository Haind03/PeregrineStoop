"""Favicon fingerprinting unit tests."""
from __future__ import annotations

from peregrinestoop.fingerprint import favicon_hash, load_favicon_map, lookup_favicon


def test_favicon_hash_is_stable():
    assert favicon_hash(b"TESTFAVICON") == favicon_hash(b"TESTFAVICON")
    assert favicon_hash(b"a") != favicon_hash(b"b")


def test_favicon_map_loads_and_filters_comments():
    m = load_favicon_map()
    assert all(not k.startswith("_") for k in m)


def test_lookup_favicon_hit_and_miss():
    h = favicon_hash(b"TESTFAVICON")
    assert lookup_favicon(h) is not None            # seeded entry
    assert lookup_favicon("deadbeef") is None
    assert lookup_favicon("x", {"x": {"tech": "Foo"}})["tech"] == "Foo"
