"""Passive JS endpoint extraction tests."""
from __future__ import annotations

from peregrinestoop.crawl import extract_js_endpoints


def test_extract_js_endpoints_finds_calls_and_literals():
    body = (b'<script>fetch("/api/v1/users?id=1");'
            b'axios.get("/graphql");'
            b'var u="/internal/debug";'
            b'xhr.open("GET","/v2/orders")</script>')
    eps = extract_js_endpoints("https://a.target.com/", body)
    assert any("/api/v1/users" in e for e in eps)
    assert any("/graphql" in e for e in eps)
    assert any("/internal/debug" in e for e in eps)
    assert any("/v2/orders" in e for e in eps)


def test_extract_js_endpoints_same_host_only():
    body = b'fetch("https://evil.com/api/x");fetch("/api/ok")'
    eps = extract_js_endpoints("https://a.target.com/", body)
    assert any("/api/ok" in e for e in eps)
    assert not any("evil.com" in e for e in eps)
