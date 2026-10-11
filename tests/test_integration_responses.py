"""Integration tests over the REAL requests/urllib3 stack via `responses`.

These validate behavior the hand-rolled fakes can't: genuine gzip decoding
through ``resp.raw.read(decode_content=True)``, the body-size cap on decoded
bytes, and that a 3xx with an external Location is read but never followed
(``allow_redirects=False``). Skipped automatically if `responses` is absent.

No real network: `responses` intercepts at the HTTP adapter.
"""
from __future__ import annotations

import gzip

import pytest

responses = pytest.importorskip("responses")

from peregrinestoop.common import ScopeChecker, ScopeViolation, StoopHTTP
from peregrinestoop.probes import probe_methods, probe_open_redirect

SCOPE = ScopeChecker.from_patterns(["*.target.com"])


@responses.activate
def test_real_gzip_body_is_decoded():
    payload = b"HELLO-WORLD" * 50
    responses.add(responses.GET, "https://a.target.com/",
                  body=gzip.compress(payload),
                  headers={"Content-Encoding": "gzip"},
                  content_type="text/html", status=200)
    http = StoopHTTP(SCOPE, rate=0)   # real requests.Session
    resp = http.get("https://a.target.com/")
    assert resp.content == payload    # transparently decompressed


@responses.activate
def test_body_cap_applies_to_decoded_gzip():
    payload = b"A" * 1000
    responses.add(responses.GET, "https://a.target.com/big",
                  body=gzip.compress(payload),
                  headers={"Content-Encoding": "gzip"}, status=200)
    http = StoopHTTP(SCOPE, rate=0, max_body=16)
    resp = http.get("https://a.target.com/big")
    assert len(resp.content) == 16    # cap applied to the decoded stream


@responses.activate
def test_redirect_read_not_followed():
    # register ONLY the in-scope login endpoint; the external target is NOT
    # registered, so following it would raise ConnectionError.
    responses.add(responses.GET, "https://a.target.com/login", status=302,
                  headers={"Location": "https://stoop-oob.example/"})
    http = StoopHTTP(SCOPE, rate=0)
    results = probe_open_redirect(http, "https://a.target.com/login", ["next"])
    assert results and results[0].kind == "open-redirect"
    assert "stoop-oob.example" in results[0].evidence
    # exactly one request was made (the redirect was not chased)
    assert len(responses.calls) == 1


@responses.activate
def test_options_methods_over_real_stack():
    responses.add(responses.OPTIONS, "https://a.target.com/", status=200,
                  headers={"Allow": "GET, POST, PUT, DELETE"})
    http = StoopHTTP(SCOPE, rate=0)
    r = probe_methods(http, "https://a.target.com/")
    assert r is not None and "PUT" in r.evidence and "DELETE" in r.evidence


@responses.activate
def test_scope_gate_runs_before_the_adapter():
    # nothing registered; an out-of-scope GET must raise ScopeViolation
    # (gate first), NOT a connection error from the adapter.
    http = StoopHTTP(SCOPE, rate=0)
    with pytest.raises(ScopeViolation):
        http.get("https://evil.com/")
    assert len(responses.calls) == 0   # no request ever reached the adapter
