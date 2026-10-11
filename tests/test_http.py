"""StoopHTTP integration: streaming body cap, audit, rate math, methods.

Exercises the real request() path with a faithful fake session + raw stream.
No real network.
"""
from __future__ import annotations

import json

import pytest
import requests

from peregrinestoop.common import (
    AuditLogger,
    RateLimiter,
    ScopeChecker,
    StoopHTTP,
)
from conftest import FakeSession, make_response


SCOPE = ScopeChecker.from_patterns(["*.target.com"])


def _read_audit(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(ln) for ln in fh if ln.strip()]


def test_get_returns_body_and_audits_success(tmp_path):
    sess = FakeSession(lambda m, u, kw: make_response(
        200, {"Server": "nginx"}, b"hello-body"))
    audit = AuditLogger(str(tmp_path / "a.jsonl"), "sid1")
    http = StoopHTTP(SCOPE, audit=audit, rate=0, session=sess)

    resp = http.get("https://a.target.com/")
    assert resp.status_code == 200
    assert resp.content == b"hello-body"
    assert sess.sent[0][0] == "GET"

    rec = _read_audit(tmp_path / "a.jsonl")[-1]
    assert rec["status"] == 200
    assert rec["scope_check"] == "in-scope:a.target.com"
    assert rec["session_id"] == "sid1"


def test_body_size_cap_truncates_and_notes(tmp_path):
    big = b"A" * 500
    sess = FakeSession(lambda m, u, kw: make_response(200, {}, big))
    audit = AuditLogger(str(tmp_path / "a.jsonl"), "sid")
    http = StoopHTTP(SCOPE, audit=audit, rate=0, session=sess, max_body=10)

    resp = http.get("https://a.target.com/")
    assert len(resp.content) == 10          # capped
    rec = _read_audit(tmp_path / "a.jsonl")[-1]
    assert "truncated" in rec["note"]


def test_error_path_audits_then_reraises(tmp_path):
    def boom(m, u, kw):
        raise requests.ConnectionError("refused")

    sess = FakeSession(boom)
    audit = AuditLogger(str(tmp_path / "a.jsonl"), "sid")
    http = StoopHTTP(SCOPE, audit=audit, rate=0, session=sess)

    with pytest.raises(requests.ConnectionError):
        http.get("https://a.target.com/")
    rec = _read_audit(tmp_path / "a.jsonl")[-1]
    assert rec["status"] is None
    assert "ConnectionError" in rec["note"]


def test_head_and_options_are_safe(tmp_path):
    sess = FakeSession(lambda m, u, kw: make_response(204, {}, b""))
    http = StoopHTTP(SCOPE, rate=0, session=sess)
    assert http.head("https://a.target.com/").status_code == 204
    assert http.options("https://a.target.com/").status_code == 204
    assert [c[0] for c in sess.sent] == ["HEAD", "OPTIONS"]


def test_unsafe_blocked_then_allowed(tmp_path):
    sess = FakeSession(lambda m, u, kw: make_response(200, {}, b""))
    # blocked by default
    http = StoopHTTP(SCOPE, rate=0, session=sess, allow_unsafe=False)
    with pytest.raises(PermissionError):
        http.request("POST", "https://a.target.com/x")
    assert sess.sent == []
    # allowed with flag
    http2 = StoopHTTP(SCOPE, rate=0, session=sess, allow_unsafe=True)
    assert http2.request("POST", "https://a.target.com/x").status_code == 200
    assert sess.sent[0][0] == "POST"


def test_default_request_options_are_defensive(tmp_path):
    captured = {}

    def grab(m, u, kw):
        captured.update(kw)
        return make_response(200, {}, b"")

    http = StoopHTTP(SCOPE, rate=0, session=FakeSession(grab), timeout=7)
    http.get("https://a.target.com/")
    assert captured["timeout"] == 7
    assert captured["allow_redirects"] is False   # no silent cross-host redirect
    assert captured["verify"] is True


def test_user_agent_declares_authorized_testing():
    sess = FakeSession()
    StoopHTTP(SCOPE, rate=0, session=sess)
    ua = sess.headers["User-Agent"]
    assert "PeregrineStoop" in ua and "authorized" in ua.lower()


def test_rate_limiter_math():
    assert RateLimiter(2).min_interval == 0.5
    assert RateLimiter(0).min_interval == 0.0
    RateLimiter(0).wait()  # no-op, must not raise
