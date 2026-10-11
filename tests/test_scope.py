"""ScopeChecker + StoopHTTP scope-gate tests. No real network."""
from __future__ import annotations

import pytest

from peregrinestoop.common import ScopeChecker, ScopeViolation, StoopHTTP


def test_wildcard_anchored_suffix():
    sc = ScopeChecker.from_patterns(["*.target.com"])
    assert sc.is_in_scope("a.target.com")
    assert sc.is_in_scope("b.a.target.com")
    assert sc.is_in_scope("target.com")           # bare apex allowed by *.
    assert not sc.is_in_scope("evil-target.com")  # the anchor: must be .target.com
    assert not sc.is_in_scope("target.com.evil.com")


def test_exact_host_only():
    sc = ScopeChecker.from_patterns(["target.com"])
    assert sc.is_in_scope("target.com")
    assert not sc.is_in_scope("a.target.com")
    assert not sc.is_in_scope("eviltarget.com")


def test_exclude_wins():
    sc = ScopeChecker.from_patterns(["*.target.com", "!secret.target.com"])
    assert sc.is_in_scope("app.target.com")
    assert not sc.is_in_scope("secret.target.com")


def test_ip_and_cidr():
    sc = ScopeChecker.from_patterns(["10.0.0.0/8", "192.168.1.5"])
    assert sc.is_in_scope("10.1.2.3")
    assert sc.is_in_scope("192.168.1.5")
    assert not sc.is_in_scope("192.168.1.6")
    assert not sc.is_in_scope("11.0.0.1")


def test_comment_and_blank_ignored():
    sc = ScopeChecker.from_patterns(["# a comment", "", "   ", "*.target.com"])
    assert sc.include == ["*.target.com"]


def test_empty_scope_is_falsey():
    assert not ScopeChecker()
    assert ScopeChecker.from_patterns(["x.com"])


def test_check_url_raises_out_of_scope():
    sc = ScopeChecker.from_patterns(["*.target.com"])
    assert sc.check_url("https://a.target.com/path") == "a.target.com"
    with pytest.raises(ScopeViolation):
        sc.check_url("https://evil.com/")


class _FakeSession:
    """Stand-in requests.Session that records calls instead of sending."""

    def __init__(self):
        self.calls = []
        self.headers = {}

    def request(self, method, url, **kw):
        self.calls.append((method, url))
        raise AssertionError("network call should not happen in these tests")


def test_http_blocks_out_of_scope_before_send():
    sc = ScopeChecker.from_patterns(["*.target.com"])
    fake = _FakeSession()
    http = StoopHTTP(sc, session=fake, rate=0)
    with pytest.raises(ScopeViolation):
        http.get("https://evil.com/")
    assert fake.calls == []  # nothing was sent


def test_http_blocks_unsafe_method():
    sc = ScopeChecker.from_patterns(["*.target.com"])
    fake = _FakeSession()
    http = StoopHTTP(sc, session=fake, rate=0, allow_unsafe=False)
    with pytest.raises(PermissionError):
        http.request("DELETE", "https://a.target.com/x")
    assert fake.calls == []
