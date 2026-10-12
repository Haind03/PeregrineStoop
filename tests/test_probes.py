"""Safe active-probe tests + deep fingerprint. All HTTP mocked."""
from __future__ import annotations

from peregrinestoop.common import ScopeChecker, StoopHTTP
from peregrinestoop.fingerprint import fingerprint_host_deep, parse_allow
from urllib.parse import parse_qs, urlsplit, unquote

from peregrinestoop.probes import (
    probe_cors,
    probe_methods,
    probe_open_redirect,
    probe_reflection,
    run_safe_probes,
)
from conftest import FakeSession, make_response


def _q(url, key="q"):
    """Decode a query param from a URL the way a vulnerable app would."""
    vals = parse_qs(urlsplit(url).query).get(key, [])
    return unquote(vals[0]) if vals else ""

SCOPE = ScopeChecker.from_patterns(["*.target.com"])


def _http(handler):
    return StoopHTTP(SCOPE, rate=0, session=FakeSession(handler))


# -- reflection ------------------------------------------------------------- #

def test_reflection_html_tag_injection_is_high():
    def handler(m, u, kw):
        raw = _q(u)  # app decodes and echoes verbatim into HTML text
        return make_response(200, {"Content-Type": "text/html"},
                             f"<p>{raw}</p>".encode())
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None and r.kind == "reflected-input"
    assert r.severity == "high"            # '<' and '>' survived in HTML context
    assert "context=html" in r.detail


def test_reflection_encoded_is_info():
    def handler(m, u, kw):
        raw = _q(u)
        safe = (raw.replace("<", "&lt;").replace(">", "&gt;")
                   .replace('"', "&quot;").replace("'", "&#39;"))
        return make_response(200, {"Content-Type": "text/html"},
                             f"<p>{safe}</p>".encode())
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None and r.severity == "info"   # reflected but encoded
    assert "survived=none" in r.detail


def test_reflection_attribute_context_medium():
    def handler(m, u, kw):
        raw = _q(u)
        # reflected inside an attribute value; only the quote matters
        no_angle = raw.replace("<", "").replace(">", "")
        return make_response(200, {"Content-Type": "text/html"},
                             f'<input value="{no_angle}">'.encode())
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None and r.severity == "medium"
    assert "context=attribute" in r.detail


def test_reflection_dom_script_context_is_high():
    def handler(m, u, kw):
        raw = _q(u)
        return make_response(200, {"Content-Type": "text/html"},
                             f'<html><body><script>var q="{raw}";</script>'
                             f'</body></html>'.encode())
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None and r.severity == "high"
    assert "context=js" in r.detail        # DOM parser knows it's inside <script>


def test_reflection_dom_comment_context():
    def handler(m, u, kw):
        raw = _q(u)
        return make_response(200, {"Content-Type": "text/html"},
                             f"<html><!-- {raw} --></html>".encode())
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None
    assert "context=comment" in r.detail   # correctly attributed to the comment


def test_reflection_none_when_not_echoed():
    handler = lambda m, u, kw: make_response(200, {}, b"static page")
    assert probe_reflection(_http(handler), "https://a.target.com/") is None


def test_reflection_non_html_downgraded():
    def handler(m, u, kw):
        raw = _q(u)
        return make_response(200, {"Content-Type": "application/json"},
                             f'{{"echo":"{raw}"}}'.encode())
    r = probe_reflection(_http(handler), "https://a.target.com/api")
    assert r is not None and r.severity == "low"   # not HTML -> downgraded


# -- open redirect ---------------------------------------------------------- #

def test_open_redirect_detected():
    def handler(m, u, kw):
        if "next=" in u or "url=" in u or "redirect=" in u:
            return make_response(302, {"Location": "https://stoop-oob.example/x"}, b"")
        return make_response(200, {}, b"")
    results = probe_open_redirect(_http(handler), "https://a.target.com/login")
    assert results
    assert all(r.kind == "open-redirect" for r in results)
    assert any("Location" in r.evidence for r in results)


def test_open_redirect_none_when_same_host():
    handler = lambda m, u, kw: make_response(
        302, {"Location": "https://a.target.com/home"}, b"")
    assert probe_open_redirect(_http(handler), "https://a.target.com/login") == []


# -- CORS ------------------------------------------------------------------- #

def test_cors_reflection_with_credentials_is_high():
    def handler(m, u, kw):
        origin = kw.get("headers", {}).get("Origin", "")
        return make_response(200, {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        }, b"")
    r = probe_cors(_http(handler), "https://a.target.com/api")
    assert r is not None and r.severity == "high"


def test_cors_no_reflection():
    handler = lambda m, u, kw: make_response(
        200, {"Access-Control-Allow-Origin": "https://trusted.target.com"}, b"")
    assert probe_cors(_http(handler), "https://a.target.com/api") is None


# -- methods ---------------------------------------------------------------- #

def test_methods_flags_put_delete():
    handler = lambda m, u, kw: make_response(
        200, {"Allow": "GET, POST, PUT, DELETE, OPTIONS"}, b"")
    r = probe_methods(_http(handler), "https://a.target.com/")
    assert r is not None and r.severity == "high"
    assert "PUT" in r.evidence and "DELETE" in r.evidence


def test_methods_none_when_safe():
    handler = lambda m, u, kw: make_response(200, {"Allow": "GET, HEAD, OPTIONS"}, b"")
    assert probe_methods(_http(handler), "https://a.target.com/") is None


def test_parse_allow_dedup_and_sort():
    assert parse_allow({"Allow": "get, GET, Post"}) == ["GET", "POST"]


# -- orchestration ---------------------------------------------------------- #

def test_run_safe_probes_collects_multiple():
    def handler(m, u, kw):
        if m == "OPTIONS":
            return make_response(200, {"Allow": "GET, TRACE"}, b"")
        if "q=" in u:
            tok = u.split("q=")[-1]
            return make_response(200, {"Content-Type": "text/html"},
                                 f"<i>{tok}</i>".encode())
        if any(f"{p}=" in u for p in ("url", "next", "redirect")):
            return make_response(302, {"Location": "https://stoop-oob.example/"}, b"")
        return make_response(200, {}, b"")
    results = run_safe_probes(_http(handler), "https://a.target.com/")
    kinds = {r.kind for r in results}
    assert "dangerous-methods" in kinds
    assert "reflected-input" in kinds
    assert "open-redirect" in kinds


# -- deep fingerprint ------------------------------------------------------- #

def test_deep_fingerprint_merges_404_waf_and_options():
    def handler(m, u, kw):
        if m == "OPTIONS":
            return make_response(200, {"Allow": "GET, POST, PUT, TRACE"}, b"")
        if "stoop-404-" in u:
            # WAF only reveals itself on the error page
            return make_response(403, {}, b"Generated by Wordfence")
        return make_response(200, {"Server": "nginx"}, b"<html>home</html>")
    fp = fingerprint_host_deep(_http(handler), "https://a.target.com/")
    assert fp.waf == "Wordfence"                 # picked up from 404 page
    assert "PUT" in fp.allowed_methods
    assert "dangerous-methods" in fp.vuln_classes
    assert "xst" in fp.vuln_classes              # TRACE advertised


def test_reflection_unstable_is_downgraded():
    state = {"n": 0}
    def handler(m, u, kw):
        state["n"] += 1
        if state["n"] == 1:                 # reflect only the first request
            return make_response(200, {"Content-Type": "text/html"},
                                 f"<p>{_q(u)}</p>".encode())
        return make_response(200, {"Content-Type": "text/html"}, b"<p>static</p>")
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None
    assert r.severity == "low"              # not reproduced -> downgraded
    assert "unconfirmed" in r.detail and "single-sample" in r.detail


def test_reflection_reports_single_quote():
    def handler(m, u, kw):
        raw = _q(u)
        v = raw.replace("<", "").replace(">", "").replace('"', "")  # keep only '
        return make_response(200, {"Content-Type": "text/html"},
                             f"<input value='{v}'>".encode())
    r = probe_reflection(_http(handler), "https://a.target.com/search")
    assert r is not None and r.severity == "medium"
    assert "single quote" in r.detail and "stable" in r.detail
