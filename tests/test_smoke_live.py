"""Live smoke harness: run the real HTTP stack against a local test server.

Unlike the mocked/`responses` suites, this starts an actual HTTP server on
localhost and drives StoopHTTP / deep fingerprint / crawl / probes against a
real socket — validating the request path end to end. No external network.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from peregrinestoop.common import ScopeChecker, StoopHTTP
from peregrinestoop.crawl import crawl_site
from peregrinestoop.fingerprint import fingerprint_host_deep
from peregrinestoop.probes import probe_methods

_HOME = (b'<html><body>'
         b'<a href="/admin/panel">admin</a>'
         b'<script>fetch("/api/v1/users?id=1")</script>'
         b'</body></html>')


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            self._send(200, _HOME,
                       {"Server": "nginx", "Set-Cookie": "PHPSESSID=abc; path=/"})
        elif p == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /secret/\n")
        elif p == "/favicon.ico":
            self._send(200, b"TESTFAVICON", {"Content-Type": "image/x-icon"})
        elif p in ("/admin/panel", "/api/v1/users", "/secret/"):
            self._send(200, b"ok")
        else:
            self._send(404, b"nope")

    def do_HEAD(self):
        self._send(200, b"", {"Server": "nginx"})

    def do_OPTIONS(self):
        self._send(204, b"", {"Allow": "GET, HEAD, OPTIONS, PUT"})


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _http(scope_ip="127.0.0.1"):
    sess = requests.Session()
    sess.trust_env = False  # ignore env proxies for localhost
    return StoopHTTP(ScopeChecker.from_patterns([scope_ip]), rate=0, session=sess)


def test_live_get_real_socket(server):
    http = _http()
    r = http.get(server + "/")
    assert r.status_code == 200 and b"admin" in r.content


def test_live_deep_fingerprint(server):
    http = _http()
    fp = fingerprint_host_deep(http, server + "/")
    assert "nginx" in (fp.server or "")         # real server also adds its banner
    assert any("nginx" in t["name"] for t in fp.tech)
    assert fp.language == "php"                 # from PHPSESSID cookie
    assert "PUT" in fp.allowed_methods          # from real OPTIONS
    assert "dangerous-methods" in fp.vuln_classes
    assert fp.favicon is not None               # favicon hashed
    # the favicon bytes match the seeded hash -> ExampleStack tech
    assert any(t["name"] == "ExampleStack" for t in fp.tech)


def test_live_crawl_discovers_js_and_links(server):
    http = _http()
    res = crawl_site(http, [server + "/"], max_pages=10, max_depth=1,
                     seed_robots=True)
    disc = " ".join(sorted(res.discovered))
    assert "/admin/panel" in disc               # HTML link
    assert "/api/v1/users" in disc              # passive JS endpoint
    # robots.txt seeded /secret/ and it was visited
    assert any("/secret/" in u for u in res.seeded_from)


def test_live_probe_methods(server):
    http = _http()
    r = probe_methods(http, server + "/")
    assert r is not None and "PUT" in r.evidence
