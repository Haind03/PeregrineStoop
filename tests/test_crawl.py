"""Bounded crawler tests. All HTTP mocked, no network."""
from __future__ import annotations

import json

from peregrinestoop import cli
from peregrinestoop.common import ScopeChecker, StoopHTTP
from peregrinestoop.crawl import crawl_site, extract_links, parse_robots, parse_sitemap
from peregrinestoop.state import BudgetTimer, StateStore
from conftest import FakeSession, make_response

SCOPE = ScopeChecker.from_patterns(["*.target.com"])


def _http(handler):
    return StoopHTTP(SCOPE, rate=0, session=FakeSession(handler))


def test_extract_links_same_host_only():
    body = (b'<a href="/a">a</a>'
            b'<a href="https://a.target.com/b?x=1">b</a>'
            b'<a href="https://evil.com/c">c</a>'
            b'<a href="mailto:x@y.z">m</a>')
    links = extract_links("https://a.target.com/", body)
    assert "https://a.target.com/a" in links
    assert "https://a.target.com/b?x=1" in links
    assert not any("evil.com" in u for u in links)
    assert not any("mailto" in u for u in links)


def test_parse_robots_paths_and_sitemap():
    txt = ("User-agent: *\n"
           "Disallow: /admin/\n"
           "Disallow: /secret/*.bak\n"
           "Allow: /public\n"
           "Sitemap: https://a.target.com/sitemap.xml\n")
    paths, sitemaps = parse_robots(txt, "https://a.target.com/")
    assert "https://a.target.com/admin/" in paths
    assert "https://a.target.com/secret/" in paths      # wildcard trimmed
    assert "https://a.target.com/public" in paths
    assert "https://a.target.com/sitemap.xml" in sitemaps


def test_parse_sitemap_locs():
    xml = ("<urlset><url><loc>https://a.target.com/x</loc></url>"
           "<url><loc>https://a.target.com/y</loc></url></urlset>")
    locs = parse_sitemap(xml, "https://a.target.com/")
    assert locs == {"https://a.target.com/x", "https://a.target.com/y"}


def test_crawl_bfs_follows_same_host_and_dedups():
    # /b links /a?id=2 while / links /a?id=1 — same endpoint, different value,
    # so the crawler must fetch the /a endpoint only once.
    pages = {
        "/": b'<a href="/a?id=1">a</a><a href="/b">b</a><a href="https://evil.com/x">e</a>',
        "/a": b"leaf-a",
        "/b": b'<a href="/a?id=2">dup</a><a href="/c">c</a>',
        "/c": b"leaf-c",
    }

    def handler(m, u, kw):
        from urllib.parse import urlsplit
        path = urlsplit(u).path or "/"
        if path == "/robots.txt":
            return make_response(404, {}, b"")
        return make_response(200, {}, pages.get(path, b"not found"))

    res = crawl_site(_http(handler), ["https://a.target.com/"],
                     max_pages=50, max_depth=2, seed_robots=False)
    from urllib.parse import urlsplit
    visited_paths = [urlsplit(u).path for u in res.visited]
    assert visited_paths.count("/") == 1
    assert visited_paths.count("/b") == 1 and visited_paths.count("/c") == 1
    # off-host link never visited
    assert not any("evil.com" in u for u in res.visited)
    # /a?id=1 and /a?id=2 dedup (same endpoint+keys) -> fetched exactly once
    assert visited_paths.count("/a") == 1


def test_crawl_respects_max_pages():
    def handler(m, u, kw):
        from urllib.parse import urlsplit
        if (urlsplit(u).path or "/") == "/robots.txt":
            return make_response(404, {}, b"")
        return make_response(200, {}, b'<a href="/x">x</a><a href="/y">y</a>'
                                      b'<a href="/z">z</a>')
    res = crawl_site(_http(handler), ["https://a.target.com/"],
                     max_pages=2, max_depth=5, seed_robots=False)
    assert len(res.pages) == 2
    assert "max-pages" in res.stopped_reason


def test_crawl_seeds_from_robots(tmp_path):
    def handler(m, u, kw):
        from urllib.parse import urlsplit
        path = urlsplit(u).path or "/"
        if path == "/robots.txt":
            return make_response(200, {}, b"Disallow: /hidden-admin/\n")
        return make_response(200, {}, b"ok")
    res = crawl_site(_http(handler), ["https://a.target.com/"],
                     max_pages=10, max_depth=0, seed_robots=True)
    assert any("/hidden-admin/" in u for u in res.seeded_from)
    assert any("/hidden-admin/" in u for u in res.visited)


def test_crawl_budget_stop():
    timer = BudgetTimer(budget_seconds=0.0)   # already expired
    def handler(m, u, kw):
        return make_response(200, {}, b"x")
    res = crawl_site(_http(handler), ["https://a.target.com/"],
                     timer=timer, seed_robots=False)
    assert res.stopped_reason == "time budget exceeded"
    assert res.pages == {}


def test_cli_crawl_offline(monkeypatch, tmp_path):
    def handler(method, url, kw):
        from urllib.parse import urlsplit
        path = urlsplit(url).path or "/"
        if path == "/robots.txt":
            return make_response(404, {}, b"")
        return make_response(200, {}, b'<a href="/api/v1/users">u</a>')

    def fake_build(args, scope, sid):
        return StoopHTTP(scope, rate=0, session=FakeSession(handler))
    monkeypatch.setattr(cli, "_build_http", fake_build)

    snap = tmp_path / "snap.json"
    out = tmp_path / "crawl.json"
    rc = cli.main([
        "crawl", "https://a.target.com/", "--scope", "*.target.com",
        "--depth", "1", "--max-pages", "10",
        "--snapshot", str(snap),
        "--state-db", str(tmp_path / "s.sqlite"),
        "--audit-log", str(tmp_path / "a.jsonl"),
        "--json", str(out),
    ])
    assert rc == 0 and snap.exists()
    data = json.loads(out.read_text())
    assert data["target"] == "a.target.com"
    assert any("/api/v1/users" in u for u in data["discovered"])
