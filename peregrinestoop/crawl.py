"""Bounded, polite link discovery to seed the rest of the pipeline.

This is friction reduction, not a scanner: a breadth-first walk that only
follows same-host links already present in pages it fetched, strictly bounded
by depth, page count and the time budget, rate-limited and scope-gated, GET
only. It also reads ``robots.txt`` and ``sitemap.xml`` — in authorized recon
those files *reveal* interesting paths, so their entries are added to the
frontier (bounded by the same limits), never used to hammer the target.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .common import ScopeViolation, StoopHTTP, log
from .diff import Snapshot, snapshot_from_items
from .state import BudgetTimer, StateStore, normalize_url

__all__ = ["crawl_site", "parse_robots", "parse_sitemap", "CrawlResult"]

_LINK = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#>]+)["']""", re.I)
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def _same_host(url: str, host: str) -> bool:
    return (urlsplit(url).hostname or "").lower() == host.lower()


def extract_links(base_url: str, body: bytes) -> set[str]:
    """Absolute, same-host links found in a page body (for the frontier)."""
    text = body.decode("latin-1", "replace")
    host = urlsplit(base_url).hostname or ""
    out: set[str] = set()
    for m in _LINK.finditer(text):
        raw = m.group(1).strip()
        if not raw or raw.startswith(("data:", "mailto:", "javascript:", "tel:")):
            continue
        absu = urljoin(base_url, raw)
        if absu.startswith(("http://", "https://")) and _same_host(absu, host):
            out.add(absu.split("#")[0])
    return out


def parse_robots(text: str, base_url: str) -> tuple[set[str], set[str]]:
    """Return (candidate URLs from Allow/Disallow, sitemap URLs)."""
    paths: set[str] = set()
    sitemaps: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue
        if key in ("disallow", "allow"):
            # robots paths may contain wildcards; keep the static prefix
            clean = val.split("*")[0].split("$")[0]
            if clean and clean != "/":
                paths.add(urljoin(base_url, clean))
        elif key == "sitemap":
            sitemaps.add(val)
    return paths, sitemaps


def parse_sitemap(xml: str, base_url: str) -> set[str]:
    """Extract <loc> URLs from a sitemap (or sitemap index)."""
    return {urljoin(base_url, m.group(1).strip())
            for m in _SITEMAP_LOC.finditer(xml)}


@dataclass
class CrawlResult:
    target: str = ""
    pages: dict[str, bytes] = field(default_factory=dict)   # url -> body
    visited: list[str] = field(default_factory=list)
    discovered: set[str] = field(default_factory=set)       # all links seen
    seeded_from: list[str] = field(default_factory=list)    # robots/sitemap
    stopped_reason: str = ""

    def snapshot(self) -> Snapshot:
        return snapshot_from_items(self.target, self.pages)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "visited": self.visited,
            "pages": len(self.pages),
            "discovered": sorted(self.discovered),
            "seeded_from": self.seeded_from,
            "stopped_reason": self.stopped_reason,
        }


def _fetch(http: StoopHTTP, url: str) -> bytes | None:
    try:
        resp = http.get(url)
        return resp.content or b""
    except ScopeViolation:
        raise
    except Exception as exc:  # noqa: BLE001
        log("-", f"crawl skip {url}: {exc}")
        return None


def crawl_site(
    http: StoopHTTP,
    seeds: list[str],
    *,
    max_pages: int = 25,
    max_depth: int = 1,
    timer: BudgetTimer | None = None,
    state: StateStore | None = None,
    seed_robots: bool = True,
) -> CrawlResult:
    """Breadth-first, bounded, scope-gated crawl starting from ``seeds``."""
    if not seeds:
        return CrawlResult()
    host = urlsplit(seeds[0]).hostname or ""
    res = CrawlResult(target=host)
    frontier: deque[tuple[str, int]] = deque((s, 0) for s in seeds)
    seen_norm: set[str] = set()

    # seed from robots.txt / sitemap.xml (bounded by the same limits)
    if seed_robots:
        base = f"{urlsplit(seeds[0]).scheme}://{host}"
        robots = _fetch(http, base + "/robots.txt")
        if robots:
            paths, sitemaps = parse_robots(robots.decode("latin-1", "replace"), base)
            for u in sorted(paths):
                frontier.append((u, 0))
                res.seeded_from.append(u)
            for sm in sorted(sitemaps):
                body = _fetch(http, sm)
                if body:
                    for loc in sorted(parse_sitemap(body.decode("latin-1", "replace"), base)):
                        if _same_host(loc, host):
                            frontier.append((loc, 0))
                            res.seeded_from.append(loc)

    while frontier:
        if len(res.pages) >= max_pages:
            res.stopped_reason = f"max-pages ({max_pages}) reached"
            break
        if timer is not None and timer.expired:
            res.stopped_reason = "time budget exceeded"
            break
        url, depth = frontier.popleft()
        norm = normalize_url(url)
        if norm in seen_norm or not _same_host(url, host):
            continue
        seen_norm.add(norm)
        if state is not None and state.seen("GET", url):
            continue
        body = _fetch(http, url)
        if state is not None:
            state.mark_tested("GET", url)
        if body is None:
            continue
        res.pages[url] = body
        res.visited.append(url)
        links = extract_links(url, body)
        res.discovered |= links
        if depth < max_depth:
            for link in sorted(links):
                if normalize_url(link) not in seen_norm:
                    frontier.append((link, depth + 1))

    if not res.stopped_reason:
        res.stopped_reason = "frontier exhausted"
    log("*", f"crawl {host}: {len(res.pages)} pages, "
             f"{len(res.discovered)} links ({res.stopped_reason})")
    return res
