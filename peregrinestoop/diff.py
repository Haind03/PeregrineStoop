"""Crawl diff watcher: snapshot a surface, then report what changed.

A *snapshot* records, per URL, a content hash plus the set of endpoints and
query/JS parameters discovered. Comparing two snapshots emits new endpoints,
new params and changed JS, ranked by "freshness + sensitivity": paths
containing admin/internal/debug/api/v* are promoted.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlsplit

from .common import StoopHTTP, log

__all__ = ["Snapshot", "snapshot_from_items", "diff_snapshots", "DiffResult"]

_SENSITIVE = re.compile(
    r"(admin|internal|debug|console|api|graphql|actuator|/v\d+/|secret|token|"
    r"backup|config|\.git|swagger|openapi|upload)",
    re.IGNORECASE,
)

# crude but dependency-free link/endpoint/param extraction from HTML/JS text
_HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#>]+)["']""", re.I)
_JS_PATH = re.compile(r"""["'](/[A-Za-z0-9._~\-/]{2,})["']""")
_JS_FETCH = re.compile(r"""(?:fetch|axios\.\w+|\.(?:get|post|put))\(\s*["'`]([^"'`]+)["'`]""", re.I)
_PARAM = re.compile(r"""[?&]([A-Za-z0-9_\-\[\]]+)=""")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def sensitivity(path: str) -> int:
    """Return a small integer score for how 'interesting' a path looks."""
    score = 0
    for m in _SENSITIVE.finditer(path):
        score += 2
    if re.search(r"/v\d+/", path):
        score += 1
    return score


def extract_surface(url: str, body: bytes) -> tuple[set[str], set[str]]:
    """Return (endpoints, params) found in a page body."""
    text = body.decode("latin-1", "replace")
    endpoints: set[str] = set()
    params: set[str] = set()

    for rx in (_HREF, _JS_PATH, _JS_FETCH):
        for m in rx.finditer(text):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("data:", "mailto:", "javascript:")):
                continue
            absu = urljoin(url, raw)
            p = urlsplit(absu)
            if p.hostname and p.hostname == urlsplit(url).hostname:
                endpoints.add(p.path or "/")
            for k, _ in parse_qsl(p.query):
                params.add(k)
            for pm in _PARAM.finditer(raw):
                params.add(pm.group(1))
    return endpoints, params


@dataclass
class Snapshot:
    target: str = ""
    created: float = field(default_factory=time.time)
    pages: dict[str, dict] = field(default_factory=dict)  # url -> {hash, endpoints, params}

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "created": self.created,
            "pages": {
                u: {
                    "hash": v["hash"],
                    "endpoints": sorted(v["endpoints"]),
                    "params": sorted(v["params"]),
                }
                for u, v in self.pages.items()
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Snapshot":
        snap = cls(target=d.get("target", ""), created=d.get("created", 0.0))
        for u, v in d.get("pages", {}).items():
            snap.pages[u] = {
                "hash": v["hash"],
                "endpoints": set(v.get("endpoints", [])),
                "params": set(v.get("params", [])),
            }
        return snap

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "Snapshot":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    # aggregate views across all pages
    def all_endpoints(self) -> set[str]:
        out: set[str] = set()
        for v in self.pages.values():
            out |= v["endpoints"]
        return out

    def all_params(self) -> set[str]:
        out: set[str] = set()
        for v in self.pages.values():
            out |= v["params"]
        return out


def snapshot_from_items(target: str, items: dict[str, bytes]) -> Snapshot:
    """Build a snapshot from a {url: body-bytes} mapping (no network)."""
    snap = Snapshot(target=target)
    for url, body in items.items():
        endpoints, params = extract_surface(url, body)
        snap.pages[url] = {
            "hash": _sha(body),
            "endpoints": endpoints,
            "params": params,
        }
    return snap


@dataclass
class DiffResult:
    new_endpoints: list[dict] = field(default_factory=list)   # {path, score}
    new_params: list[str] = field(default_factory=list)
    changed_js: list[dict] = field(default_factory=list)      # {url, old, new}
    new_pages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "new_endpoints": self.new_endpoints,
            "new_params": self.new_params,
            "changed_js": self.changed_js,
            "new_pages": self.new_pages,
        }

    @property
    def empty(self) -> bool:
        return not (self.new_endpoints or self.new_params
                    or self.changed_js or self.new_pages)


def diff_snapshots(old: Snapshot, new: Snapshot) -> DiffResult:
    """Report what appeared in ``new`` that was absent in ``old``."""
    res = DiffResult()

    new_eps = new.all_endpoints() - old.all_endpoints()
    res.new_endpoints = sorted(
        ({"path": p, "score": sensitivity(p)} for p in new_eps),
        key=lambda d: (-d["score"], d["path"]),
    )

    res.new_params = sorted(new.all_params() - old.all_params())

    for url, meta in new.pages.items():
        if url not in old.pages:
            res.new_pages.append(url)
        elif old.pages[url]["hash"] != meta["hash"]:
            res.changed_js.append(
                {"url": url, "old": old.pages[url]["hash"], "new": meta["hash"]}
            )

    return res


def crawl_light(http: StoopHTTP, urls: list[str]) -> dict[str, bytes]:
    """Fetch each URL once (GET) through the scope gate. No recursion."""
    items: dict[str, bytes] = {}
    for u in urls:
        try:
            resp = http.get(u)
            items[u] = resp.content or b""
            log("*", f"snapshot {u} ({len(items[u])} bytes, {resp.status_code})")
        except Exception as exc:  # noqa: BLE001
            log("-", f"skip {u}: {exc}")
    return items
