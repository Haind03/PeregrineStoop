"""Cross-session state & dedup backed by SQLite.

Tracks which endpoints/params were already tested, stored fingerprints and
findings, and enforces a per-target time budget ("5-minute rule"). URL
normalization drops param *values* but keeps keys (sorted) so that re-visiting
the same endpoint with different data is recognized as already seen.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit, urlunsplit

__all__ = ["StateStore", "normalize_url", "BudgetTimer"]


def normalize_url(url: str) -> str:
    """Canonicalize a URL for dedup.

    Drops the fragment and all query *values*, keeps the sorted set of query
    *keys*, lowercases scheme/host, and strips a trailing slash from the path.
    ``?id=1&x=a`` and ``?x=b&id=2`` on the same path collapse to one key.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if parts.port:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    keys = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(keys)
    return urlunsplit((scheme, host, path, query, ""))


@dataclass
class BudgetTimer:
    """Warns once a target exceeds its time budget (default 300s = 5 min)."""

    budget_seconds: float = 300.0
    start: float = 0.0

    def __post_init__(self) -> None:
        if not self.start:
            self.start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start

    @property
    def remaining(self) -> float:
        return self.budget_seconds - self.elapsed

    @property
    def expired(self) -> bool:
        return self.elapsed >= self.budget_seconds


class StateStore:
    """SQLite-backed dedup + finding store, safe to reuse across sessions."""

    def __init__(self, path: str = ".stoop_state.sqlite") -> None:
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS tested (
                norm       TEXT NOT NULL,
                method     TEXT NOT NULL,
                param      TEXT NOT NULL DEFAULT '',
                raw_url    TEXT,
                first_seen REAL,
                last_seen  REAL,
                PRIMARY KEY (norm, method, param)
            );
            CREATE TABLE IF NOT EXISTS fingerprints (
                host    TEXT PRIMARY KEY,
                data    TEXT,
                ts      REAL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                target   TEXT,
                kind     TEXT,
                detail   TEXT,
                severity TEXT,
                ts       REAL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                target     TEXT,
                started    REAL,
                updated    REAL
            );
            """
        )
        self.conn.commit()

    # -- dedup ------------------------------------------------------------- #

    def seen(self, method: str, url: str, param: str = "") -> bool:
        norm = normalize_url(url)
        cur = self.conn.execute(
            "SELECT 1 FROM tested WHERE norm=? AND method=? AND param=?",
            (norm, method.upper(), param),
        )
        return cur.fetchone() is not None

    def mark_tested(self, method: str, url: str, param: str = "") -> None:
        norm = normalize_url(url)
        now = time.time()
        self.conn.execute(
            """
            INSERT INTO tested (norm, method, param, raw_url, first_seen, last_seen)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(norm, method, param)
            DO UPDATE SET last_seen=excluded.last_seen
            """,
            (norm, method.upper(), param, url, now, now),
        )
        self.conn.commit()

    # -- fingerprints ------------------------------------------------------ #

    def save_fingerprint(self, host: str, data: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO fingerprints (host, data, ts) VALUES (?,?,?)",
            (host, json.dumps(data, ensure_ascii=False), time.time()),
        )
        self.conn.commit()

    def get_fingerprint(self, host: str) -> dict | None:
        row = self.conn.execute(
            "SELECT data FROM fingerprints WHERE host=?", (host,)
        ).fetchone()
        return json.loads(row["data"]) if row else None

    # -- findings ---------------------------------------------------------- #

    def record_finding(
        self, target: str, kind: str, detail: str, severity: str = "info"
    ) -> None:
        self.conn.execute(
            "INSERT INTO findings (target, kind, detail, severity, ts) "
            "VALUES (?,?,?,?,?)",
            (target, kind, detail, severity, time.time()),
        )
        self.conn.commit()

    def findings(self, target: str | None = None) -> list[dict]:
        if target:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE target=? ORDER BY ts", (target,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY ts"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- resume ------------------------------------------------------------ #

    def touch_session(self, session_id: str, target: str) -> None:
        now = time.time()
        self.conn.execute(
            """
            INSERT INTO sessions (session_id, target, started, updated)
            VALUES (?,?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET updated=excluded.updated
            """,
            (session_id, target, now, now),
        )
        self.conn.commit()

    def resume(self) -> dict | None:
        """Return the most recently updated session, or None."""
        row = self.conn.execute(
            "SELECT * FROM sessions ORDER BY updated DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self.conn.close()
