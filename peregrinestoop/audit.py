"""Audit-log analysis — summarize the append-only JSONL request trail.

During an authorized engagement the audit log is the record of exactly what was
sent where. This module turns that raw JSONL into a summary an operator can
review or attach to a report: totals, per-host breakdown, how many requests were
actually sent vs blocked by the scope gate, the HTTP status distribution, and
any unsafe-method attempts.

Pure / offline — it only reads a local file, never the network.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = ["load_audit", "summarize_audit", "AuditSummary",
           "filter_entries", "to_csv"]


def load_audit(path: str) -> list[dict]:
    """Load JSONL audit entries. Malformed lines are skipped, not fatal."""
    entries: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
    except FileNotFoundError:
        return []
    return entries


def _entry_host(e: dict) -> str:
    scope = str(e.get("scope_check", ""))
    if scope.startswith("in-scope:"):
        return scope.split(":", 1)[1]
    return urlsplit(str(e.get("url", ""))).hostname or ""


def filter_entries(entries: list[dict], *, host: str | None = None,
                   session: str | None = None) -> list[dict]:
    """Return the subset of entries matching the given host and/or session."""
    out = entries
    if host:
        h = host.lower()
        out = [e for e in out if _entry_host(e).lower() == h]
    if session:
        out = [e for e in out if str(e.get("session_id", "")) == session]
    return out


def to_csv(entries: list[dict]) -> str:
    """Render entries as CSV (one row per request attempt)."""
    import csv
    import io

    cols = ["iso", "session_id", "method", "url", "scope_check", "status", "note"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for e in entries:
        w.writerow({c: e.get(c, "") for c in cols})
    return buf.getvalue()


@dataclass
class AuditSummary:
    total: int = 0
    sent: int = 0
    blocked: int = 0
    unsafe_blocked: int = 0
    errors: int = 0
    hosts: dict[str, int] = field(default_factory=dict)
    methods: dict[str, int] = field(default_factory=dict)
    status_dist: dict[str, int] = field(default_factory=dict)
    scope_checks: dict[str, int] = field(default_factory=dict)
    sessions: set[str] = field(default_factory=set)
    first_ts: float | None = None
    last_ts: float | None = None

    def to_dict(self) -> dict:
        span = None
        if self.first_ts is not None and self.last_ts is not None:
            span = round(self.last_ts - self.first_ts, 2)
        return {
            "total": self.total,
            "sent": self.sent,
            "blocked": self.blocked,
            "unsafe_blocked": self.unsafe_blocked,
            "errors": self.errors,
            "sessions": len(self.sessions),
            "hosts": dict(sorted(self.hosts.items(), key=lambda kv: -kv[1])),
            "methods": dict(sorted(self.methods.items(), key=lambda kv: -kv[1])),
            "status_distribution": dict(sorted(self.status_dist.items())),
            "scope_checks": dict(sorted(self.scope_checks.items())),
            "time_span_seconds": span,
        }


def _bump(d: dict, key) -> None:
    d[key] = d.get(key, 0) + 1


def summarize_audit(entries: list[dict]) -> AuditSummary:
    """Aggregate a list of audit entries into an :class:`AuditSummary`."""
    s = AuditSummary()
    for e in entries:
        s.total += 1
        scope = str(e.get("scope_check", ""))
        _bump(s.scope_checks, scope or "unknown")

        if scope.startswith("in-scope"):
            s.sent += 1
        elif scope == "out-of-scope":
            s.blocked += 1
        elif scope == "blocked-unsafe":
            s.unsafe_blocked += 1

        note = str(e.get("note", ""))
        if note.startswith("error:"):
            s.errors += 1

        method = str(e.get("method", "")).upper()
        if method:
            _bump(s.methods, method)

        status = e.get("status")
        _bump(s.status_dist, str(status) if status is not None else "none")

        sid = e.get("session_id")
        if sid:
            s.sessions.add(str(sid))

        # host: prefer scope_check's "in-scope:<host>", else parse url
        host = ""
        if scope.startswith("in-scope:"):
            host = scope.split(":", 1)[1]
        else:
            host = urlsplit(str(e.get("url", ""))).hostname or ""
        if host:
            _bump(s.hosts, host)

        ts = e.get("ts")
        if isinstance(ts, (int, float)):
            s.first_ts = ts if s.first_ts is None else min(s.first_ts, ts)
            s.last_ts = ts if s.last_ts is None else max(s.last_ts, ts)
    return s


def format_text(summary: AuditSummary) -> str:
    """Human-readable summary for stderr/console."""
    d = summary.to_dict()
    lines = ["audit summary",
             f"  total={d['total']} sent={d['sent']} blocked(out-of-scope)="
             f"{d['blocked']} unsafe-blocked={d['unsafe_blocked']} "
             f"errors={d['errors']} sessions={d['sessions']}"]
    if d["time_span_seconds"] is not None:
        lines.append(f"  time span: {d['time_span_seconds']}s")
    if d["hosts"]:
        lines.append("  hosts:")
        for h, n in d["hosts"].items():
            lines.append(f"    {n:>5}  {h}")
    if d["methods"]:
        lines.append("  methods: " + ", ".join(f"{k}={v}" for k, v in d["methods"].items()))
    if d["status_distribution"]:
        lines.append("  status: " + ", ".join(f"{k}={v}"
                     for k, v in d["status_distribution"].items()))
    return "\n".join(lines)
