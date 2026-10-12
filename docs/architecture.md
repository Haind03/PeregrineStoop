# Architecture

- `common.py` — ScopeChecker + StoopHTTP (scope gate, audit, rate limit, timeout).
- `state.py` — SQLite dedup/state across sessions.
- `fingerprint.py` — tech/WAF inference, data-driven signatures + CVE map.
- `crawl.py` / `diff.py` — bounded crawl and snapshot diffing.
- `probes.py` — safe active probes (GET/OPTIONS).
- `report.py` — Markdown/HTML reports.
- `cli.py` — the `stoop` orchestrator.
