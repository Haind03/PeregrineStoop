# Safety model

1. Every outbound request passes `ScopeChecker` (anchored suffix / IP / CIDR,
   exclude rules). Out-of-scope hosts are never contacted.
2. Append-only JSONL audit log records every request attempt.
3. Rate limit, timeout, declared User-Agent, body-size cap.
4. Safe methods only (GET/HEAD/OPTIONS) unless `--allow-unsafe`.

Authorized testing only.
