# Audit log analysis

Every request attempt — sent or blocked — is written to an append-only JSONL
audit log (`--audit-log`, default `stoop_audit.jsonl`). During an authorized
engagement this file is the record of exactly what traffic the toolkit
generated, which is useful for scoping evidence, debugging, and post-engagement
review.

`stoop audit` turns that raw log into a summary without touching the network:

```bash
stoop audit --audit-log stoop_audit.jsonl
stoop audit --audit-log stoop_audit.jsonl --json summary.json
```

It reports:

- **total / sent / blocked / unsafe-blocked / errors** — how many requests were
  actually sent (in-scope), refused by the scope gate (out-of-scope), refused as
  an unsafe method without `--allow-unsafe`, or raised a transport error.
- **hosts** — request count per host (sorted).
- **methods** — HTTP method distribution.
- **status distribution** — response status codes seen.
- **scope_checks** — raw scope-gate outcomes.
- **sessions** and the **time span** covered by the log.

A non-zero `blocked` count is a good sign: it means the scope gate stopped
out-of-scope requests before any packet left. Malformed log lines are skipped
rather than treated as fatal.
