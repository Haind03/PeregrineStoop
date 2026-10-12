# Session bundle export

`stoop run --session-dir DIR` writes a self-contained engagement bundle into
`DIR` after the run:

- `run.json` — the full run payload.
- `fingerprint.json` — the stored fingerprint.
- `findings.json` — recorded findings.
- `report.md` / `report.html` — the triage report in both formats.
- `audit.jsonl` — a copy of the audit log for this run.

This keeps everything one engagement produced in a single folder, ready to
archive or attach to a report. It is offline — only local files are written.
