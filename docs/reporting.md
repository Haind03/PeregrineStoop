# Reporting

`stoop report <target>` aggregates the stored fingerprint and findings into a
structured report.

- Markdown by default; `--html` (or a `.html` output path) renders a
  self-contained, theme-aware HTML page.
- Includes suggested CVSS 3.1 starting vectors per finding kind — templates to
  re-judge, never an auto-scored result.
