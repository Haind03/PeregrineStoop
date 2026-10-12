# Reporting

`stoop report <target>` aggregates the stored fingerprint and findings into a
structured report.

- Markdown by default; `--html` (or a `.html` output path) renders a
  self-contained, theme-aware HTML page.
- Includes suggested CVSS 3.1 starting vectors per finding kind — templates to
  re-judge, never an auto-scored result.

## SARIF export

`stoop report <target> --sarif out.sarif` also writes findings as SARIF 2.1.0,
the format GitHub Code Scanning and many pipelines consume. Severity maps to the
SARIF level (high to error, medium to warning, low and info to note), one rule
per finding kind, and every result message is labelled a candidate to verify.
