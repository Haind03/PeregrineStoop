# Contributing

Thanks for your interest in PeregrineStoop.

## Development

```bash
pip install -e '.[test]'
pytest -q
```

All HTTP in the test suite is mocked — tests never make real network calls.

## Guidelines

- Python 3.11+, type hints, `from __future__ import annotations`.
- Keep the dependency surface minimal (stdlib + `requests`); justify any new
  runtime dependency in the README.
- Signatures and the CVE map are data-driven (`peregrinestoop/data/*.json`) —
  prefer extending the data files over hard-coding.
- Preserve the safety model: every outbound request must pass the scope gate
  and be audited; active probes stay non-destructive (GET/OPTIONS only).
- Add tests for new behavior and keep `pytest` green.
