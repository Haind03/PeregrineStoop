# Testing

```bash
pip install -e '.[test]'
pytest -q
```

All HTTP is mocked — the suite makes no real network calls. A `responses`-backed
integration suite drives the real requests/urllib3 stack (gzip/deflate decoding,
body-cap, redirect-read-not-followed, scope gate before the adapter).
