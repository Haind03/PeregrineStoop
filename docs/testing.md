# Testing

```bash
pip install -e '.[test]'
pytest -q
```

All HTTP is mocked — the suite makes no real network calls. A `responses`-backed
integration suite drives the real requests/urllib3 stack (gzip/deflate decoding,
body-cap, redirect-read-not-followed, scope gate before the adapter).

## Live smoke harness

`tests/test_smoke_live.py` starts a real HTTP server on localhost and drives
StoopHTTP / deep fingerprint / crawl / probes against an actual socket — so the
request path is validated beyond mocks (it already caught two real port-handling
bugs). Still no external network.
