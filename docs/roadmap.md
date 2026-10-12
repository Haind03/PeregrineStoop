# Roadmap

Status: v0.1.0 — 8 CLI subcommands, 117 passing tests (1 skipped: brotli),
stdlib + `requests` only.

All planned work stays inside the project's constraints: authorized testing
only, friction reduction (not a raw scanner), stdlib + `requests` (new runtime
dependencies must be justified in the README), and the safety envelope (every
request scope-gated + audited, active probes non-destructive).

## v0.2 — correctness & validation (highest priority)

The biggest honest gap today is that nothing has been exercised against a live
target; all end-to-end coverage is mocked or `responses`-backed.

- **Live smoke harness in CI:** stand up a local test server (stdlib
  `http.server` or a tiny fixture app) and run `fingerprint` / `crawl` / `probe`
  / `run` against a real socket, so the request path is validated beyond mocks.
- **Transfer-encoding coverage:** add integration tests for `br` (brotli) and
  chunked responses; today only gzip/deflate/identity are covered and the brotli
  test is skipped when the library is absent.
- **Rate-limiter timing test:** currently only the interval math is asserted,
  not the actual pacing behaviour.

## v0.3 — detection depth (data-driven)

- Expand `signatures.json`: more frameworks (Spring MVC, Rails/Hotwire, Laravel
  Livewire) and WAF/CDN entries, all as data-file additions.
- **Favicon fingerprinting:** hash `/favicon.ico` and map known hashes to a tech
  stack via a data file.
- **Passive JS endpoint extraction:** parse bundled JavaScript for API routes
  and parameters and feed them into the ranked surface.
- **Version→CVE narrowing:** when a concrete version is parsed, filter CVE
  candidates by affected version ranges instead of listing all.

## v0.4 — probes (fewer false positives, same safety envelope)

- Reflection: distinguish single- vs double-quote attribute contexts, detect
  per-sink encoding, and optionally confirm reflection stability with one extra
  GET.
- Open-redirect: recognise `meta refresh` and JS `location` sinks (parse only,
  never auto-follow a cross-host redirect).
- CORS: test preflight (`OPTIONS`), the `null` origin, and sibling-subdomain
  trust.
- All probes remain GET/OPTIONS and candidate-only.

## v0.5 — reporting & workflow

- HTML report: a surface-priority chart and severity breakdown (inline SVG,
  theme-aware).
- Export: SARIF and a stable JSON schema for pipeline ingestion.
- `stoop audit`: add filtering (per host / per session) and CSV export.
- Session bundles: write fingerprint, findings, report and an audit slice into
  one per-engagement folder.

## Known limitations (tracked, not yet addressed)

- No validation against live targets yet — coverage is mocked / `responses`.
- Probes are heuristic: the stdlib DOM parser is not a browser engine, so
  mutation-XSS and client-side template injection are out of scope.
- CVSS vectors are starting templates, never auto-scored.
- CVE candidates are illustrative, not an exhaustive or version-exact database.
