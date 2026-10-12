# Crawl

`stoop crawl` performs a bounded, same-host, scope-gated breadth-first walk,
limited by depth, page count and the time budget, GET only. It seeds from
`robots.txt`/`sitemap.xml` and emits a snapshot that chains into `stoop diff`.
Dedup uses the state layer's URL normalization.

## Passive JS endpoint extraction

While crawling, bodies are also scanned for API-looking endpoints in JS/XHR
call sites (`fetch`, `axios`, `.get/.post`, `xhr.open`) and path literals
(`/api/...`, `/v1/...`, `/graphql`, `/internal/...`). This is passive — nothing
is executed — and only same-host URLs are kept. Discovered endpoints flow into
the snapshot and the ranked surface.
