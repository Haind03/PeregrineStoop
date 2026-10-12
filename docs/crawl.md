# Crawl

`stoop crawl` performs a bounded, same-host, scope-gated breadth-first walk,
limited by depth, page count and the time budget, GET only. It seeds from
`robots.txt`/`sitemap.xml` and emits a snapshot that chains into `stoop diff`.
Dedup uses the state layer's URL normalization.
