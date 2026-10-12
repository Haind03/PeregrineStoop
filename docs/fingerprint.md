# Fingerprinting

Infers server, framework/language, CDN and WAF from headers, cookies, body and
meta tags, plus a security-header analysis. Signatures live in
`peregrinestoop/data/signatures.json`; CVE candidates in `cve_map.json`.

Version guesses are flagged low-confidence; CVEs are candidates to verify.
`stoop run` performs a deep fingerprint (home + 404 + OPTIONS).

## Favicon fingerprinting

`stoop run` fetches `/favicon.ico`, computes a sha256 hash, and maps known
hashes to a tech stack via `peregrinestoop/data/favicon_hashes.json`. The hash
is always recorded in the fingerprint notes so you can also look it up in
external databases (Shodan / FavFreak). Operators extend the data file.

## Version-aware CVE narrowing

When a concrete version is parsed (e.g. `Server: Apache/2.4.49`), CVE candidates
carrying an `affected` version spec in `cve_map.json` are filtered: only CVEs
whose range the detected version satisfies are listed (and marked medium
confidence with a `version_match` note). If the version is unknown, the
candidate is kept with an "affects X; version unknown" note. Entries without an
`affected` spec are always listed as candidates.
