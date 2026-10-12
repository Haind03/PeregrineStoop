# Fingerprinting

Infers server, framework/language, CDN and WAF from headers, cookies, body and
meta tags, plus a security-header analysis. Signatures live in
`peregrinestoop/data/signatures.json`; CVE candidates in `cve_map.json`.

Version guesses are flagged low-confidence; CVEs are candidates to verify.
`stoop run` performs a deep fingerprint (home + 404 + OPTIONS).
