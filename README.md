# PeregrineStoop

> A peregrine's stoop is the fastest hunting move in nature — PeregrineStoop brings that to blackbox recon.

**PeregrineStoop** is an authorized blackbox-pentest accelerator. It does **not**
add another raw scanner; it *reduces friction between recon steps* so you spend
time on reasoning instead of plumbing. Four small CLI modules share one state
layer, and **every HTTP request passes through a scope gate + append-only audit
log**.

Author / brand: **HaiND from the Post and Telecommunication Institute of Technology**
Repo: https://github.com/Haind03/PeregrineStoop · CLI: `stoop` · Package: `peregrinestoop`

---

## ⚠️ Authorization & Safety

PeregrineStoop is built for **authorized testing only** (HackerOne, Bugcrowd,
Intigriti, Immunefi, or a signed engagement). It refuses to touch any host that
is not explicitly in scope.

Non-negotiable guardrails:

1. **Scope gate.** Every outbound request is checked by `ScopeChecker`.
   `*.target.com` matches `a.target.com` and `target.com`, **anchored on the
   dot** so `evil-target.com` does *not* match. Out-of-scope → the request is
   never sent (raises `ScopeViolation`).
2. **Append-only audit log** (JSONL) for every request attempt: `url`, `method`,
   `scope_check`, `status`, `timestamp`, `session_id` — including blocked ones.
3. **Rate limit** (default 3 req/s), **timeout**, **body-size cap**, and a
   **User-Agent that declares authorized testing** (`contact=` included).
4. **Safe methods by default.** Only `GET`/`HEAD`/`OPTIONS`. `PUT`/`POST`/
   `DELETE`/`PATCH` require `--allow-unsafe` and print a warning.

There are **no** mass-targeting, DoS, or detection-evasion features. Confirm a
host is in your authorized scope before pointing PeregrineStoop at it.

---

## Install

```bash
pip install -e .          # editable; installs the `stoop` entrypoint
# dependencies: Python 3.11+, requests (stdlib otherwise)
```

`requests` is the only non-stdlib **runtime** dependency (robust HTTP session:
TLS verification, streaming, header handling). The test suite additionally uses
`responses` (dev-only; `pip install -e '.[test]'`) to drive integration tests
through the real HTTP adapter without network — it is never imported by the
package itself.

CVE routing is data-driven: candidates live in
[`peregrinestoop/data/cve_map.json`](peregrinestoop/data/cve_map.json) and can
be extended without touching code. Every entry is a *candidate to verify*.

---

## Modules

| File | Role |
|------|------|
| `common.py` | `ScopeChecker`, `StoopHTTP` (scope gate + audit + rate limit + timeout + UA + body cap), colored stderr logging. |
| `state.py` | SQLite state & dedup across sessions; URL normalization; 5-minute budget timer; findings store. |
| `fingerprint.py` | Tech/WAF fingerprint from headers/cookies/body/meta + **security-header analysis** → vuln classes + CVE *candidates* (version guesses flagged low-confidence). |
| `diff.py` | Snapshot a surface (content hash + endpoints + params), diff vs baseline, rank by freshness + sensitivity. |
| `probes.py` | **Safe active probes (GET/OPTIONS only, non-destructive)**: context-aware reflected-input, open-redirect, CORS reflection, method enumeration. Each reports a *candidate*, never a confirmation. |
| `report.py` | Render stored fingerprint + findings into a structured **Markdown recon report** for triage/disclosure. |
| `cli.py` | `stoop` orchestrator: scope gate → deep fingerprint → rank → dedup filter → safe probes → priority table → report. |

Deep fingerprint (`stoop run`) fetches the home page **plus a 404 error page and
an OPTIONS request** — error pages often reveal a WAF the home page hides, and
`Allow` enumerates advertised methods (flagging TRACE/PUT/DELETE).

---

## Usage

Scope is mandatory. Supply it inline or from a file.

```bash
# scope file: one pattern per line; '!' = exclude, '#' = comment
cat scope.txt
# *.target.com
# !admin.target.com
# 10.0.0.0/8
```

### Fingerprint

```bash
stoop fingerprint https://app.target.com --scope "*.target.com" --json fp.json
```

### Diff watcher

```bash
# first run: snapshot
stoop diff --url-file urls.txt --scope-file scope.txt --snapshot base.json
# later: diff against the baseline
stoop diff --url-file urls.txt --scope-file scope.txt --baseline base.json --json diff.json
```

### Full pipeline (time-budgeted)

```bash
stoop run https://app.target.com --scope "*.target.com" \
  --budget 300 --rate 3 --json run.json
```

### Safe active probes

```bash
# GET/OPTIONS only, non-destructive, scope-gated. Reports candidates to verify.
stoop probe https://app.target.com/login --scope "*.target.com" --json probe.json
# disable individual checks: --no-reflection --no-redirect --no-cors --no-methods
```

### Markdown report

```bash
# aggregate stored fingerprint + findings for a host into a triage report
stoop report https://app.target.com --out report.md
```

### Resume last session

```bash
stoop resume --json -
```

### Common flags

`--scope PATTERN` (repeatable) · `--scope-file FILE` · `--budget SECONDS` ·
`--rate N` · `--timeout SECONDS` · `--insecure` (lab TLS) ·
`--allow-unsafe` · `--audit-log FILE` · `--state-db FILE` · `--json FILE`

Output convention: **stdout = machine-readable JSON**, **stderr = human log and
the priority table** (colored `[+] [-] [!] [*]`).

---

## Detection coverage

**Stacks:** PHP, Java (Tomcat/Jetty/JBoss/WebLogic/WebSphere/GlassFish), ASP.NET
(+Core/Kestrel), Node (Express/Next/Nuxt), Python (Django/Flask/Gunicorn/Uvicorn/
Daphne), Ruby (Rails/Rack/Passenger), ColdFusion, Symfony/Yii/CodeIgniter/Laravel,
Spring Boot, Drupal/Joomla/Magento/WordPress, Angular/React/Vue, Jenkins/GitLab/
Atlassian/Grafana/phpMyAdmin.

**WAF/CDN:** Cloudflare, Akamai, Imperva Incapsula, F5 BIG-IP ASM, AWS CloudFront/
WAF, Sucuri, Fastly, ModSecurity, Wordfence, Barracuda, FortiWeb, Citrix NetScaler,
Azure Front Door, Reblaze, DenyAll, Edgecast.

**Vuln classes routed:** injection (sqli/nosqli/ssti/spel/ognl/csti), file issues
(lfi/path-traversal/upload), deserialization, SSRF, XXE, proto-pollution,
IDOR/mass-assignment, viewstate/padding-oracle, debug/actuator leaks,
dangerous-methods/XST, and security-header gaps (missing HSTS/CSP, clickjacking,
CORS-misconfig, mime-sniffing, version-disclosure).

**Active-probe candidates (safe, GET/OPTIONS):** context-aware reflected-input —
a **stdlib `html.parser` DOM pass** (no extra dependency) classifies the
reflection context (HTML text / attribute / `<script>` / comment) the way a
browser tokenizes it, so a quote/bracket breakout shows up as a context change;
combined with which XSS metacharacters survive unencoded. Plus open-redirect,
CORS reflection (with/without credentials), and dangerous HTTP methods. All
non-destructive and reported as *candidates to verify*.

**CVSS scaffolding:** `stoop report` prints a *suggested* CVSS 3.1 starting
vector per finding kind (reflected-input, open-redirect, CORS, dangerous
methods), explicitly labelled a template to re-judge — it never reports an
unverified score.

**CVE candidates** (verify-only, version-gated): CVE-2021-41773 (Apache),
CVE-2020-1938 (Ghostcat), CVE-2022-22965 (Spring4Shell), CVE-2022-26134
(Confluence), CVE-2018-7600 (Drupalgeddon2), CVE-2020-14882 (WebLogic), Jenkins
script console, Werkzeug debug PIN, and others. Each is a *candidate to verify*,
never an assertion.

## Tests

```bash
pip install -e '.[test]'   # pytest + responses (dev-only)
pytest -q
```

Covers: scope matching (`*.target.com` vs `evil-target.com`, exclude, IP/CIDR),
the HTTP gate refusing out-of-scope and unsafe methods *before sending*,
**streaming body-size cap + audit on success/error**, URL dedup normalization,
fingerprint inference across every stack/WAF/security-header case above, deep
fingerprint (404 WAF merge + OPTIONS methods), the **safe active probes**
(context-aware reflection/open-redirect/CORS/methods), the data-driven CVE map,
Markdown report rendering (incl. CVSS templates), snapshot diffing, and **full
CLI pipelines** (`fingerprint`/`diff`/`run`/`probe`/`report`/`resume`)
end-to-end. A separate **`responses`-backed integration suite** drives the real
requests/urllib3 stack — genuine gzip decoding, body-cap on decoded bytes,
redirect-read-not-followed, scope gate before the adapter. **No test makes a
real network call**; fakes and `responses` intercept everything.
