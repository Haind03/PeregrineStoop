"""Aggregate recon findings into a Markdown report for triage / disclosure.

Pulls the stored fingerprint and findings for a host out of the state DB and
renders a structured Markdown document. It is a *recon summary* to speed up
triage, not a vulnerability-confirmation report: every active-probe item and
CVE entry is labelled a candidate to verify.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import html
import time

from . import BRAND

__all__ = ["render_report", "render_html_report"]

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _sev_key(f: dict) -> int:
    return _SEV_ORDER.get((f.get("severity") or "info").lower(), 3)


# Suggested CVSS 3.1 *starting* vectors per finding kind. These are templates to
# adapt, NOT scores to report — the real metrics depend on the asset, the data
# exposed, and confirmation. Scope/Confidentiality in particular must be
# re-judged per target.
_CVSS_HINTS = {
    "reflected-input": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "reflected XSS baseline (user interaction, scope change into the page)"),
    "open-redirect": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
        "open redirect; raise if it enables token theft / OAuth chaining"),
    "cors-reflection": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "credentialed CORS reflection exposing authed data; drop C if no creds"),
    "dangerous-methods": (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "depends on whether the method is actually actionable (PUT/DELETE)"),
}


def cvss_hint(kind: str) -> tuple[str, str] | None:
    """Return a (vector, rationale) starting template for a finding kind."""
    return _CVSS_HINTS.get(kind)


def render_report(host: str, fingerprint: dict | None, findings: list[dict]) -> str:
    """Render a Markdown report. Pure function — no I/O, fully testable."""
    now = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    fp = fingerprint or {}
    lines: list[str] = []
    add = lines.append

    add(f"# PeregrineStoop recon report — {host}")
    add("")
    add(f"_{BRAND}_")
    add("")
    add(f"- Generated: {now}")
    add(f"- Target host: `{host}`")
    add(f"- Findings recorded: {len(findings)}")
    add("")
    add("> Authorized testing only. This is a recon triage summary; every "
        "active-probe item and CVE entry below is a **candidate to verify**, "
        "not a confirmed vulnerability.")
    add("")

    # -- Summary counts ---------------------------------------------------- #
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    add("## Summary")
    add("")
    if counts:
        parts = [f"{counts[s]} {s}" for s in ("high", "medium", "low", "info")
                 if s in counts]
        add(f"Findings by severity: {', '.join(parts)}.")
    else:
        add("No findings recorded yet.")
    add("")

    # -- Fingerprint ------------------------------------------------------- #
    add("## Technology fingerprint")
    add("")
    add(f"- **Server:** {fp.get('server') or 'unknown'}")
    add(f"- **Language:** {fp.get('language') or 'unknown'}")
    add(f"- **CDN:** {fp.get('cdn') or 'none detected'}")
    add(f"- **WAF:** {fp.get('waf') or 'none detected'}")
    if fp.get("allowed_methods"):
        add(f"- **Advertised methods:** {', '.join(fp['allowed_methods'])}")
    if fp.get("tech"):
        techs = ", ".join(f"{t['name']} ({t['confidence']})" for t in fp["tech"])
        add(f"- **Detected tech:** {techs}")
    if fp.get("vuln_classes"):
        add(f"- **Vuln classes to prioritize:** {', '.join(fp['vuln_classes'])}")
    add("")

    # -- Security headers -------------------------------------------------- #
    sh = fp.get("security_headers") or {}
    missing = [v for v in fp.get("vuln_classes", [])
               if v in ("missing-hsts", "missing-csp", "clickjacking",
                        "mime-sniffing", "cors-misconfig", "version-disclosure")]
    if sh or missing:
        add("### Security headers")
        add("")
        if sh:
            for k, v in sh.items():
                add(f"- present: `{k}: {v}`")
        if missing:
            add(f"- gaps: {', '.join(missing)}")
        add("")

    # -- CVE candidates ---------------------------------------------------- #
    cves = fp.get("cve_candidates") or []
    if cves:
        add("## CVE candidates (verify only)")
        add("")
        add("| CVE / lead | For | Confidence | Verify |")
        add("|---|---|---|---|")
        for c in cves:
            add(f"| {c.get('cve','?')} | {c.get('for','')} | "
                f"{c.get('confidence','low')} | {c.get('verify','')} |")
        add("")

    # -- Findings ---------------------------------------------------------- #
    add("## Findings")
    add("")
    if findings:
        add("| Severity | Kind | Detail |")
        add("|---|---|---|")
        for f in sorted(findings, key=_sev_key):
            detail = (f.get("detail") or "").replace("|", "\\|")
            add(f"| {f.get('severity','info')} | {f.get('kind','')} | {detail} |")
    else:
        add("_No findings recorded._")
    add("")

    # -- CVSS starting vectors --------------------------------------------- #
    kinds_present = []
    for f in findings:
        k = f.get("kind", "")
        if k not in kinds_present and cvss_hint(k):
            kinds_present.append(k)
    if kinds_present:
        add("## Suggested CVSS 3.1 starting vectors (verify before use)")
        add("")
        add("> Templates only. Re-judge every metric against the actual asset "
            "and confirmed impact; do **not** report an unverified score.")
        add("")
        add("| Kind | Starting vector | Rationale |")
        add("|---|---|---|")
        for k in kinds_present:
            vec, why = cvss_hint(k)
            add(f"| {k} | `{vec}` | {why} |")
        add("")

    # -- Methodology ------------------------------------------------------- #
    add("## Methodology & tooling")
    add("")
    add("- Tool: PeregrineStoop (scope-gated, audited recon accelerator).")
    add("- All requests passed a scope gate and were rate-limited; active "
        "probes were GET/OPTIONS only and non-destructive.")
    add("- Every outbound request is recorded in an append-only JSONL audit log.")
    add("")
    add("---")
    add("")
    add("_Candidates require manual verification before reporting. "
        "Responsible, authorized disclosure only._")
    add("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# HTML rendering — a self-contained, themeable page (no external assets)
# --------------------------------------------------------------------------- #

_SEV_COLOR = {"high": "#d9534f", "medium": "#e0922f",
              "low": "#4a90d9", "info": "#888"}

_HTML_CSS = """
:root { --bg:#fff; --fg:#1a1a1a; --muted:#666; --card:#f6f7f9;
        --border:#e2e4e8; --code:#f0f1f3; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#15171a; --fg:#e8e8e8; --muted:#9aa0a6; --card:#1e2126;
          --border:#2a2e35; --code:#23262c; } }
* { box-sizing: border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
       font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width: 880px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 28px 0 10px; border-bottom:1px solid var(--border);
     padding-bottom:6px; }
.brand { color: var(--muted); font-style: italic; margin: 0 0 16px; }
.meta { color: var(--muted); font-size: .9rem; }
.note { background: var(--card); border:1px solid var(--border); border-left:4px solid #e0922f;
        padding:10px 14px; border-radius:6px; margin:14px 0; }
table { border-collapse: collapse; width:100%; margin:10px 0; font-size:.92rem; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--border);
        vertical-align:top; }
th { color: var(--muted); font-weight:600; }
code { background: var(--code); padding:1px 5px; border-radius:4px; font-size:.86em; }
.pill { display:inline-block; padding:1px 9px; border-radius:11px; color:#fff;
        font-size:.78rem; font-weight:600; }
ul { margin:8px 0; padding-left:20px; }
footer { margin-top:28px; color:var(--muted); font-size:.85rem;
         border-top:1px solid var(--border); padding-top:12px; }
"""


def _esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def _pill(sev: str) -> str:
    c = _SEV_COLOR.get((sev or "info").lower(), "#888")
    return f'<span class="pill" style="background:{c}">{_esc(sev)}</span>'


def render_html_report(host: str, fingerprint: dict | None,
                       findings: list[dict]) -> str:
    """Render the same report as a self-contained HTML page (no external assets)."""
    now = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    fp = fingerprint or {}
    rows = []

    rows.append(f"<h1>PeregrineStoop recon report</h1>")
    rows.append(f'<p class="brand">{_esc(BRAND)}</p>')
    rows.append(f'<p class="meta">Target <code>{_esc(host)}</code> · generated '
                f'{_esc(now)} · {len(findings)} finding(s)</p>')
    rows.append('<div class="note">Authorized testing only. A recon triage '
                'summary — every active-probe item and CVE entry is a '
                '<b>candidate to verify</b>, not a confirmed vulnerability.</div>')

    rows.append("<h2>Technology fingerprint</h2><ul>")
    rows.append(f"<li><b>Server:</b> {_esc(fp.get('server') or 'unknown')}</li>")
    rows.append(f"<li><b>Language:</b> {_esc(fp.get('language') or 'unknown')}</li>")
    rows.append(f"<li><b>CDN:</b> {_esc(fp.get('cdn') or 'none detected')}</li>")
    rows.append(f"<li><b>WAF:</b> {_esc(fp.get('waf') or 'none detected')}</li>")
    if fp.get("allowed_methods"):
        rows.append(f"<li><b>Methods:</b> {_esc(', '.join(fp['allowed_methods']))}</li>")
    if fp.get("vuln_classes"):
        rows.append(f"<li><b>Vuln classes:</b> {_esc(', '.join(fp['vuln_classes']))}</li>")
    rows.append("</ul>")

    cves = fp.get("cve_candidates") or []
    if cves:
        rows.append("<h2>CVE candidates (verify only)</h2>")
        rows.append("<table><tr><th>CVE / lead</th><th>For</th>"
                    "<th>Confidence</th><th>Verify</th></tr>")
        for c in cves:
            rows.append(f"<tr><td><code>{_esc(c.get('cve'))}</code></td>"
                        f"<td>{_esc(c.get('for'))}</td>"
                        f"<td>{_esc(c.get('confidence'))}</td>"
                        f"<td>{_esc(c.get('verify'))}</td></tr>")
        rows.append("</table>")

    rows.append("<h2>Findings</h2>")
    if findings:
        rows.append("<table><tr><th>Severity</th><th>Kind</th><th>Detail</th></tr>")
        for f in sorted(findings, key=_sev_key):
            rows.append(f"<tr><td>{_pill(f.get('severity','info'))}</td>"
                        f"<td>{_esc(f.get('kind'))}</td>"
                        f"<td>{_esc(f.get('detail'))}</td></tr>")
        rows.append("</table>")
    else:
        rows.append("<p>No findings recorded.</p>")

    cvss = [k for k in dict.fromkeys(f.get("kind", "") for f in findings)
            if cvss_hint(k)]
    if cvss:
        rows.append("<h2>Suggested CVSS 3.1 starting vectors (verify before use)</h2>")
        rows.append("<table><tr><th>Kind</th><th>Starting vector</th>"
                    "<th>Rationale</th></tr>")
        for k in cvss:
            vec, why = cvss_hint(k)
            rows.append(f"<tr><td>{_esc(k)}</td><td><code>{_esc(vec)}</code></td>"
                        f"<td>{_esc(why)}</td></tr>")
        rows.append("</table>")

    rows.append('<footer>Generated by PeregrineStoop — scope-gated, audited '
                'recon. Candidates require manual verification; responsible, '
                'authorized disclosure only.</footer>')

    body = "\n".join(rows)
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>PeregrineStoop — {_esc(host)}</title>"
            f"<style>{_HTML_CSS}</style></head><body><div class=\"wrap\">"
            f"{body}</div></body></html>\n")
