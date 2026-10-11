"""Aggregate recon findings into a Markdown report for triage / disclosure.

Pulls the stored fingerprint and findings for a host out of the state DB and
renders a structured Markdown document. It is a *recon summary* to speed up
triage, not a vulnerability-confirmation report: every active-probe item and
CVE entry is labelled a candidate to verify.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import time

from . import BRAND

__all__ = ["render_report"]

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
