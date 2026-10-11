"""Tech / WAF fingerprinting + vuln-class & CVE routing.

Inspects response headers, cookies, body, generator meta tags and security
headers to infer the server, framework/language, CDN and WAF, then suggests
which vulnerability classes to prioritize. Version guesses are always flagged
``low-confidence`` unless a header states the version verbatim.

The signature tables aim for broad coverage of the stacks and WAFs commonly
seen on bug-bounty scopes. They are inference aids, not proof: a CVE listed
here is a *candidate to verify*, never an assertion that the target is
vulnerable.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping

from .common import StoopHTTP, log

__all__ = [
    "Fingerprint",
    "fingerprint_response",
    "fingerprint_host",
    "fingerprint_host_deep",
    "analyze_security_headers",
    "detect_waf",
    "parse_allow",
    "load_cve_map",
    "load_signatures",
]

_META_GENERATOR = re.compile(
    rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# --------------------------------------------------------------------------- #
# Signature tables — loaded from data/signatures.json so the lists can be
# extended without code changes. Body markers are stored as latin-1 strings and
# re-encoded to bytes here.
# --------------------------------------------------------------------------- #


def load_signatures() -> dict:
    """Load and reshape the signature tables from the bundled JSON file.

    Returns a dict with keys: cookies, server, xpowered, body, waf,
    security_headers — in the internal shapes the matcher expects.
    """
    import json
    from pathlib import Path

    path = Path(__file__).with_name("data") / "signatures.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # missing/corrupt -> no detection
        log("!", f"signatures.json unavailable ({exc}); fingerprinting disabled")
        raw = {}

    cookies = {k: (v["tech"], v.get("lang"), v["vulns"])
               for k, v in raw.get("cookies", {}).items()}
    server = [(e["needle"], e["tech"], e["vulns"]) for e in raw.get("server", [])]
    xpowered = [(e["needle"], e["tech"], e.get("lang"), e["vulns"])
                for e in raw.get("xpowered", [])]
    body = [(e["marker"].encode("latin-1"), e["tech"], e.get("lang"), e["vulns"])
            for e in raw.get("body", [])]
    waf = [(e["name"], e["kind"],
            [tuple(x) for x in e.get("headers", [])],
            list(e.get("cookies", [])),
            [b.encode("latin-1") for b in e.get("body", [])])
           for e in raw.get("waf", [])]
    sec = [(e["header"], e["vuln"], e["note"])
           for e in raw.get("security_headers", [])]
    return {"cookies": cookies, "server": server, "xpowered": xpowered,
            "body": body, "waf": waf, "security_headers": sec}


_SIGS = load_signatures()
_COOKIE_SIGS = _SIGS["cookies"]
_SERVER_SIGS = _SIGS["server"]
_XPOWERED_SIGS = _SIGS["xpowered"]
_BODY_SIGS = _SIGS["body"]
_WAF_SIGS = _SIGS["waf"]


@dataclass
class Fingerprint:
    host: str = ""
    tech: list[dict] = field(default_factory=list)   # [{name, confidence, evidence}]
    language: str | None = None
    server: str | None = None
    cdn: str | None = None
    waf: str | None = None
    vuln_classes: list[str] = field(default_factory=list)
    cve_candidates: list[dict] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    allowed_methods: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_tech(self, name: str, confidence: str, evidence: str) -> None:
        if not any(t["name"] == name for t in self.tech):
            self.tech.append(
                {"name": name, "confidence": confidence, "evidence": evidence}
            )

    def add_vuln(self, classes: list[str]) -> None:
        for c in classes:
            if c not in self.vuln_classes:
                self.vuln_classes.append(c)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "server": self.server,
            "language": self.language,
            "cdn": self.cdn,
            "waf": self.waf,
            "tech": self.tech,
            "vuln_classes": self.vuln_classes,
            "cve_candidates": self.cve_candidates,
            "security_headers": self.security_headers,
            "allowed_methods": self.allowed_methods,
            "notes": self.notes,
        }


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _version_in(text: str) -> str | None:
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# Security-header analysis — low-hanging bug-bounty surface
# --------------------------------------------------------------------------- #

# header -> (header name, missing vuln class, note); loaded from signatures.json
_SEC_HEADERS = _SIGS["security_headers"]


def analyze_security_headers(fp: Fingerprint, h: dict[str, str]) -> None:
    """Flag missing/misconfigured security headers as vuln classes + findings."""
    present = {}
    for name, vuln, note in _SEC_HEADERS:
        if name in h:
            present[name] = h[name]
        else:
            fp.add_vuln([vuln])
            fp.notes.append(note)

    # clickjacking: neither XFO nor frame-ancestors CSP
    xfo = h.get("x-frame-options")
    csp = h.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        fp.add_vuln(["clickjacking"])
        fp.notes.append("no X-Frame-Options / frame-ancestors — clickjacking risk")
    elif xfo:
        present["x-frame-options"] = xfo

    # permissive / credentialed CORS
    aco = h.get("access-control-allow-origin")
    acc = h.get("access-control-allow-credentials", "").lower()
    if aco:
        present["access-control-allow-origin"] = aco
        if aco == "*" or acc == "true":
            fp.add_vuln(["cors-misconfig"])
            fp.notes.append(
                f"CORS ACAO={aco!r} credentials={acc or 'n/a'} — "
                "review for cross-origin data exposure"
            )

    # verbose server banner = info leak
    if fp.server and _version_in(fp.server):
        fp.add_vuln(["version-disclosure"])

    fp.security_headers = present


def fingerprint_response(
    host: str,
    status: int,
    headers: Mapping[str, str],
    body: bytes = b"",
    set_cookies: list[str] | None = None,
) -> Fingerprint:
    """Build a :class:`Fingerprint` from a single response. Pure / testable."""
    fp = Fingerprint(host=host)
    h = _lower_headers(headers)
    body = body or b""
    cookies_raw = set_cookies if set_cookies is not None else []
    if "set-cookie" in h and not cookies_raw:
        cookies_raw = [h["set-cookie"]]
    cookie_blob = " ".join(cookies_raw).lower()

    # Server header
    if h.get("server"):
        fp.server = h["server"]
        low = h["server"].lower()
        for needle, name, vulns in _SERVER_SIGS:
            if needle in low:
                ver = _version_in(h["server"])
                conf = "high" if ver else "medium"
                fp.add_tech(name + (f" {ver}" if ver else ""), conf,
                            f"Server: {h['server']}")
                fp.add_vuln(vulns)
                if ver:
                    fp.notes.append(f"{name} version {ver} parsed from Server header")
                break

    # X-Powered-By
    if h.get("x-powered-by"):
        low = h["x-powered-by"].lower()
        for needle, name, lang, vulns in _XPOWERED_SIGS:
            if needle in low:
                ver = _version_in(h["x-powered-by"])
                fp.language = fp.language or lang
                fp.add_tech(name + (f" {ver}" if ver else ""),
                            "high" if ver else "medium",
                            f"X-Powered-By: {h['x-powered-by']}")
                fp.add_vuln(vulns)

    # X-Generator / X-AspNet-Version etc.
    if h.get("x-aspnet-version"):
        fp.language = fp.language or "dotnet"
        fp.add_tech(f"ASP.NET {h['x-aspnet-version']}", "high",
                    "X-AspNet-Version header")
        fp.add_vuln(["viewstate-deser"])

    # Cookies
    for cname, (tech, lang, vulns) in _COOKIE_SIGS.items():
        if cname in cookie_blob:
            if lang:
                fp.language = fp.language or lang
            fp.add_tech(tech, "high", f"cookie {cname}")
            fp.add_vuln(vulns)

    # meta generator
    m = _META_GENERATOR.search(body)
    if m:
        gen = m.group(1).decode("latin-1", "replace")
        ver = _version_in(gen)
        fp.add_tech(gen, "medium", "meta generator")
        if ver:
            fp.notes.append(
                f"generator version {ver} (low-confidence — client-side meta)")

    # body markers
    for marker, name, lang, vulns in _BODY_SIGS:
        if marker.lower() in body.lower():
            if lang:
                fp.language = fp.language or lang
            fp.add_tech(name, "medium", f"body marker {marker.decode('latin-1')!r}")
            fp.add_vuln(vulns)

    detect_waf(fp, h, cookie_blob, body)
    analyze_security_headers(fp, h)
    _route_cves(fp)
    return fp


def detect_waf(fp: Fingerprint, h: dict[str, str], cookie_blob: str,
               body: bytes) -> None:
    """Match WAF/CDN signatures and record them on ``fp`` (idempotent).

    Separated so it can be re-run against an error page (404/403), where WAFs
    often reveal themselves even when the home page does not.
    """
    for name, kind, hdr_checks, cookie_checks, body_checks in _WAF_SIGS:
        hit, evidence = False, ""
        for hk, hv in hdr_checks:
            if hk in h and (hv == "" or hv in h[hk].lower()):
                hit, evidence = True, f"header {hk}"
                break
        if not hit:
            for ck in cookie_checks:
                if ck in cookie_blob:
                    hit, evidence = True, f"cookie {ck}"
                    break
        if not hit:
            for bc in body_checks:
                if bc.lower() in body.lower():
                    hit, evidence = True, "error-page body"
                    break
        if hit:
            if "waf" in kind:
                fp.waf = fp.waf or name
            if "cdn" in kind:
                fp.cdn = fp.cdn or name
            if "lb" in kind and not fp.waf:
                fp.waf = name
            fp.add_tech(name, "high", evidence)


def parse_allow(headers: Mapping[str, str]) -> list[str]:
    """Extract HTTP methods advertised in an ``Allow`` header."""
    h = _lower_headers(headers)
    raw = h.get("allow") or h.get("access-control-allow-methods") or ""
    return sorted({m.strip().upper() for m in raw.split(",") if m.strip()})


# CVE routing is data-driven: candidates live in data/cve_map.json so the list
# can be extended without code changes. Each entry is a CANDIDATE to verify,
# never an assertion. Version-gated entries stay low-confidence unless a version
# was parsed from a header.


def load_cve_map() -> dict[str, list[dict]]:
    """Load the CVE-candidate map from the bundled JSON data file."""
    import json
    from pathlib import Path

    path = Path(__file__).with_name("data") / "cve_map.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # missing/corrupt -> degrade gracefully
        log("!", f"cve_map.json unavailable ({exc}); CVE routing disabled")
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_")}


_CVE_MAP = load_cve_map()


def _route_cves(fp: Fingerprint) -> None:
    for t in fp.tech:
        base = re.sub(r"\s+\d.*$", "", t["name"]).strip()
        for key, cves in _CVE_MAP.items():
            if key == base or key == t["name"]:
                for c in cves:
                    if not any(
                        x["cve"] == c["cve"] and x.get("for") == t["name"]
                        for x in fp.cve_candidates
                    ):
                        fp.cve_candidates.append({**c, "for": t["name"]})


def fingerprint_host(http: StoopHTTP, base_url: str) -> Fingerprint:
    """Live fingerprint: fetch base_url through the scope gate, then infer."""
    from urllib.parse import urlsplit

    host = urlsplit(base_url).hostname or base_url
    resp = http.get(base_url)
    set_cookies = None
    raw = getattr(resp, "raw", None)
    if raw is not None and hasattr(getattr(raw, "headers", None), "get_all"):
        try:
            set_cookies = raw.headers.get_all("Set-Cookie")
        except Exception:  # noqa: BLE001
            set_cookies = None
    fp = fingerprint_response(
        host, resp.status_code, dict(resp.headers), resp.content or b"", set_cookies
    )
    log("*", f"fingerprinted {host}: server={fp.server} waf={fp.waf} "
             f"tech={[t['name'] for t in fp.tech]}")
    return fp


_UNSAFE_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


def fingerprint_host_deep(http: StoopHTTP, base_url: str) -> Fingerprint:
    """Multi-probe fingerprint: home page + a 404 error page + OPTIONS.

    The 404 page is re-run through WAF detection (error pages often reveal a
    WAF that the home page hides). OPTIONS parses the ``Allow`` header to
    enumerate advertised methods and flag dangerous ones (TRACE/PUT/DELETE).
    All requests are GET/OPTIONS, scope-gated and audited.
    """
    from urllib.parse import urljoin, urlsplit

    fp = fingerprint_host(http, base_url)

    # 1) error page -> extra WAF signal
    err_url = urljoin(base_url, f"/stoop-404-{uuid_hex()}")
    try:
        er = http.get(err_url)
        detect_waf(fp, _lower_headers(dict(er.headers)),
                   "", er.content or b"")
        fp.notes.append(f"error-page probe {er.status_code} {err_url}")
    except Exception as exc:  # noqa: BLE001 - best effort
        fp.notes.append(f"error-page probe failed: {exc}")

    # 2) OPTIONS -> allowed methods
    try:
        opt = http.options(base_url)
        methods = parse_allow(dict(opt.headers))
        if methods:
            fp.allowed_methods = methods
            dangerous = sorted(set(methods) & _UNSAFE_METHODS)
            if dangerous:
                fp.add_vuln(["dangerous-methods"])
                fp.notes.append(
                    f"OPTIONS advertises {', '.join(dangerous)} — verify they are "
                    "intentional (state-changing / XST risk)")
            if "TRACE" in methods:
                fp.add_vuln(["xst"])
    except Exception as exc:  # noqa: BLE001
        fp.notes.append(f"OPTIONS probe failed: {exc}")

    host = urlsplit(base_url).hostname or base_url
    log("*", f"deep fingerprint {host}: methods={fp.allowed_methods} "
             f"waf={fp.waf}")
    return fp


def uuid_hex() -> str:
    import uuid as _uuid

    return _uuid.uuid4().hex[:8]
