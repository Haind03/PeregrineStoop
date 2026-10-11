"""Tech / WAF fingerprinting + vuln-class & CVE routing.

Inspects response headers, cookies, body and generator meta tags to infer the
server, framework/language, CDN and WAF, then suggests which vulnerability
classes to prioritize. Version guesses are always flagged ``low-confidence``
unless a header states the version verbatim.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping

from .common import StoopHTTP, log

__all__ = ["Fingerprint", "fingerprint_response", "fingerprint_host"]

_META_GENERATOR = re.compile(
    rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Cookie-name -> (tech, language, vuln classes)
_COOKIE_SIGS = {
    "phpsessid": ("PHP", "php", ["lfi", "rce-upload", "sqli"]),
    "jsessionid": ("Java servlet (JSP/Tomcat)", "java", ["deserialization", "ssrf", "path-traversal"]),
    "laravel_session": ("Laravel", "php", ["mass-assignment", "debug-leak", "idor"]),
    "asp.net_sessionid": ("ASP.NET", "dotnet", ["viewstate-deser", "padding-oracle"]),
    "ci_session": ("CodeIgniter", "php", ["sqli", "idor"]),
    "django_session": ("Django", "python", ["ssti", "debug-leak", "idor"]),
    "sessionid": ("Django", "python", ["ssti", "debug-leak"]),
    "connect.sid": ("Express / Node.js", "nodejs", ["proto-pollution", "ssrf", "nosqli"]),
    "wordpress_logged_in": ("WordPress", "php", ["plugin-cve", "xmlrpc", "rest-idor"]),
}

# header substring -> (tech, vuln classes)
_SERVER_SIGS = [
    ("nginx", "nginx", ["misrouting", "alias-traversal"]),
    ("apache", "Apache httpd", ["cgi-rce", "path-traversal"]),
    ("microsoft-iis", "Microsoft IIS", ["short-name-enum", "webdav"]),
    ("litespeed", "LiteSpeed", ["path-traversal"]),
    ("gunicorn", "Gunicorn (Python)", ["ssti", "debug-leak"]),
    ("werkzeug", "Werkzeug (Flask)", ["debug-console-rce", "ssti"]),
    ("express", "Express (Node.js)", ["proto-pollution", "nosqli"]),
    ("kestrel", "ASP.NET Core (Kestrel)", ["deserialization"]),
    ("openresty", "OpenResty", ["ssrf", "lua-misconfig"]),
]

_XPOWERED_SIGS = [
    ("php", "PHP", "php", ["lfi", "rce-upload", "sqli"]),
    ("asp.net", "ASP.NET", "dotnet", ["viewstate-deser", "padding-oracle"]),
    ("express", "Express (Node.js)", "nodejs", ["proto-pollution", "nosqli"]),
    ("servlet", "Java servlet", "java", ["deserialization"]),
    ("next.js", "Next.js", "nodejs", ["ssrf", "middleware-bypass"]),
]

# WAF/CDN signatures: (name, kind, [header checks], [cookie checks], [body checks])
_WAF_SIGS = [
    ("Cloudflare", "cdn+waf",
     [("server", "cloudflare"), ("cf-ray", "")], ["__cfduid", "cf_clearance"],
     [b"Attention Required! | Cloudflare"]),
    ("Akamai", "cdn+waf",
     [("server", "akamaighost"), ("x-akamai", "")], ["akamai"],
     [b"Reference&#32;&#35;"]),
    ("Imperva Incapsula", "waf",
     [("x-iinfo", ""), ("x-cdn", "incapsula")], ["incap_ses", "visid_incap"],
     [b"Incapsula incident ID"]),
    ("F5 BIG-IP ASM", "waf",
     [("server", "big-ip")], ["ts", "bigipserver"],
     [b"The requested URL was rejected"]),
    ("AWS CloudFront", "cdn",
     [("x-amz-cf-id", ""), ("via", "cloudfront")], [], []),
    ("Sucuri", "waf",
     [("server", "sucuri"), ("x-sucuri-id", "")], [], [b"Sucuri WebSite Firewall"]),
    ("Fastly", "cdn",
     [("x-served-by", "cache"), ("x-fastly", "")], [], []),
]


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
            "notes": self.notes,
        }


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _version_in(text: str) -> str | None:
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
    return m.group(1) if m else None


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
    # requests folds multiple Set-Cookie into one header; keep both paths
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
                ev = f"Server: {h['server']}"
                fp.add_tech(name + (f" {ver}" if ver else ""), conf, ev)
                fp.add_vuln(vulns)
                if ver:
                    fp.notes.append(f"{name} version {ver} parsed from Server header")

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

    # Cookies
    for cname, (tech, lang, vulns) in _COOKIE_SIGS.items():
        if cname in cookie_blob:
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
            fp.notes.append(f"generator version {ver} (low-confidence — client-side meta)")

    # framework hints in body
    if b"__NEXT_DATA__" in body:
        fp.add_tech("Next.js", "medium", "__NEXT_DATA__ in body")
        fp.language = fp.language or "nodejs"
    if b"wp-content" in body or b"wp-includes" in body:
        fp.add_tech("WordPress", "medium", "wp-content/wp-includes paths")
        fp.add_vuln(["plugin-cve", "xmlrpc", "rest-idor"])

    # WAF / CDN
    for name, kind, hdr_checks, cookie_checks, body_checks in _WAF_SIGS:
        hit = False
        evidence = ""
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
                fp.waf = name
            if "cdn" in kind:
                fp.cdn = name
            fp.add_tech(name, "high", evidence)

    _route_cves(fp)
    return fp


# Illustrative, non-exhaustive routing. CVEs are *candidates to verify*, never
# asserted as present. Version-gated entries stay low-confidence unless a
# version was parsed from a header above.
_CVE_MAP = {
    "Werkzeug (Flask)": [
        {"cve": "CVE-2019-14806-class", "desc": "debug console PIN / RCE if debug=on",
         "confidence": "low", "verify": "GET /console then check for interactive prompt"},
    ],
    "WordPress": [
        {"cve": "plugin-specific", "desc": "enumerate plugins/themes for known CVEs",
         "confidence": "low", "verify": "GET /wp-json/wp/v2/plugins and /readme.html"},
    ],
    "Apache httpd": [
        {"cve": "CVE-2021-41773", "desc": "path traversal/RCE in 2.4.49",
         "confidence": "low", "verify": "requires version 2.4.49; confirm via Server header"},
    ],
}


def _route_cves(fp: Fingerprint) -> None:
    for t in fp.tech:
        base = re.sub(r"\s+\d.*$", "", t["name"]).strip()
        for key, cves in _CVE_MAP.items():
            if key == base or key == t["name"]:
                for c in cves:
                    fp.cve_candidates.append({**c, "for": t["name"]})


def fingerprint_host(http: StoopHTTP, base_url: str) -> Fingerprint:
    """Live fingerprint: fetch base_url (and a 404 page) through the gate."""
    from urllib.parse import urlsplit

    host = urlsplit(base_url).hostname or base_url
    resp = http.get(base_url)
    set_cookies = resp.raw.headers.get_all("Set-Cookie") if hasattr(
        resp.raw, "headers"
    ) else None
    fp = fingerprint_response(
        host, resp.status_code, dict(resp.headers), resp.content or b"", set_cookies
    )
    log("*", f"fingerprinted {host}: server={fp.server} waf={fp.waf} "
             f"tech={[t['name'] for t in fp.tech]}")
    return fp
