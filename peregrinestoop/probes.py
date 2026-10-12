"""Safe, non-destructive active probes (GET/OPTIONS only).

Each probe sends a single, benign, scope-gated request and reports a
*candidate* worth manual verification — never a confirmed vulnerability. No
payload here is destructive, state-changing, or capable of DoS:

* reflected-input marker — does a unique benign token echo unencoded? (XSS lead)
* open-redirect — does a redirect param bounce to an external marker host?
* CORS reflection — is a crafted ``Origin`` reflected in ACAO (with creds)?
* method enumeration — does OPTIONS advertise TRACE/PUT/DELETE?

The injected markers are harmless strings pointing at RFC-2606 example hosts;
the request itself always targets the in-scope host and passes the scope gate.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlencode, urlsplit, urlunsplit

from .common import ScopeViolation, StoopHTTP, log
from .fingerprint import parse_allow

__all__ = ["ProbeResult", "run_safe_probes", "REDIRECT_PARAMS"]

# common parameter names that frequently drive redirects
REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_uri", "return", "returnurl",
    "return_to", "dest", "destination", "continue", "r", "u", "goto",
]

# RFC-2606 reserved host — safe, routes nowhere meaningful
_REDIR_MARKER = "https://stoop-oob.example/"
_CORS_ORIGIN = "https://stoop-evil.example"


@dataclass
class ProbeResult:
    kind: str
    url: str
    severity: str          # info | low | medium | high
    confidence: str         # low | medium | high
    detail: str
    evidence: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "url": self.url, "severity": self.severity,
            "confidence": self.confidence, "detail": self.detail,
            "evidence": self.evidence,
        }


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    q = parts.query
    extra = urlencode({key: value})
    new_q = f"{q}&{extra}" if q else extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", new_q, ""))


def _body_text(resp) -> str:
    try:
        return (resp.content or b"").decode("latin-1", "replace")
    except Exception:  # noqa: BLE001
        return ""


_SPECIAL = ['<', '>', '"', "'"]

# which context a browser would treat the reflection as — most to least severe
_CTX_PRIORITY = ["js", "html", "attribute", "comment", "css"]


class _ReflectionDOM(HTMLParser):
    """stdlib DOM parser that records where a marker lands, as a browser sees it.

    Because the parser models real tokenization, a quote/angle-bracket breakout
    shows up as the marker appearing in a *different* context than it was
    injected into — a far stronger signal than substring matching.
    """

    def __init__(self, marker: str) -> None:
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.hits: list[tuple[str, str]] = []  # (context, descriptor)
        self._stack: list[str] = []

    def _attrs(self, tag, attrs):
        for k, v in attrs:
            if v and self.marker in v:
                self.hits.append(("attribute", f"{tag}@{k}"))

    def handle_starttag(self, tag, attrs):
        self._attrs(tag, attrs)
        if tag not in ("br", "img", "input", "meta", "link", "hr"):
            self._stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        self._attrs(tag, attrs)

    def handle_endtag(self, tag):
        while self._stack and self._stack.pop() != tag:
            pass

    def handle_data(self, data):
        if self.marker in data:
            cur = self._stack[-1] if self._stack else "body"
            if cur == "script":
                self.hits.append(("js", "script"))
            elif cur == "style":
                self.hits.append(("css", "style"))
            else:
                self.hits.append(("html", cur))

    def handle_comment(self, data):
        if self.marker in data:
            self.hits.append(("comment", ""))


def _classify_context(body: str, marker: str) -> tuple[str, str]:
    """Return (context, descriptor) using the DOM parser, with a safe fallback."""
    try:
        p = _ReflectionDOM(marker)
        p.feed(body)
        p.close()
        if p.hits:
            for ctx in _CTX_PRIORITY:
                for c, desc in p.hits:
                    if c == ctx:
                        return c, desc
            return p.hits[0]
    except Exception:  # noqa: BLE001 - malformed HTML: fall back
        pass
    # fallback heuristic if the parser found nothing
    bl = body.lower()
    idx = bl.find(marker.lower())
    if idx < 0:
        return "unknown", ""
    before = bl[:idx]
    if before.rfind("<script") > before.rfind("</script"):
        return "js", "script"
    if before.rfind("<!--") > before.rfind("-->"):
        return "comment", ""
    if before.rfind("<") > before.rfind(">"):
        return "attribute", ""
    return "html", ""


def _survived_specials(body: str, marker: str) -> list[str]:
    """Which of < > " ' appear unencoded in the window right after the marker."""
    idx = body.find(marker)
    if idx < 0:
        return []
    window = body[idx + len(marker): idx + len(marker) + 8]
    return [c for c in _SPECIAL if c in window]


def probe_reflection(http: StoopHTTP, url: str, param: str = "q",
                     confirm: bool = True) -> ProbeResult | None:
    """Inject a benign canary and classify the reflection context + encoding.

    The canary appends ``"'<>`` after a unique marker so we can see which XSS
    metacharacters survive unencoded and in what context (HTML text, attribute,
    JS or comment). Nothing is executed; the value is only reflected, so this
    stays a non-destructive lead, reported as a candidate to verify.

    When ``confirm`` is set, a second request with a fresh marker checks that the
    reflection is stable (reproducible), which cuts false positives from caches
    or one off echoes. For the attribute context it also reports which quote
    survived, since that is what an attribute breakout needs.
    """
    marker = "prgstoop" + secrets.token_hex(4)
    canary = marker + "\"'<>"
    test_url = _with_param(url, param, canary)
    try:
        resp = http.get(test_url)
    except ScopeViolation:
        raise
    except Exception as exc:  # noqa: BLE001
        log("-", f"reflection probe error: {exc}")
        return None
    body = _body_text(resp)
    if marker not in body:
        return None

    ctype = resp.headers.get("Content-Type", "").lower()
    htmlish = "html" in ctype or "<html" in body.lower()
    context, where = _classify_context(body, marker)
    survived = _survived_specials(body, marker)

    # which quote survived (matters for an attribute breakout)
    quote = ""
    if '"' in survived and "'" in survived:
        quote = "both quotes"
    elif '"' in survived:
        quote = "double quote"
    elif "'" in survived:
        quote = "single quote"

    # severity from how exploitable the context+encoding looks
    if not survived:
        severity, confidence = "info", "low"
        lead = "reflected but XSS metacharacters are encoded"
    elif context == "js":
        severity, confidence = "high", "medium"
        lead = "reflected inside a <script> block with unencoded chars"
    elif context == "html" and "<" in survived and ">" in survived:
        severity, confidence = "high", "medium"
        lead = "reflected in HTML text with '<' and '>' unencoded (tag injection)"
    elif context == "attribute" and quote:
        severity, confidence = "medium", "medium"
        lead = f"reflected inside an attribute with {quote} unencoded (attr breakout)"
    else:
        severity, confidence = "low", "low"
        lead = "reflected with some metacharacters unencoded"

    if not htmlish and severity in ("high", "medium"):
        # not served as HTML, so downgrade (e.g. JSON reflecting input)
        severity, confidence = "low", "low"
        lead += " (non-HTML content-type, lower impact)"

    # stability check: reproduce with a fresh marker
    stable = True
    if confirm:
        marker2 = "prgstoop" + secrets.token_hex(4)
        try:
            resp2 = http.get(_with_param(url, param, marker2))
            stable = marker2 in _body_text(resp2)
        except ScopeViolation:
            raise
        except Exception:  # noqa: BLE001
            stable = True  # could not re-check; do not penalize
    if confirm and not stable:
        # reflection did not reproduce: likely noise, drop to a low lead
        severity = "low" if severity != "info" else "info"
        confidence = "low"
        lead = "unconfirmed (not reproduced on a second request): " + lead
    elif stable and confidence == "medium":
        confidence = "high"   # reproducible reflection in an exploitable context

    loc = f"context={context}" + (f" ({where})" if where else "")
    note = "stable" if stable else "single-sample"
    return ProbeResult(
        kind="reflected-input", url=test_url, severity=severity,
        confidence=confidence,
        detail=f"param '{param}': {lead}; {loc}, "
               f"survived={''.join(survived) or 'none'}, {note}, "
               f"content-type={ctype or 'unknown'}, verify manually",
        evidence=f"marker {marker} reflected ({note}), unencoded chars: "
                 f"{''.join(survived) or 'none'}",
    )


def probe_open_redirect(http: StoopHTTP, url: str,
                        params=REDIRECT_PARAMS) -> list[ProbeResult]:
    """Test common redirect params for a bounce to an external marker host."""
    out: list[ProbeResult] = []
    for p in params:
        test_url = _with_param(url, p, _REDIR_MARKER)
        try:
            resp = http.get(test_url)  # allow_redirects is False by default
        except ScopeViolation:
            raise
        except Exception:  # noqa: BLE001
            continue
        loc = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and \
                "stoop-oob.example" in loc:
            out.append(ProbeResult(
                kind="open-redirect", url=test_url, severity="medium",
                confidence="medium",
                detail=f"param '{p}' drives redirect to attacker-controlled host",
                evidence=f"{resp.status_code} Location: {loc}",
            ))
    return out


def _cors_vectors(host: str) -> list[tuple[str, str]]:
    """Origin values to test, as (label, origin). Benign RFC-2606 markers."""
    vectors = [
        ("arbitrary-origin", _CORS_ORIGIN),
        ("null-origin", "null"),
    ]
    if host:
        # weak origin validation patterns
        vectors.append(("subdomain-suffix", f"https://{host}.stoop-evil.example"))
        vectors.append(("prefix-bypass", f"https://stoop-evil-{host}"))
    return vectors


def probe_cors(http: StoopHTTP, url: str) -> list[ProbeResult]:
    """Test several crafted Origins and report each ACAO that trusts one.

    Covers arbitrary-origin reflection, the ``null`` origin, and two weak
    validation patterns (an attacker suffix and an attacker prefix on the host).
    Each is a single benign GET with an ``Origin`` header.
    """
    host = urlsplit(url).hostname or ""
    out: list[ProbeResult] = []
    for label, origin in _cors_vectors(host):
        try:
            resp = http.get(url, headers={"Origin": origin})
        except ScopeViolation:
            raise
        except Exception:  # noqa: BLE001
            continue
        aco = resp.headers.get("Access-Control-Allow-Origin", "")
        acc = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        trusts = (aco == origin) or (label == "null-origin" and aco == "null")
        if not trusts:
            continue
        creds = acc == "true"
        sev = "high" if creds else "medium"
        out.append(ProbeResult(
            kind="cors-reflection", url=url, severity=sev,
            confidence="high" if creds else "medium",
            detail=f"ACAO trusts {label} ({origin})"
                   + (" with credentials" if creds else ""),
            evidence=f"Origin={origin} ACAO={aco} ACAC={acc or 'n/a'}",
        ))
    return out


def probe_methods(http: StoopHTTP, url: str) -> ProbeResult | None:
    """OPTIONS method enumeration — flag TRACE/PUT/DELETE/PATCH."""
    try:
        resp = http.options(url)
    except ScopeViolation:
        raise
    except Exception:  # noqa: BLE001
        return None
    methods = parse_allow(dict(resp.headers))
    risky = sorted(set(methods) & {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"})
    if not risky:
        return None
    sev = "high" if ({"PUT", "DELETE"} & set(risky)) else "low"
    return ProbeResult(
        kind="dangerous-methods", url=url, severity=sev, confidence="high",
        detail=f"OPTIONS advertises {', '.join(risky)}",
        evidence=f"Allow: {', '.join(methods)}",
    )


def run_safe_probes(
    http: StoopHTTP,
    base_url: str,
    *,
    reflection_param: str = "q",
    redirect_params=REDIRECT_PARAMS,
    do_reflection: bool = True,
    do_redirect: bool = True,
    do_cors: bool = True,
    do_methods: bool = True,
) -> list[ProbeResult]:
    """Run the enabled safe probes against ``base_url`` and collect candidates."""
    results: list[ProbeResult] = []
    if do_methods:
        r = probe_methods(http, base_url)
        if r:
            results.append(r)
    if do_cors:
        results.extend(probe_cors(http, base_url))
    if do_reflection:
        r = probe_reflection(http, base_url, reflection_param)
        if r:
            results.append(r)
    if do_redirect:
        results.extend(probe_open_redirect(http, base_url, redirect_params))
    for r in results:
        log("+", f"candidate [{r.severity}] {r.kind}: {r.detail}")
    return results
