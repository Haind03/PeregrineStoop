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


def probe_reflection(http: StoopHTTP, url: str, param: str = "q") -> ProbeResult | None:
    """Inject a unique benign token and see if it reflects unencoded."""
    token = "prgstoop" + secrets.token_hex(4)
    test_url = _with_param(url, param, token)
    try:
        resp = http.get(test_url)
    except ScopeViolation:
        raise
    except Exception as exc:  # noqa: BLE001
        log("-", f"reflection probe error: {exc}")
        return None
    body = _body_text(resp)
    if token not in body:
        return None
    ctype = resp.headers.get("Content-Type", "").lower()
    htmlish = "html" in ctype or "<html" in body.lower()
    # unencoded reflection in an HTML context is the interesting case
    severity = "medium" if htmlish else "low"
    return ProbeResult(
        kind="reflected-input", url=test_url, severity=severity,
        confidence="low",
        detail=f"param '{param}' reflected unencoded in response "
               f"(content-type={ctype or 'unknown'}) — candidate reflected XSS, "
               "verify context/encoding manually",
        evidence=f"token {token} echoed",
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


def probe_cors(http: StoopHTTP, url: str) -> ProbeResult | None:
    """Send a crafted Origin and check whether ACAO reflects it."""
    try:
        resp = http.get(url, headers={"Origin": _CORS_ORIGIN})
    except ScopeViolation:
        raise
    except Exception:  # noqa: BLE001
        return None
    aco = resp.headers.get("Access-Control-Allow-Origin", "")
    acc = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    if aco == _CORS_ORIGIN:
        sev = "high" if acc == "true" else "medium"
        return ProbeResult(
            kind="cors-reflection", url=url, severity=sev, confidence="medium",
            detail="ACAO reflects arbitrary Origin"
                   + (" WITH credentials" if acc == "true" else ""),
            evidence=f"ACAO={aco} ACAC={acc or 'n/a'}",
        )
    return None


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
        r = probe_cors(http, base_url)
        if r:
            results.append(r)
    if do_reflection:
        r = probe_reflection(http, base_url, reflection_param)
        if r:
            results.append(r)
    if do_redirect:
        results.extend(probe_open_redirect(http, base_url, redirect_params))
    for r in results:
        log("+", f"candidate [{r.severity}] {r.kind}: {r.detail}")
    return results
