"""Shared primitives: scope gate, audited HTTP session, colored logging.

Every outbound request in PeregrineStoop goes through :class:`StoopHTTP`,
which refuses to touch any host that is not explicitly in scope and writes an
append-only audit record for each attempt. This module is the trust boundary
of the toolkit.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit

try:
    import requests
except ImportError:  # pragma: no cover - requests is a hard dependency
    requests = None  # type: ignore

__all__ = [
    "ScopeChecker",
    "ScopeViolation",
    "StoopHTTP",
    "AuditLogger",
    "RateLimiter",
    "log",
    "SAFE_METHODS",
    "DEFAULT_UA",
]

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
DEFAULT_UA = (
    "PeregrineStoop/0.1 (authorized security testing; "
    "contact=haind@ptit.edu.vn)"
)

# --------------------------------------------------------------------------- #
# Logging (stderr only; stdout is reserved for machine-readable output)
# --------------------------------------------------------------------------- #

_COLORS = {
    "+": "\033[32m",  # green  — success / finding
    "-": "\033[31m",  # red    — error / out-of-scope
    "!": "\033[33m",  # yellow — warning
    "*": "\033[36m",  # cyan   — info
}
_RESET = "\033[0m"


def _use_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stderr.isatty()


def log(kind: str, msg: str) -> None:
    """Write a status line to stderr. ``kind`` is one of ``+ - ! *``."""
    prefix = f"[{kind}]"
    if _use_color() and kind in _COLORS:
        prefix = f"{_COLORS[kind]}{prefix}{_RESET}"
    print(f"{prefix} {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Scope checking
# --------------------------------------------------------------------------- #


class ScopeViolation(RuntimeError):
    """Raised when a request targets a host outside the authorized scope."""


def _normalize_host(host: str) -> str:
    return host.strip().strip(".").lower()


@dataclass
class ScopeChecker:
    """Decide whether a host is authorized.

    Patterns:
      * ``*.target.com`` — ``target.com`` and any subdomain of it, anchored on
        the leading dot so ``evil-target.com`` does NOT match.
      * ``target.com``   — exact host only.
      * ``10.0.0.0/8`` / ``192.168.1.1`` — IP address or CIDR network.

    ``exclude`` patterns always win over ``include`` patterns.
    """

    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)

    def add(self, pattern: str) -> None:
        pattern = pattern.strip()
        if not pattern or pattern.startswith("#"):
            return
        if pattern.startswith("!"):
            self.exclude.append(pattern[1:].strip().lower())
        else:
            self.include.append(pattern.lower())

    @classmethod
    def from_patterns(cls, patterns: Iterable[str]) -> "ScopeChecker":
        sc = cls()
        for p in patterns:
            sc.add(p)
        return sc

    @classmethod
    def from_file(cls, path: str) -> "ScopeChecker":
        sc = cls()
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                sc.add(line)
        return sc

    # -- matching ---------------------------------------------------------- #

    @staticmethod
    def _match_one(host: str, pattern: str) -> bool:
        host = _normalize_host(host)
        pattern = _normalize_host(pattern)
        if not pattern:
            return False

        # CIDR network
        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False

        # Wildcard suffix, anchored on the dot
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)

        # Bare IP or exact host
        return host == pattern

    def is_in_scope(self, host: str) -> bool:
        host = _normalize_host(host)
        if not host:
            return False
        if any(self._match_one(host, p) for p in self.exclude):
            return False
        return any(self._match_one(host, p) for p in self.include)

    def check_url(self, url: str) -> str:
        """Return the host if in scope, else raise :class:`ScopeViolation`."""
        host = urlsplit(url).hostname or ""
        if not self.is_in_scope(host):
            raise ScopeViolation(
                f"host {host!r} is out of scope — refusing to send request"
            )
        return host

    def __bool__(self) -> bool:  # empty scope == no authorization
        return bool(self.include)


# --------------------------------------------------------------------------- #
# Audit log (append-only JSONL)
# --------------------------------------------------------------------------- #


class AuditLogger:
    """Append-only JSONL audit trail. One record per request attempt."""

    def __init__(self, path: str, session_id: str) -> None:
        self.path = path
        self.session_id = session_id
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    def record(
        self,
        *,
        url: str,
        method: str,
        scope_check: str,
        status: int | None,
        note: str = "",
    ) -> None:
        entry = {
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session_id": self.session_id,
            "method": method,
            "url": url,
            "scope_check": scope_check,
            "status": status,
            "note": note,
        }
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #


class RateLimiter:
    """Simple token-bucket-ish limiter: at most ``rate`` requests per second."""

    def __init__(self, rate: float) -> None:
        self.min_interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


# --------------------------------------------------------------------------- #
# Audited HTTP session
# --------------------------------------------------------------------------- #


class StoopHTTP:
    """A ``requests`` session wrapped in a scope gate + audit log.

    No request leaves this object unless :class:`ScopeChecker` authorizes the
    target host. Unsafe methods (anything outside GET/HEAD/OPTIONS) require
    ``allow_unsafe=True`` and emit a warning.
    """

    def __init__(
        self,
        scope: ScopeChecker,
        *,
        audit: AuditLogger | None = None,
        rate: float = 3.0,
        timeout: float = 15.0,
        user_agent: str = DEFAULT_UA,
        verify: bool = True,
        allow_unsafe: bool = False,
        max_body: int = 2_000_000,
        session: "requests.Session | None" = None,
    ) -> None:
        if requests is None and session is None:  # pragma: no cover
            raise RuntimeError("the 'requests' package is required")
        self.scope = scope
        self.audit = audit
        self.rate = RateLimiter(rate)
        self.timeout = timeout
        self.verify = verify
        self.allow_unsafe = allow_unsafe
        self.max_body = max_body
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def request(self, method: str, url: str, **kwargs):
        method = method.upper()

        # 1) method safety gate
        if method not in SAFE_METHODS and not self.allow_unsafe:
            if self.audit:
                self.audit.record(
                    url=url, method=method, scope_check="blocked-unsafe",
                    status=None, note="unsafe method without --allow-unsafe",
                )
            raise PermissionError(
                f"method {method} is unsafe; pass allow_unsafe=True "
                "(CLI: --allow-unsafe) to permit it"
            )
        if method not in SAFE_METHODS:
            log("!", f"UNSAFE {method} {url} (allow_unsafe enabled)")

        # 2) scope gate — raises before any packet is sent
        try:
            host = self.scope.check_url(url)
        except ScopeViolation:
            if self.audit:
                self.audit.record(
                    url=url, method=method, scope_check="out-of-scope",
                    status=None, note="blocked by scope gate",
                )
            log("-", f"OUT-OF-SCOPE {url} — not sent")
            raise

        # 3) rate limit
        self.rate.wait()

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("stream", True)

        status: int | None = None
        note = ""
        try:
            resp = self.session.request(method, url, **kwargs)
            # enforce body-size cap when streaming
            if kwargs.get("stream"):
                content = resp.raw.read(self.max_body + 1, decode_content=True)
                if len(content) > self.max_body:
                    content = content[: self.max_body]
                    note = f"body truncated at {self.max_body} bytes"
                resp._content = content  # type: ignore[attr-defined]
                resp._content_consumed = True  # type: ignore[attr-defined]
            status = resp.status_code
            return resp
        except Exception as exc:  # noqa: BLE001 - audit then re-raise
            note = f"error: {exc.__class__.__name__}: {exc}"
            raise
        finally:
            if self.audit:
                self.audit.record(
                    url=url, method=method, scope_check=f"in-scope:{host}",
                    status=status, note=note,
                )

    # convenience wrappers
    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw):
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw):
        return self.request("OPTIONS", url, **kw)


def new_session_id() -> str:
    return uuid.uuid4().hex[:12]
