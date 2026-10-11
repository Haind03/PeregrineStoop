"""Optional TOML config profiles for default scope and HTTP settings.

Lets an operator keep per-engagement defaults (scope patterns, rate, budget,
timeout) in a file instead of retyping flags. Explicit CLI flags always win
over the config; the config wins over the built-in defaults. Uses the stdlib
``tomllib`` (Python 3.11+) — no extra dependency.

Example ``stoop.toml``::

    [scope]
    include = ["*.target.com"]
    exclude = ["admin.target.com"]

    [http]
    rate = 2
    budget = 600
    timeout = 20

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import tomllib

from .common import log

__all__ = ["load_config", "RATE_DEFAULT", "BUDGET_DEFAULT", "TIMEOUT_DEFAULT"]

RATE_DEFAULT = 3.0
BUDGET_DEFAULT = 300.0
TIMEOUT_DEFAULT = 15.0


def load_config(path: str) -> dict:
    """Load a TOML config file into a dict. Missing/invalid -> empty dict."""
    try:
        with open(path, "rb") as fh:
            cfg = tomllib.load(fh)
    except FileNotFoundError:
        log("!", f"config {path} not found — ignoring")
        return {}
    except (tomllib.TOMLDecodeError, OSError) as exc:
        log("-", f"config {path} invalid ({exc}) — ignoring")
        return {}
    if not isinstance(cfg, dict):
        return {}
    return cfg


def cfg_scope(cfg: dict) -> tuple[list[str], list[str]]:
    scope = cfg.get("scope", {}) if isinstance(cfg.get("scope"), dict) else {}
    include = [str(x) for x in scope.get("include", []) or []]
    exclude = [str(x) for x in scope.get("exclude", []) or []]
    return include, exclude


def cfg_http(cfg: dict, key: str, default):
    http = cfg.get("http", {}) if isinstance(cfg.get("http"), dict) else {}
    val = http.get(key)
    return val if val is not None else default
