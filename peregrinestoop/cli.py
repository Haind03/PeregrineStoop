"""``stoop`` — the PeregrineStoop CLI orchestrator.

Pipeline (time-budgeted): scope gate -> fingerprint -> rank attack surface ->
filter through the dedup state -> probe safe low-hanging fruit (GET/HEAD) ->
print a priority table. All HTTP goes through the audited, scope-gated session.

A peregrine's stoop is the fastest hunting move in nature.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlsplit

from . import BRAND, __version__
from .common import (
    AuditLogger,
    ScopeChecker,
    ScopeViolation,
    StoopHTTP,
    log,
    new_session_id,
)
from .diff import (
    Snapshot,
    crawl_light,
    diff_snapshots,
    snapshot_from_items,
    sensitivity,
)
from .fingerprint import fingerprint_host, fingerprint_host_deep
from .audit import format_text, load_audit, summarize_audit
from .crawl import crawl_site
from .config import (
    BUDGET_DEFAULT,
    RATE_DEFAULT,
    TIMEOUT_DEFAULT,
    cfg_http,
    cfg_scope,
    load_config,
)
from .probes import run_safe_probes
from .report import render_html_report, render_report
from .state import BudgetTimer, StateStore

_BANNER = rf"""
  PeregrineStoop v{__version__}  ·  stoop
  {BRAND}
  authorized testing only — no host is touched unless it is in scope
"""

# Safe paths probed during `run` for quick wins. GET only.
_PROBE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.env",
    "/swagger.json",
    "/openapi.json",
    "/api/",
    "/actuator/health",
    "/server-status",
]


def _add_common_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--scope", action="append", default=[], metavar="PATTERN",
                   help="in-scope pattern (repeatable), e.g. '*.target.com'")
    p.add_argument("--scope-file", metavar="FILE",
                   help="file of scope patterns ('!'=exclude, '#'=comment)")
    p.add_argument("--config", metavar="FILE",
                   help="TOML config with default scope/http settings")
    p.add_argument("--rate", type=float, default=None,
                   help="max requests/second (default 3)")
    p.add_argument("--timeout", type=float, default=None,
                   help="per-request timeout seconds (default 15)")
    p.add_argument("--budget", type=float, default=None,
                   help="per-target time budget seconds (default 300 = 5 min)")
    p.add_argument("--insecure", action="store_true",
                   help="disable TLS verification (lab use)")
    p.add_argument("--allow-unsafe", action="store_true",
                   help="permit PUT/POST/DELETE/PATCH (prints a warning)")
    p.add_argument("--audit-log", default="stoop_audit.jsonl",
                   help="append-only JSONL audit log path")
    p.add_argument("--state-db", default=".stoop_state.sqlite",
                   help="SQLite state/dedup database path")
    p.add_argument("--json", metavar="FILE",
                   help="also write machine-readable JSON to this file")


def _cfg(args) -> dict:
    return getattr(args, "_cfg", {}) or {}


def _budget(args) -> float:
    if args.budget is not None:
        return args.budget
    return float(cfg_http(_cfg(args), "budget", BUDGET_DEFAULT))


def _build_scope(args) -> ScopeChecker:
    sc = ScopeChecker()
    if args.scope_file:
        sc = ScopeChecker.from_file(args.scope_file)
    inc, exc = cfg_scope(_cfg(args))        # config-provided scope (additive)
    for pat in inc:
        sc.add(pat)
    for pat in exc:
        sc.add("!" + pat)
    for pat in args.scope:                  # explicit CLI scope
        sc.add(pat)
    if not sc:
        log("-", "empty scope — refusing to run. Provide --scope, --scope-file, "
                 "or a [scope] section in --config.")
        raise SystemExit(2)
    log("*", f"scope include={sc.include} exclude={sc.exclude}")
    return sc


def _build_http(args, scope: ScopeChecker, session_id: str) -> StoopHTTP:
    audit = AuditLogger(args.audit_log, session_id)
    cfg = _cfg(args)
    rate = args.rate if args.rate is not None else cfg_http(cfg, "rate", RATE_DEFAULT)
    timeout = (args.timeout if args.timeout is not None
               else cfg_http(cfg, "timeout", TIMEOUT_DEFAULT))
    return StoopHTTP(
        scope,
        audit=audit,
        rate=float(rate),
        timeout=float(timeout),
        verify=not args.insecure,
        allow_unsafe=args.allow_unsafe,
    )


def _emit_json(args, payload: dict) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(text)
        log("+", f"wrote JSON -> {args.json}")
    else:
        print(text)  # stdout = machine output


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #


def cmd_fingerprint(args) -> int:
    scope = _build_scope(args)
    sid = new_session_id()
    http = _build_http(args, scope, sid)
    try:
        fp = fingerprint_host(http, args.url)
    except ScopeViolation as exc:
        log("-", str(exc))
        return 3
    store = StateStore(args.state_db)
    store.save_fingerprint(fp.host, fp.to_dict())
    store.touch_session(sid, fp.host)
    store.close()
    _emit_json(args, fp.to_dict())
    return 0


def cmd_diff(args) -> int:
    scope = _build_scope(args)
    sid = new_session_id()
    http = _build_http(args, scope, sid)

    urls = [args.url] if args.url else []
    if args.url_file:
        with open(args.url_file, encoding="utf-8") as fh:
            urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not urls:
        log("-", "no URLs given (use positional URL or --url-file)")
        return 2

    target = urlsplit(urls[0]).hostname or "target"
    try:
        items = crawl_light(http, urls)
    except ScopeViolation as exc:
        log("-", str(exc))
        return 3
    new_snap = snapshot_from_items(target, items)

    result = None
    if args.baseline:
        try:
            old_snap = Snapshot.load(args.baseline)
            result = diff_snapshots(old_snap, new_snap)
        except FileNotFoundError:
            log("!", f"baseline {args.baseline} not found — treating as first run")

    out_snap = args.snapshot or f"snapshot_{target}.json"
    new_snap.save(out_snap)
    log("+", f"snapshot saved -> {out_snap}")

    payload = {"target": target, "snapshot_file": out_snap,
               "pages": len(new_snap.pages)}
    if result is not None:
        payload["diff"] = result.to_dict()
        if result.empty:
            log("*", "no changes vs baseline")
        else:
            for ep in result.new_endpoints:
                mark = "!" if ep["score"] else "*"
                log(mark, f"new endpoint {ep['path']} (sensitivity={ep['score']})")
            if result.new_params:
                log("!", f"new params: {', '.join(result.new_params)}")
            for js in result.changed_js:
                log("!", f"changed: {js['url']}")
    _emit_json(args, payload)
    return 0


def cmd_run(args) -> int:
    scope = _build_scope(args)
    sid = new_session_id()
    http = _build_http(args, scope, sid)
    store = StateStore(args.state_db)
    budget = _budget(args)
    timer = BudgetTimer(budget_seconds=budget)

    host = urlsplit(args.url).hostname or args.url
    store.touch_session(sid, host)
    log("*", f"session {sid} target {host} budget {budget:.0f}s")

    # 1) deep fingerprint (home + 404 + OPTIONS)
    try:
        fp = fingerprint_host_deep(http, args.url)
    except ScopeViolation as exc:
        log("-", str(exc))
        store.close()
        return 3
    store.save_fingerprint(fp.host, fp.to_dict())

    # 2) rank + probe safe surface (dedup-filtered, budget-aware)
    base = f"{urlsplit(args.url).scheme}://{host}"
    surface: list[dict] = []
    probe_paths = list(_PROBE_PATHS)   # local copy; never mutate the module list

    # 2a) optional bounded crawl to expand the surface before probing
    crawl_info: dict = {}
    seen_paths: set[str] = set()
    if getattr(args, "crawl", False) and not timer.expired:
        try:
            cres = crawl_site(
                http, [args.url], max_pages=args.crawl_pages, max_depth=1,
                timer=timer, state=store, seed_robots=True)
            crawl_info = cres.to_dict()
            # crawl already fetched these (dedup would skip re-probing), so add
            # the reachable ones straight into the ranked surface.
            for url, code in cres.status.items():
                p = urlsplit(url).path or "/"
                if p in seen_paths:
                    continue
                seen_paths.add(p)
                score = sensitivity(p) + (3 if code and code < 400 else 0)
                surface.append({"path": p, "status": code, "score": score,
                                "src": "crawl"})
                if code and code < 400:
                    store.record_finding(host, "reachable-path",
                                         f"{p} -> {code} (crawl)", "info")
        except ScopeViolation as exc:
            log("-", str(exc))

    for path in probe_paths:
        if timer.expired:
            log("!", f"time budget ({budget:.0f}s) exceeded — stopping probes")
            break
        if path in seen_paths:        # already surfaced by the crawl
            continue
        url = base + path
        if store.seen("GET", url):
            log("*", f"skip (already tested) {path}")
            continue
        try:
            resp = http.head(url)
            code = resp.status_code
        except ScopeViolation:
            continue
        except Exception as exc:  # noqa: BLE001
            log("-", f"probe {path}: {exc}")
            store.mark_tested("GET", url)
            continue
        store.mark_tested("GET", url)
        score = sensitivity(path) + (3 if code and code < 400 else 0)
        if code and code < 400:
            log("+", f"{code} {path} (score {score})")
            store.record_finding(host, "reachable-path",
                                  f"{path} -> {code}", "info")
        surface.append({"path": path, "status": code, "score": score})

    surface.sort(key=lambda d: -d["score"])

    # 3) safe active probes (GET/OPTIONS only), budget + dedup aware
    probes: list[dict] = []
    if not args.no_active and not timer.expired:
        if store.seen("PROBE", args.url):
            log("*", "skip active probes (endpoint already probed)")
        else:
            try:
                for r in run_safe_probes(http, args.url):
                    probes.append(r.to_dict())
                    store.record_finding(host, r.kind, r.detail, r.severity)
                store.mark_tested("PROBE", args.url)
            except ScopeViolation as exc:
                log("-", str(exc))
    elif timer.expired:
        log("!", "skip active probes — time budget exceeded")

    # 4) priority table (console)
    _print_table(host, fp, surface, timer, probes)

    payload = {
        "session_id": sid,
        "target": host,
        "elapsed_seconds": round(timer.elapsed, 2),
        "budget_exceeded": timer.expired,
        "fingerprint": fp.to_dict(),
        "surface": surface,
        "probes": probes,
        "crawl": crawl_info,
        "findings": store.findings(host),
    }
    store.touch_session(sid, host)
    store.close()
    _emit_json(args, payload)
    return 0


def cmd_probe(args) -> int:
    scope = _build_scope(args)
    sid = new_session_id()
    http = _build_http(args, scope, sid)
    store = StateStore(args.state_db)
    host = urlsplit(args.url).hostname or args.url
    store.touch_session(sid, host)
    try:
        results = run_safe_probes(
            http, args.url,
            do_reflection=not args.no_reflection,
            do_redirect=not args.no_redirect,
            do_cors=not args.no_cors,
            do_methods=not args.no_methods,
        )
    except ScopeViolation as exc:
        log("-", str(exc))
        store.close()
        return 3
    for r in results:
        store.record_finding(host, r.kind, r.detail, r.severity)
    store.mark_tested("PROBE", args.url)
    store.close()
    if not results:
        log("*", "no candidates surfaced")
    _emit_json(args, {"target": host, "url": args.url,
                      "probes": [r.to_dict() for r in results]})
    return 0


def cmd_crawl(args) -> int:
    scope = _build_scope(args)
    sid = new_session_id()
    http = _build_http(args, scope, sid)
    store = StateStore(args.state_db)
    timer = BudgetTimer(budget_seconds=_budget(args))

    host = urlsplit(args.url).hostname or args.url
    store.touch_session(sid, host)
    try:
        res = crawl_site(
            http, [args.url],
            max_pages=args.max_pages, max_depth=args.depth,
            timer=timer, state=store, seed_robots=not args.no_robots,
        )
    except ScopeViolation as exc:
        log("-", str(exc))
        store.close()
        return 3

    out_snap = args.snapshot or f"snapshot_{host}.json"
    res.snapshot().save(out_snap)
    log("+", f"snapshot saved -> {out_snap}")
    store.touch_session(sid, host)
    store.close()

    payload = res.to_dict()
    payload["snapshot_file"] = out_snap
    _emit_json(args, payload)
    return 0


def cmd_report(args) -> int:
    store = StateStore(args.state_db)
    host = urlsplit(args.target).hostname or args.target
    fp = store.get_fingerprint(host)
    findings = store.findings(host)
    store.close()
    if fp is None and not findings:
        log("!", f"no stored data for {host} — run 'stoop run' first")
    as_html = args.html or (args.out or "").lower().endswith((".html", ".htm"))
    content = (render_html_report(host, fp, findings) if as_html
               else render_report(host, fp, findings))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(content)
        log("+", f"wrote {'HTML' if as_html else 'Markdown'} report -> {args.out}")
    else:
        print(content)  # stdout
    return 0


def cmd_audit(args) -> int:
    entries = load_audit(args.audit_log)
    if not entries:
        log("!", f"no audit entries in {args.audit_log}")
    summary = summarize_audit(entries)
    print(format_text(summary), file=sys.stderr)
    if summary.blocked:
        log("!", f"{summary.blocked} out-of-scope request(s) were blocked "
                 "(not sent) — good, the scope gate held")
    _emit_json(args, summary.to_dict())
    return 0


def cmd_resume(args) -> int:
    store = StateStore(args.state_db)
    sess = store.resume()
    if not sess:
        log("!", "no previous session found in state DB")
        store.close()
        return 1
    fp = store.get_fingerprint(sess["target"])
    findings = store.findings(sess["target"])
    log("*", f"last session {sess['session_id']} target {sess['target']}")
    log("*", f"{len(findings)} finding(s) recorded")
    store.close()
    _emit_json(args, {"session": sess, "fingerprint": fp, "findings": findings})
    return 0


def _print_table(host, fp, surface, timer, probes=None) -> None:
    line = "-" * 60
    print(line, file=sys.stderr)
    print(f"  PRIORITY SURFACE — {host}", file=sys.stderr)
    print(f"  server={fp.server}  waf={fp.waf}  lang={fp.language}", file=sys.stderr)
    if fp.allowed_methods:
        print(f"  methods: {', '.join(fp.allowed_methods)}", file=sys.stderr)
    if fp.vuln_classes:
        print(f"  vuln-classes: {', '.join(fp.vuln_classes)}", file=sys.stderr)
    if fp.cve_candidates:
        for c in fp.cve_candidates:
            print(f"  CVE? {c['cve']} [{c['confidence']}] {c['desc']}", file=sys.stderr)
    print(line, file=sys.stderr)
    print(f"  {'SCORE':>5}  {'STATUS':>6}  PATH", file=sys.stderr)
    for s in surface:
        print(f"  {s['score']:>5}  {str(s['status']):>6}  {s['path']}", file=sys.stderr)
    if probes:
        print(line, file=sys.stderr)
        print("  ACTIVE-PROBE CANDIDATES (verify manually):", file=sys.stderr)
        for p in probes:
            print(f"  [{p['severity']:>6}] {p['kind']}: {p['detail']}",
                  file=sys.stderr)
    print(line, file=sys.stderr)
    print(f"  elapsed {timer.elapsed:.1f}s / budget {timer.budget_seconds:.0f}s",
          file=sys.stderr)
    print(line, file=sys.stderr)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stoop",
        description=f"PeregrineStoop — authorized blackbox recon accelerator. {BRAND}.",
        epilog="authorized testing only; every request passes a scope gate.",
    )
    p.add_argument("--version", action="version",
                   version=f"PeregrineStoop {__version__} — {BRAND}")
    sub = p.add_subparsers(dest="command", required=True)

    fp = sub.add_parser("fingerprint", help="tech/WAF fingerprint a single URL")
    fp.add_argument("url", help="target URL (must be in scope)")
    _add_common_flags(fp)
    fp.set_defaults(func=cmd_fingerprint)

    df = sub.add_parser("diff", help="snapshot a surface and diff vs a baseline")
    df.add_argument("url", nargs="?", help="single URL to snapshot")
    df.add_argument("--url-file", help="file of URLs to snapshot")
    df.add_argument("--baseline", help="previous snapshot JSON to diff against")
    df.add_argument("--snapshot", help="output snapshot path")
    _add_common_flags(df)
    df.set_defaults(func=cmd_diff)

    rn = sub.add_parser("run", help="full budgeted pipeline against one target")
    rn.add_argument("url", help="target base URL (must be in scope)")
    rn.add_argument("--no-active", action="store_true",
                    help="skip safe active probes (fingerprint + path map only)")
    rn.add_argument("--crawl", action="store_true",
                    help="run a bounded crawl first to expand the probe surface")
    rn.add_argument("--crawl-pages", type=int, default=15,
                    help="max pages for the in-run crawl (default 15)")
    _add_common_flags(rn)
    rn.set_defaults(func=cmd_run)

    pr = sub.add_parser("probe", help="safe active probes (GET/OPTIONS only)")
    pr.add_argument("url", help="target URL (must be in scope)")
    pr.add_argument("--no-reflection", action="store_true")
    pr.add_argument("--no-redirect", action="store_true")
    pr.add_argument("--no-cors", action="store_true")
    pr.add_argument("--no-methods", action="store_true")
    _add_common_flags(pr)
    pr.set_defaults(func=cmd_probe)

    cr = sub.add_parser("crawl", help="bounded, scope-gated link discovery")
    cr.add_argument("url", help="seed URL (must be in scope)")
    cr.add_argument("--depth", type=int, default=1, help="max crawl depth (default 1)")
    cr.add_argument("--max-pages", type=int, default=25,
                    help="max pages to fetch (default 25)")
    cr.add_argument("--no-robots", action="store_true",
                    help="do not seed from robots.txt / sitemap.xml")
    cr.add_argument("--snapshot", help="output snapshot path (chains into `diff`)")
    _add_common_flags(cr)
    cr.set_defaults(func=cmd_crawl)

    rp = sub.add_parser("report", help="render a Markdown recon report from state")
    rp.add_argument("target", help="target host or URL (uses stored data)")
    rp.add_argument("--state-db", default=".stoop_state.sqlite")
    rp.add_argument("--out", metavar="FILE",
                    help="write here (else stdout); .html extension implies --html")
    rp.add_argument("--html", action="store_true",
                    help="render a self-contained HTML page instead of Markdown")
    rp.set_defaults(func=cmd_report)

    au = sub.add_parser("audit", help="summarize the JSONL audit log")
    au.add_argument("--audit-log", default="stoop_audit.jsonl",
                    help="audit log to summarize")
    au.add_argument("--json", metavar="FILE",
                    help="also write the summary JSON to this file")
    au.set_defaults(func=cmd_audit)

    rs = sub.add_parser("resume", help="show the last session's state")
    rs.add_argument("--state-db", default=".stoop_state.sqlite")
    rs.add_argument("--json", metavar="FILE")
    rs.set_defaults(func=cmd_resume)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(_BANNER, file=sys.stderr)
    parser = build_parser()
    args = parser.parse_args(argv)
    # load optional config profile (flags still override it)
    args._cfg = load_config(args.config) if getattr(args, "config", None) else {}
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log("!", "interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
