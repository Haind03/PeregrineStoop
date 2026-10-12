"""Write a per-engagement session bundle to a directory.

Collects everything a `stoop run` produced — the raw JSON payload, the
fingerprint, the findings, a Markdown and an HTML report, and a copy of the
audit log — into one folder so it can be archived or attached to an engagement
record. Offline: it only writes local files.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

import json
import os
import shutil

from .report import render_html_report, render_report

__all__ = ["write_bundle"]


def _dump_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)


def write_bundle(dirpath: str, payload: dict, audit_path: str | None = None) -> list[str]:
    """Write a run payload into ``dirpath`` as a set of files. Returns paths."""
    os.makedirs(dirpath, exist_ok=True)
    host = payload.get("target", "target")
    fp = payload.get("fingerprint") or {}
    findings = payload.get("findings") or []
    written: list[str] = []

    def _w(name: str, writer) -> None:
        p = os.path.join(dirpath, name)
        writer(p)
        written.append(p)

    _w("run.json", lambda p: _dump_json(p, payload))
    _w("fingerprint.json", lambda p: _dump_json(p, fp))
    _w("findings.json", lambda p: _dump_json(p, findings))
    _w("report.md", lambda p: open(p, "w", encoding="utf-8").write(
        render_report(host, fp, findings)))
    _w("report.html", lambda p: open(p, "w", encoding="utf-8").write(
        render_html_report(host, fp, findings)))

    if audit_path and os.path.exists(audit_path):
        dst = os.path.join(dirpath, "audit.jsonl")
        shutil.copyfile(audit_path, dst)
        written.append(dst)

    return written
