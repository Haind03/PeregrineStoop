"""Session bundle export tests."""
from __future__ import annotations

import json
import os

from peregrinestoop.bundle import write_bundle


def test_write_bundle_creates_all_files(tmp_path):
    payload = {
        "target": "a.target.com",
        "fingerprint": {"server": "nginx", "vuln_classes": ["lfi"],
                        "cve_candidates": []},
        "findings": [{"severity": "high", "kind": "open-redirect", "detail": "x"}],
    }
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"ts":1}\n', encoding="utf-8")
    out = tmp_path / "bundle"
    files = write_bundle(str(out), payload, audit_path=str(audit))
    names = {os.path.basename(f) for f in files}
    assert {"run.json", "fingerprint.json", "findings.json",
            "report.md", "report.html", "audit.jsonl"} <= names
    assert (out / "report.html").read_text().startswith("<!doctype html>")
    assert json.loads((out / "run.json").read_text())["target"] == "a.target.com"


def test_write_bundle_without_audit(tmp_path):
    out = tmp_path / "b2"
    files = write_bundle(str(out), {"target": "x", "fingerprint": {}, "findings": []})
    assert not any(f.endswith("audit.jsonl") for f in files)
    assert (out / "report.md").exists()
