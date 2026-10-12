"""Export findings as SARIF 2.1.0 for pipeline ingestion.

SARIF is the format GitHub Code Scanning and many tools consume. PeregrineStoop
findings are recon candidates (not confirmed vulnerabilities), so every result
is labelled as a candidate in its message and carries the finding severity and
confidence in properties. Locations point at the target host.

Author: HaiND from the Post and Telecommunication Institute of Technology
"""
from __future__ import annotations

from . import __version__

__all__ = ["to_sarif"]

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Haind03/PeregrineStoop"

# finding severity -> SARIF result level
_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule_id(kind: str) -> str:
    return kind or "finding"


def to_sarif(host: str, findings: list[dict]) -> dict:
    """Build a SARIF 2.1.0 document from stored findings. Pure / testable."""
    uri = f"https://{host}/" if host and "://" not in host else (host or "")

    # one rule per distinct finding kind
    rules: list[dict] = []
    seen: set[str] = set()
    for f in findings:
        rid = _rule_id(f.get("kind", ""))
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({
            "id": rid,
            "name": rid.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": f"PeregrineStoop {rid} candidate"},
            "helpUri": _INFO_URI,
            "defaultConfiguration": {
                "level": _LEVEL.get((f.get("severity") or "info").lower(), "note")
            },
        })

    results: list[dict] = []
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        results.append({
            "ruleId": _rule_id(f.get("kind", "")),
            "level": _LEVEL.get(sev, "note"),
            "message": {"text": f"[candidate to verify] {f.get('detail', '')}"},
            "properties": {"severity": sev,
                           "confidence": f.get("confidence", "")},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": uri}}
            }],
        })

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PeregrineStoop",
                "version": __version__,
                "informationUri": _INFO_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    }
