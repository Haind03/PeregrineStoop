"""Version-aware CVE narrowing tests."""
from __future__ import annotations

from peregrinestoop.fingerprint import fingerprint_response, version_matches


def _cves(fp):
    return [c["cve"] for c in fp.cve_candidates]


def test_version_matches_operators():
    assert version_matches("2.4.49", "==2.4.49")
    assert not version_matches("2.4.50", "==2.4.49")
    assert version_matches("8.5.0", "<8.5.1")
    assert not version_matches("8.5.1", "<8.5.1")
    assert version_matches("2.4.30", ">=2.4.0,<2.4.50")
    assert not version_matches("2.5.0", ">=2.4.0,<2.4.50")
    assert version_matches("9.0.30", "<9.0.31")


def test_apache_matching_version_included_and_medium():
    fp = fingerprint_response("t.com", 200, {"Server": "Apache/2.4.49"}, b"")
    assert "CVE-2021-41773" in _cves(fp)
    c = [x for x in fp.cve_candidates if x["cve"] == "CVE-2021-41773"][0]
    assert c["confidence"] == "medium"
    assert "satisfies" in c.get("version_match", "")


def test_apache_non_matching_version_excluded():
    fp = fingerprint_response("t.com", 200, {"Server": "Apache/2.4.59"}, b"")
    assert "CVE-2021-41773" not in _cves(fp)   # version out of range -> dropped


def test_apache_unknown_version_kept_with_note():
    fp = fingerprint_response("t.com", 200, {"Server": "Apache"}, b"")
    cands = [x for x in fp.cve_candidates if x["cve"] == "CVE-2021-41773"]
    assert cands and "version unknown" in cands[0]["note"]


def test_no_affected_entry_unchanged():
    # Spring4Shell has no 'affected' spec -> always listed as a candidate
    fp = fingerprint_response("t.com", 500, {}, b"Whitelabel Error Page")
    assert "CVE-2022-22965" in _cves(fp)
