"""Fingerprint inference tests from synthetic responses (no network)."""
from __future__ import annotations

from peregrinestoop.fingerprint import fingerprint_response


def _names(fp):
    return [t["name"] for t in fp.tech]


def test_php_via_cookie_and_powered_by():
    fp = fingerprint_response(
        "t.com", 200,
        {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/8.1.2",
         "Set-Cookie": "PHPSESSID=abc; path=/"},
        b"<html></html>",
    )
    assert fp.language == "php"
    assert any("PHP" in n for n in _names(fp))
    assert "lfi" in fp.vuln_classes or "sqli" in fp.vuln_classes
    # Apache 2.4.49 CVE candidate should be routed (low-confidence)
    assert any(c["cve"] == "CVE-2021-41773" for c in fp.cve_candidates)


def test_java_jsessionid():
    fp = fingerprint_response(
        "t.com", 200, {"Set-Cookie": "JSESSIONID=xyz"}, b"",
    )
    assert fp.language == "java"
    assert "deserialization" in fp.vuln_classes


def test_cloudflare_waf_detection():
    fp = fingerprint_response(
        "t.com", 403,
        {"Server": "cloudflare", "CF-RAY": "abc123"},
        b"Attention Required! | Cloudflare",
    )
    assert fp.waf == "Cloudflare" or fp.cdn == "Cloudflare"
    assert any(t["name"] == "Cloudflare" for t in fp.tech)


def test_imperva_via_cookie():
    fp = fingerprint_response(
        "t.com", 200, {"Set-Cookie": "visid_incap_123=foo; incap_ses_1=bar"}, b"",
    )
    assert fp.waf == "Imperva Incapsula"


def test_wordpress_body_detection():
    fp = fingerprint_response(
        "t.com", 200, {}, b"<link href='/wp-content/themes/x/style.css'>",
    )
    assert any(t["name"] == "WordPress" for t in fp.tech)
    assert "xmlrpc" in fp.vuln_classes


def test_version_parsed_is_high_confidence_note():
    fp = fingerprint_response("t.com", 200, {"Server": "nginx/1.18.0"}, b"")
    nginx = [t for t in fp.tech if "nginx" in t["name"]][0]
    assert nginx["confidence"] == "high"
    assert any("1.18.0" in n for n in fp.notes)


def test_no_signatures_is_empty_but_valid():
    fp = fingerprint_response("t.com", 200, {"Server": "unknownsrv"}, b"")
    assert fp.server == "unknownsrv"
    assert fp.waf is None
