"""CVE / CWE / CAPEC identifier validation and normalization — offline, deterministic."""

from __future__ import annotations

from services.knowledge.vulnerabilities import identity


def test_normalize_cve_accepts_canonical_and_bare_forms():
    assert identity.normalize_cve("CVE-2021-44228") == "CVE-2021-44228"
    assert identity.normalize_cve("cve-2021-44228") == "CVE-2021-44228"
    assert identity.normalize_cve("2021-44228") == "CVE-2021-44228"


def test_normalize_cve_rejects_malformed_input():
    assert identity.normalize_cve("not-a-cve") is None
    assert identity.normalize_cve("CVE-21-4") is None
    assert identity.normalize_cve("") is None
    assert identity.normalize_cve(None) is None


def test_normalize_cwe_accepts_bare_number_and_string():
    assert identity.normalize_cwe(79) == "CWE-79"
    assert identity.normalize_cwe("79") == "CWE-79"
    assert identity.normalize_cwe("CWE-79") == "CWE-79"
    assert identity.normalize_cwe("cwe-79") == "CWE-79"


def test_normalize_cwe_rejects_non_numeric():
    assert identity.normalize_cwe("CWE-abc") is None
    assert identity.normalize_cwe("NVD-CWE-noinfo") is None
    assert identity.normalize_cwe(None) is None


def test_normalize_capec_accepts_bare_number_and_string():
    assert identity.normalize_capec(66) == "CAPEC-66"
    assert identity.normalize_capec("CAPEC-66") == "CAPEC-66"


def test_find_identifiers_extracts_all_three_from_free_text():
    text = "See CVE-2021-44228, related to CWE-502 and cwe-917, exploited via CAPEC-586."
    ids = identity.find_identifiers(text)
    assert ids["cve"] == ["CVE-2021-44228"]
    assert ids["cwe"] == ["CWE-502", "CWE-917"]
    assert ids["capec"] == ["CAPEC-586"]


def test_find_identifiers_empty_text_returns_empty_lists():
    ids = identity.find_identifiers("")
    assert ids == {"cve": [], "cwe": [], "capec": [], "ghsa": [], "osv": []}


def test_find_identifiers_never_invents_an_id_from_plain_text():
    ids = identity.find_identifiers("Tell me about cross-site scripting and SQL injection.")
    assert ids == {"cve": [], "cwe": [], "capec": [], "ghsa": [], "osv": []}


def test_normalize_ghsa_accepts_real_shape_and_rejects_garbage():
    assert identity.normalize_ghsa("GHSA-23rx-79r7-6cpx") == "GHSA-23RX-79R7-6CPX"
    assert identity.normalize_ghsa("not-a-ghsa-id") is None
    assert identity.normalize_ghsa(None) is None


def test_normalize_osv_id_accepts_known_families_and_rejects_prose():
    assert identity.normalize_osv_id("PYSEC-2024-1") == "PYSEC-2024-1"
    assert identity.normalize_osv_id("GO-2024-1234") == "GO-2024-1234"
    assert identity.normalize_osv_id("this is not an id") is None


def test_find_identifiers_extracts_ghsa_and_osv_and_does_not_double_count():
    text = "See GHSA-23rx-79r7-6cpx and PYSEC-2024-1 for details."
    ids = identity.find_identifiers(text)
    assert ids["ghsa"] == ["GHSA-23RX-79R7-6CPX"]
    assert ids["osv"] == ["PYSEC-2024-1"]
