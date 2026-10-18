"""GHSA/OSV router + answer wiring: exact-identifier routing, package/
ecosystem query detection, and never-fabricated answers — offline."""

from __future__ import annotations

from services.knowledge import security_answer, security_router
from services.knowledge.vulnerabilities import osv_store
from services.knowledge.vulnerabilities.sources.osv_schema import OsvAffectedRange, OsvRecord


def _install_ghsa(ghsa_id, **kw):
    defaults = dict(schema_version="1.4.0", summary="Widget vuln", details="d",
                    published="2024-01-01T00:00:00Z", modified="2024-01-01T00:00:00Z",
                    withdrawn=None, severity_vector="CVSS:3.1/AV:N", severity_type="CVSS_V3",
                    database_severity="HIGH", cwe_ids=["CWE-79"], aliases=["CVE-2024-88001"],
                    cve_aliases=["CVE-2024-88001"], ghsa_alias=None, references=[],
                    affected=[OsvAffectedRange(ecosystem="npm", package="widget-lib",
                                               introduced="0", fixed="2.0.0")])
    defaults.update(kw)
    rec = OsvRecord(record_id=ghsa_id, **defaults)
    osv_store.upsert_ghsa(rec)


def _install_osv(osv_id, ecosystem_source, **kw):
    defaults = dict(schema_version="1.4.0", summary="pysec vuln", details="d", published=None,
                    modified=None, withdrawn=None, severity_vector=None, severity_type=None,
                    database_severity="MEDIUM", cwe_ids=[], aliases=[], cve_aliases=[],
                    ghsa_alias=None, references=[],
                    affected=[OsvAffectedRange(ecosystem="PyPI", package="requests-mock-lib",
                                               fixed="1.5.0")])
    defaults.update(kw)
    rec = OsvRecord(record_id=osv_id, **defaults)
    osv_store.upsert_osv(rec, ecosystem_source=ecosystem_source)


# ---------------------------------------------------------------------------
# Identifier extraction + classify
# ---------------------------------------------------------------------------

def test_extract_identifiers_finds_ghsa_and_osv():
    ids = security_router.extract_identifiers("See GHSA-2345-6789-cfgh and PYSEC-2024-1")
    assert ids["ghsa"] == ["GHSA-2345-6789-CFGH"]
    assert ids["osv"] == ["PYSEC-2024-1"]


def test_classify_routes_ghsa_to_exact_lookup():
    decision = security_router.classify("What is GHSA-2345-6789-cfgh?")
    assert decision["route"] == security_router.ROUTE_EXACT_LOOKUP
    assert decision["identifiers"]["ghsa"] == ["GHSA-2345-6789-CFGH"]


def test_classify_routes_osv_to_exact_lookup():
    decision = security_router.classify("Tell me about PYSEC-2024-1")
    assert decision["route"] == security_router.ROUTE_EXACT_LOOKUP
    assert decision["identifiers"]["osv"] == ["PYSEC-2024-1"]


def test_classify_detects_package_ecosystem_query():
    decision = security_router.classify("what vulnerabilities affect the npm package left-pad")
    assert decision["route"] == security_router.ROUTE_PACKAGE
    assert decision["package_query"] == {"ecosystem": "npm", "package": "left-pad"}


def test_classify_does_not_force_package_route_on_bare_ecosystem_mention():
    decision = security_router.classify("what are npm best practices for supply chain security")
    assert decision["route"] != security_router.ROUTE_PACKAGE


def test_classify_package_query_pypi_library_phrasing():
    decision = security_router.classify("are there CVEs in the PyPI library requests")
    assert decision["route"] == security_router.ROUTE_PACKAGE
    assert decision["package_query"]["ecosystem"] == "PyPI"
    assert decision["package_query"]["package"] == "requests"


# ---------------------------------------------------------------------------
# resolve_exact
# ---------------------------------------------------------------------------

def test_resolve_exact_ghsa_found_and_not_found():
    _install_ghsa("GHSA-2345-6789-CFGH")
    resolved = security_router.resolve_exact({"cve": [], "cwe": [], "capec": [], "attack": [],
                                              "d3fend": [], "nist_control": [],
                                              "ghsa": ["GHSA-2345-6789-CFGH", "GHSA-9999-9999-9999"],
                                              "osv": []})
    found = [r for r in resolved["ghsa"] if r.get("found") is not False]
    not_found = [r for r in resolved["ghsa"] if r.get("found") is False]
    assert len(found) == 1
    assert found[0]["ghsa_id"] == "GHSA-2345-6789-CFGH"
    assert len(not_found) == 1
    assert not_found[0]["ghsa_id"] == "GHSA-9999-9999-9999"  # never fabricated


def test_resolve_exact_osv_found_and_not_found():
    _install_osv("PYSEC-2024-1", "PyPI")
    resolved = security_router.resolve_exact({"cve": [], "cwe": [], "capec": [], "attack": [],
                                              "d3fend": [], "nist_control": [], "ghsa": [],
                                              "osv": ["PYSEC-2024-1", "GO-9999-9999"]})
    found = [r for r in resolved["osv"] if r.get("found") is not False]
    not_found = [r for r in resolved["osv"] if r.get("found") is False]
    assert len(found) == 1
    assert len(not_found) == 1


# ---------------------------------------------------------------------------
# Answer formatting — never fabricates, surfaces withdrawal/fixed-versions
# ---------------------------------------------------------------------------

def test_answer_ghsa_surfaces_fixed_version_and_cve_alias():
    _install_ghsa("GHSA-2345-6789-CFGJ")
    resolved = security_router.resolve_exact({"cve": [], "cwe": [], "capec": [], "attack": [],
                                              "d3fend": [], "nist_control": [],
                                              "ghsa": ["GHSA-2345-6789-CFGJ"], "osv": []})
    payload = security_answer._exact_lookup_answer(resolved)
    item = payload["items"][0]
    assert item["identifier"] == "GHSA-2345-6789-CFGJ"
    assert "2.0.0" in item["defensive_actions"]
    assert "CVE-2024-88001" in item["severity_and_exploitation"]


def test_answer_ghsa_withdrawn_is_clearly_labeled():
    _install_ghsa("GHSA-2345-6789-CFGM", withdrawn="2026-01-01T00:00:00Z")
    resolved = security_router.resolve_exact({"cve": [], "cwe": [], "capec": [], "attack": [],
                                              "d3fend": [], "nist_control": [],
                                              "ghsa": ["GHSA-2345-6789-CFGM"], "osv": []})
    payload = security_answer._exact_lookup_answer(resolved)
    item = payload["items"][0]
    assert item["is_withdrawn"] is True
    assert "WITHDRAWN" in item["direct_answer"]


def test_answer_never_fabricates_unknown_ghsa_or_osv():
    resolved = security_router.resolve_exact({"cve": [], "cwe": [], "capec": [], "attack": [],
                                              "d3fend": [], "nist_control": [],
                                              "ghsa": ["GHSA-0000-0000-0000"], "osv": ["ZZZZ-0000-0"]})
    payload = security_answer._exact_lookup_answer(resolved)
    assert payload["items"] == []
    assert "GHSA-0000-0000-0000" in payload["confidence"]["data_gap_warning"] \
        or payload["confidence"]["level"] == "none"


def test_package_answer_found_and_not_found():
    _install_ghsa("GHSA-2345-6789-CFGP", affected=[OsvAffectedRange(ecosystem="npm", package="leftish-pad")])
    found = security_answer._package_answer({
        "ecosystem": "npm", "package": "leftish-pad",
        "ghsa": [osv_store.search_ghsa_by_package("npm", "leftish-pad")[0]], "osv": [], "found": True,
    })
    assert found["items"]
    assert "1 advisory" in found["direct_answer"]

    empty = security_answer._package_answer({"ecosystem": "npm", "package": "nope-pkg",
                                             "ghsa": [], "osv": [], "found": False})
    assert empty["items"] == []
    assert "No GHSA or OSV advisory" in empty["direct_answer"]
