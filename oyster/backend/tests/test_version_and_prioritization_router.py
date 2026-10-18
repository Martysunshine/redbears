"""Router + answer wiring for the two Cycle V5 query types: deterministic
package-version evaluation and transparent patch prioritization — offline."""

from __future__ import annotations

from services.knowledge import security_answer, security_router
from services.knowledge.vulnerabilities import osv_store
from services.knowledge.vulnerabilities.sources.osv_schema import OsvAffectedRange, OsvRecord


def _install_ghsa(ghsa_id, **kw):
    defaults = dict(schema_version="1.4.0", summary="Widget vuln", details="d",
                    published="2024-01-01T00:00:00Z", modified="2024-01-01T00:00:00Z",
                    withdrawn=None, severity_vector="CVSS:3.1/AV:N", severity_type="CVSS_V3",
                    database_severity="HIGH", cwe_ids=["CWE-79"], aliases=[],
                    cve_aliases=[], ghsa_alias=None, references=[],
                    affected=[OsvAffectedRange(ecosystem="npm", package="widget-lib",
                                               introduced="0", fixed="2.0.0")])
    defaults.update(kw)
    rec = OsvRecord(record_id=ghsa_id, **defaults)
    osv_store.upsert_ghsa(rec)


# ---------------------------------------------------------------------------
# classify() — version-check detection
# ---------------------------------------------------------------------------

def test_classify_detects_version_query():
    decision = security_router.classify(
        "is the npm package widget-lib version 1.5.0 vulnerable")
    assert decision["route"] == security_router.ROUTE_VERSION_CHECK
    assert decision["version_query"] == {"ecosystem": "npm", "package": "widget-lib", "version": "1.5.0"}


def test_classify_package_query_without_version_stays_package_route():
    decision = security_router.classify("what vulnerabilities affect the npm package widget-lib")
    assert decision["route"] == security_router.ROUTE_PACKAGE


def test_classify_version_query_requires_version_keyword():
    # a bare version-shaped number with no "version" keyword must not force
    # the version-check route — it's still just a package query.
    decision = security_router.classify("vulnerabilities in the npm package widget-lib 1.5.0")
    assert decision["route"] == security_router.ROUTE_PACKAGE


# ---------------------------------------------------------------------------
# classify() — prioritization detection
# ---------------------------------------------------------------------------

def test_classify_prioritization_with_cve_identifiers():
    decision = security_router.classify(
        "what should I patch first: CVE-2024-11111 or CVE-2024-22222?")
    assert decision["route"] == security_router.ROUTE_PRIORITIZATION
    assert decision["identifiers"]["cve"] == ["CVE-2024-11111", "CVE-2024-22222"]


def test_classify_prioritization_without_any_identifier():
    decision = security_router.classify("help me prioritize these vulnerabilities")
    assert decision["route"] == security_router.ROUTE_PRIORITIZATION
    assert decision["identifiers"]["cve"] == []


def test_classify_bare_cve_without_prioritization_phrase_is_exact_lookup():
    decision = security_router.classify("what is CVE-2024-11111")
    assert decision["route"] == security_router.ROUTE_EXACT_LOOKUP


# ---------------------------------------------------------------------------
# route_and_retrieve + answer — version check
# ---------------------------------------------------------------------------

async def test_version_check_end_to_end_vulnerable():
    _install_ghsa("GHSA-2222-2222-2222")
    routed = await security_router.route_and_retrieve(
        "is the npm package widget-lib version 1.0.0 vulnerable")
    assert routed["route"] == security_router.ROUTE_VERSION_CHECK
    assert routed["results"]["status"] == "vulnerable"
    assert routed["results"]["fixed_versions"] == ["2.0.0"]

    answer = await security_answer.answer("is the npm package widget-lib version 1.0.0 vulnerable")
    assert answer["route"] == security_router.ROUTE_VERSION_CHECK
    assert "Fixed in: 2.0.0" in answer["direct_answer"]


async def test_version_check_end_to_end_not_found():
    answer = await security_answer.answer(
        "is the npm package never-installed-anywhere version 1.0.0 vulnerable")
    assert answer["status"] == "not_found"
    assert "not evidence" in answer["direct_answer"]


# ---------------------------------------------------------------------------
# route_and_retrieve + answer — prioritization
# ---------------------------------------------------------------------------

async def test_prioritization_no_identifiers_explains_itself():
    answer = await security_answer.answer("help me prioritize these vulnerabilities")
    assert answer["route"] == security_router.ROUTE_PRIORITIZATION
    assert answer["ranked"] == []
    assert "name one or more CVE ids" in answer["direct_answer"]


async def test_prioritization_unknown_cve_reported_not_fabricated():
    answer = await security_answer.answer("what should I patch first: CVE-9999-99999")
    assert "CVE-9999-99999" in answer["not_found"]
    assert answer["ranked"][0]["found"] is False
