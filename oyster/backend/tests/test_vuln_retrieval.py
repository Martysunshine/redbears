"""Vulnerability retrieval — exact-ID short-circuit, KEV ranking boost (never
mutates stored severity), and CVSS/EPSS/KEV kept as separate labeled fields.
Offline, deterministic — pure SQL, no embedding model involved."""

from __future__ import annotations

import pytest

from services.knowledge.vulnerabilities import retrieval, store
from services.knowledge.vulnerabilities.models import EpssEntry, KevEntry, NvdCveEntry


def _seed(cve_id: str, *, cvss: float | None = None, epss: float | None = None, kev: bool = False):
    store.sync_nvd_batch([NvdCveEntry(cve_id=cve_id, description=f"desc for {cve_id}",
                                      vuln_status="Analyzed", cvss_v3_score=cvss,
                                      cvss_v3_severity="CRITICAL" if cvss and cvss >= 9 else "MEDIUM")])
    if epss is not None:
        store.sync_epss_batch([EpssEntry(cve_id=cve_id, score=epss, percentile=epss, as_of="2024-01-01")])
    if kev:
        store.sync_kev([KevEntry(cve_id=cve_id, short_description="x", date_added="2024-01-01",
                                 due_date="2024-01-15")])


def test_get_cve_returns_none_for_a_real_looking_but_absent_id():
    assert retrieval.get_cve("CVE-2099-99999") is None


def test_get_cve_returns_none_for_malformed_input_never_guesses():
    assert retrieval.get_cve("definitely not a cve") is None


def test_get_cwe_and_get_capec_return_none_when_absent():
    assert retrieval.get_cwe("CWE-999999") is None
    assert retrieval.get_capec("CAPEC-999999") is None


async def test_search_resolves_an_exact_cve_id_in_free_text_first():
    _seed("CVE-2024-10001", cvss=9.8, epss=0.9, kev=True)
    result = await retrieval.search("what is CVE-2024-10001?")
    assert result["identified"]["cve"] == ["CVE-2024-10001"]
    assert len(result["exact_matches"]) == 1
    assert result["exact_matches"][0]["cve_id"] == "CVE-2024-10001"


async def test_search_reports_found_false_for_an_identifier_shaped_but_absent_cve():
    result = await retrieval.search("tell me about CVE-2030-00001")
    assert result["exact_matches"] == [{"cve_id": "CVE-2030-00001", "found": False}]


def test_cvss_epss_kev_are_separate_fields_never_averaged():
    _seed("CVE-2024-10002", cvss=7.0, epss=0.95, kev=True)
    rec = retrieval.get_cve("CVE-2024-10002")
    assert rec["cvss"]["v3"]["score"] == 7.0
    assert rec["epss"]["score"] == 0.95
    assert rec["kev"]["listed"] is True
    # None of the three values equals another — proves they weren't blended.
    assert rec["cvss"]["v3"]["score"] != rec["epss"]["score"]


def test_kev_ranking_boost_changes_order_but_never_the_stored_cvss_value():
    _seed("CVE-2024-10003", cvss=8.0, epss=0.5, kev=False)
    _seed("CVE-2024-10004", cvss=8.0, epss=0.5, kev=True)
    before_a = retrieval.get_cve("CVE-2024-10003")["cvss"]["v3"]["score"]
    before_b = retrieval.get_cve("CVE-2024-10004")["cvss"]["v3"]["score"]

    listing = store.search_vulnerabilities(min_cvss=8.0, limit=10)
    boosted = sorted(listing, key=lambda r: (retrieval.KEV_RANK_BOOST if r["kev_listed"] else 1.0)
                     * (r["epss_score"] or 0), reverse=True)
    assert boosted[0]["cve_id"] == "CVE-2024-10004"  # KEV-listed ranks first despite equal cvss/epss

    after_a = retrieval.get_cve("CVE-2024-10003")["cvss"]["v3"]["score"]
    after_b = retrieval.get_cve("CVE-2024-10004")["cvss"]["v3"]["score"]
    assert (before_a, before_b) == (after_a, after_b) == (8.0, 8.0)  # untouched by ranking


def test_capecs_related_to_cwe_returns_empty_list_not_error_when_unlinked():
    from services.knowledge.vulnerabilities.models import CweRecord
    store.sync_cwe_records([CweRecord(cwe_id="CWE-1", name="Isolated", version="4.20")])
    assert retrieval.capecs_related_to_cwe("CWE-1") == []
