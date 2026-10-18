"""Schema/migration idempotency + CVE-keyed column-scoped merge — offline,
deterministic, uses the temp DB the conftest fixtures redirect to."""

from __future__ import annotations

from services.knowledge.vulnerabilities import store
from services.knowledge.vulnerabilities.models import CapecRecord, CweRecord, EpssEntry, KevEntry, NvdCveEntry


def test_init_db_is_idempotent_and_preserves_existing_rows():
    store.init_db()
    store.sync_kev([KevEntry(cve_id="CVE-2024-00001", short_description="x", date_added="2024-01-01")])
    store.init_db()  # re-run migrations
    store.init_db()  # and again
    rec = store.get_vulnerability("CVE-2024-00001")
    assert rec is not None
    assert rec["kev_listed"] is True or rec["kev_listed"] == 1


def test_kev_then_nvd_then_epss_merge_onto_the_same_row_without_clobbering():
    store.sync_kev([KevEntry(cve_id="CVE-2024-00002", short_description="KEV desc",
                             date_added="2024-01-01", due_date="2024-01-15",
                             vulnerability_name="Test Vuln", required_action="Patch it",
                             known_ransomware="Known", cwe_ids=["CWE-79"])])
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00002", vuln_status="Analyzed",
                                      description="NVD authoritative description",
                                      cvss_v3_score=9.8, cvss_v3_severity="CRITICAL",
                                      cvss_v3_vector="CVSS:3.1/AV:N", cwe_ids=["CWE-89"])])
    store.sync_epss_batch([EpssEntry(cve_id="CVE-2024-00002", score=0.87, percentile=0.95, as_of="2024-02-01")])

    rec = store.get_vulnerability("CVE-2024-00002")
    # NVD's description/CVSS survived (KEV never overwrote them).
    assert rec["description"] == "NVD authoritative description"
    assert rec["cvss_v3_score"] == 9.8
    # KEV's columns survived (NVD sync never touched them).
    assert rec["kev_listed"] == 1
    assert rec["kev_due_date"] == "2024-01-15"
    assert rec["kev_known_ransomware"] == "Known"
    # EPSS's columns survived.
    assert rec["epss_score"] == 0.87
    # CWE links from BOTH sources are present (union, not overwrite).
    assert set(rec["cwe_ids"]) == {"CWE-79", "CWE-89"}


def test_kev_stub_row_flagged_needs_nvd_backfill_until_nvd_arrives():
    store.sync_kev([KevEntry(cve_id="CVE-2024-00003", short_description="stub", date_added="2024-01-01")])
    stub = store.get_vulnerability("CVE-2024-00003")
    assert stub["needs_nvd_backfill"] == 1

    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00003", description="now real", vuln_status="Analyzed")])
    filled = store.get_vulnerability("CVE-2024-00003")
    assert filled["needs_nvd_backfill"] == 0
    assert filled["description"] == "now real"


def test_epss_creates_a_stub_row_when_nvd_has_not_synced_yet():
    store.sync_epss_batch([EpssEntry(cve_id="CVE-2024-00004", score=0.5, percentile=0.5, as_of="2024-01-01")])
    rec = store.get_vulnerability("CVE-2024-00004")
    assert rec is not None
    assert rec["epss_score"] == 0.5
    assert rec["description"] is None


def test_nvd_resync_never_blanks_a_good_field_with_an_empty_one():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00006", description="rich description",
                                      vuln_status="Analyzed", cvss_v3_score=8.1,
                                      cvss_v3_severity="HIGH", cvss_v3_vector="CVSS:3.1/AV:N",
                                      cvss_source="nvd@nist.gov")])
    # A later, sparser fetch (e.g. a transient partial response) must not
    # clobber the richer data already on file.
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00006", description=None,
                                      vuln_status="Analyzed", cvss_v3_score=None,
                                      cvss_v3_severity=None, cvss_v3_vector=None, cvss_source=None)])
    rec = store.get_vulnerability("CVE-2024-00006")
    assert rec["description"] == "rich description"
    assert rec["cvss_v3_score"] == 8.1
    assert rec["cvss_source"] == "nvd@nist.gov"


def test_nvd_resync_does_apply_a_real_new_value_over_an_old_one():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00007", description="v1", cvss_v3_score=5.0)])
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00007", description="v2 corrected", cvss_v3_score=9.0)])
    rec = store.get_vulnerability("CVE-2024-00007")
    assert rec["description"] == "v2 corrected"
    assert rec["cvss_v3_score"] == 9.0


def test_nvd_resync_always_applies_vuln_status_transition_even_to_rejected():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00008", description="d", vuln_status="Analyzed")])
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00008", description="d", vuln_status="Rejected")])
    rec = store.get_vulnerability("CVE-2024-00008")
    assert rec["vuln_status"] == "Rejected"
    assert rec["is_active"] == 0


def test_cvss_v4_columns_stored_and_retrieved():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00010", cvss_v4_score=6.9,
                                      cvss_v4_severity="MEDIUM", cvss_v4_vector="CVSS:4.0/AV:N")])
    rec = store.get_vulnerability("CVE-2024-00010")
    assert rec["cvss_v4_score"] == 6.9
    assert rec["cvss_v4_severity"] == "MEDIUM"


def test_multi_source_cvss_scores_preserved_even_when_they_disagree():
    entry = NvdCveEntry(cve_id="CVE-2024-00011", cvss_v3_score=10.0, cvss_source="nvd@nist.gov",
                        all_cvss_scores=[
                            {"source": "nvd@nist.gov", "cvss_version": "3.1", "vector": "CVSS:3.1/AV:N",
                             "score": 10.0, "severity": "CRITICAL", "type": "Primary"},
                            {"source": "cna@example.com", "cvss_version": "3.1", "vector": "CVSS:3.1/AV:L",
                             "score": 6.5, "severity": "MEDIUM", "type": "Secondary"},
                        ])
    store.sync_nvd_batch([entry])
    scores = store.get_cvss_scores_for_cve("CVE-2024-00011")
    assert len(scores) == 2
    by_source = {s["source"]: s["score"] for s in scores}
    assert by_source["nvd@nist.gov"] == 10.0
    assert by_source["cna@example.com"] == 6.5


def test_multi_source_cvss_scores_upsert_not_duplicate_on_resync():
    entry = NvdCveEntry(cve_id="CVE-2024-00012", all_cvss_scores=[
        {"source": "nvd@nist.gov", "cvss_version": "3.1", "vector": "v", "score": 5.0,
         "severity": "MEDIUM", "type": "Primary"},
    ])
    store.sync_nvd_batch([entry])
    entry2 = NvdCveEntry(cve_id="CVE-2024-00012", all_cvss_scores=[
        {"source": "nvd@nist.gov", "cvss_version": "3.1", "vector": "v2", "score": 7.0,
         "severity": "HIGH", "type": "Primary"},
    ])
    store.sync_nvd_batch([entry2])
    scores = store.get_cvss_scores_for_cve("CVE-2024-00012")
    assert len(scores) == 1
    assert scores[0]["score"] == 7.0


def test_kev_delisting_tombstones_kev_columns_but_keeps_nvd_data():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00005", description="keep me", vuln_status="Analyzed")])
    store.sync_kev([KevEntry(cve_id="CVE-2024-00005", short_description="was listed", date_added="2024-01-01")])
    assert store.get_vulnerability("CVE-2024-00005")["kev_listed"] == 1

    # Re-sync KEV WITHOUT this CVE in the incoming catalog -> tombstone.
    store.sync_kev([KevEntry(cve_id="CVE-2024-00099", short_description="unrelated", date_added="2024-01-01")])
    rec = store.get_vulnerability("CVE-2024-00005")
    assert rec["kev_listed"] == 0
    assert rec["kev_due_date"] is None
    assert rec["description"] == "keep me"  # NVD data untouched by the tombstone


def test_kev_reimporting_identical_data_reports_unchanged_not_updated():
    entry = KevEntry(cve_id="CVE-2024-00006", short_description="x", date_added="2024-01-01",
                     due_date="2024-01-15")
    first = store.sync_kev([entry])
    assert first["added"] == 1
    second = store.sync_kev([entry])
    assert second["added"] == 0
    assert second["updated"] == 0
    assert second["unchanged"] == 1


def test_epss_reimporting_identical_scores_is_a_noop():
    entry = EpssEntry(cve_id="CVE-2024-00007", score=0.42, percentile=0.6, as_of="2024-01-01")
    first = store.sync_epss_batch([entry])
    assert first["added"] == 1
    second = store.sync_epss_batch([entry])
    assert second["unchanged"] == 1
    assert second["updated"] == 0


def test_cve_id_is_a_real_primary_key_no_duplicates_possible():
    store.sync_kev([KevEntry(cve_id="CVE-2024-00008", short_description="a")])
    store.sync_kev([KevEntry(cve_id="CVE-2024-00008", short_description="b")])
    con = store.conn()
    n = con.execute("SELECT COUNT(*) c FROM vulnerability_records WHERE cve_id='CVE-2024-00008'").fetchone()["c"]
    con.close()
    assert n == 1


def test_cwe_sync_is_diffed_by_content_hash():
    rec = CweRecord(cwe_id="CWE-79", name="XSS", description="desc", version="4.20")
    first = store.sync_cwe_records([rec])
    assert first["added"] == 1
    second = store.sync_cwe_records([rec])
    assert second["unchanged"] == 1
    assert second["updated"] == 0
    changed = CweRecord(cwe_id="CWE-79", name="XSS", description="new desc", version="4.21")
    third = store.sync_cwe_records([changed])
    assert third["updated"] == 1


def test_capec_sync_populates_cwe_links():
    rec = CapecRecord(capec_id="CAPEC-66", name="SQL Injection", related_weaknesses=["CWE-89"], version="3.9")
    store.sync_capec_records([rec])
    con = store.conn()
    row = con.execute("SELECT * FROM capec_cwe_links WHERE capec_id='CAPEC-66' AND cwe_id='CWE-89'").fetchone()
    con.close()
    assert row is not None


def test_search_vulnerabilities_excludes_inactive_records():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-00009", description="rejected one",
                                      vuln_status="Rejected", cvss_v3_score=9.0)])
    results = store.search_vulnerabilities(min_cvss=1.0, limit=50)
    assert all(r["cve_id"] != "CVE-2024-00009" for r in results)
