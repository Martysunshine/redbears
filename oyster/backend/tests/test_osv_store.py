"""GHSA/OSV structured store — idempotent upserts, alias lookup, withdrawal
handling, package/ecosystem filtering."""

from __future__ import annotations

from services.knowledge.vulnerabilities import osv_store as store
from services.knowledge.vulnerabilities.sources.osv_schema import OsvAffectedRange, OsvRecord


def _rec(record_id, **kw):
    defaults = dict(schema_version="1.4.0", summary="s", details="d", published="2024-01-01T00:00:00Z",
                    modified="2024-01-01T00:00:00Z", withdrawn=None, severity_vector=None,
                    severity_type=None, database_severity=None, cwe_ids=[], aliases=[],
                    cve_aliases=[], ghsa_alias=None, references=[], affected=[])
    defaults.update(kw)
    return OsvRecord(record_id=record_id, **defaults)


# ---------------------------------------------------------------------------
# GHSA
# ---------------------------------------------------------------------------

def test_upsert_ghsa_tristate_and_idempotent():
    rec = _rec("GHSA-2345-6789-CFGH", summary="v1")
    assert store.upsert_ghsa(rec, source_url="https://x") == "added"
    assert store.upsert_ghsa(rec, source_url="https://x") == "unchanged"
    rec2 = _rec("GHSA-2345-6789-CFGH", summary="v2 corrected")
    assert store.upsert_ghsa(rec2, source_url="https://x") == "updated"


def test_get_ghsa_returns_aliases_cwes_and_affected():
    rec = _rec("GHSA-2345-6789-CFGJ", summary="Widget vuln", cve_aliases=["CVE-2024-11111"],
              aliases=["CVE-2024-11111"], cwe_ids=["CWE-79"],
              affected=[OsvAffectedRange(ecosystem="npm", package="widget", introduced="0", fixed="2.0.0")])
    store.upsert_ghsa(rec)
    got = store.get_ghsa("GHSA-2345-6789-CFGJ")
    assert got["summary"] == "Widget vuln"
    assert got["aliases"] == ["CVE-2024-11111"]
    assert got["cwe_ids"] == ["CWE-79"]
    assert got["affected"][0]["package"] == "widget"
    assert got["is_withdrawn"] is False


def test_ghsa_withdrawn_flag_set_when_withdrawn_timestamp_present():
    rec = _rec("GHSA-2345-6789-CFGM", withdrawn="2026-01-01T00:00:00Z")
    store.upsert_ghsa(rec)
    got = store.get_ghsa("GHSA-2345-6789-CFGM")
    assert got["is_withdrawn"] is True


def test_find_ghsa_by_cve_alias():
    rec = _rec("GHSA-2345-6789-CFGP", aliases=["CVE-2024-22222"])
    store.upsert_ghsa(rec)
    found = store.find_ghsa_by_alias("CVE-2024-22222")
    assert len(found) == 1
    assert found[0]["ghsa_id"] == "GHSA-2345-6789-CFGP"


def test_search_ghsa_by_package_and_ecosystem():
    store.upsert_ghsa(_rec("GHSA-2345-6789-CFGQ",
                          affected=[OsvAffectedRange(ecosystem="PyPI", package="requests")]))
    store.upsert_ghsa(_rec("GHSA-2345-6789-CFGR",
                          affected=[OsvAffectedRange(ecosystem="npm", package="requests")]))
    results = store.search_ghsa_by_package("PyPI", "requests")
    assert len(results) == 1
    assert results[0]["ghsa_id"] == "GHSA-2345-6789-CFGQ"


def test_ghsa_upsert_replaces_affected_ranges_not_appends():
    store.upsert_ghsa(_rec("GHSA-2345-6789-CFGV",
                          affected=[OsvAffectedRange(ecosystem="npm", package="pkg-a")]))
    store.upsert_ghsa(_rec("GHSA-2345-6789-CFGV", summary="v2",
                          affected=[OsvAffectedRange(ecosystem="npm", package="pkg-b")]))
    got = store.get_ghsa("GHSA-2345-6789-CFGV")
    assert len(got["affected"]) == 1
    assert got["affected"][0]["package"] == "pkg-b"


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

def test_upsert_osv_with_ecosystem_source_tag():
    rec = _rec("PYSEC-2024-1", summary="pysec vuln")
    assert store.upsert_osv(rec, ecosystem_source="PyPI") == "added"
    got = store.get_osv("PYSEC-2024-1")
    assert got["ecosystem_source"] == "PyPI"


def test_osv_alias_lookup_finds_ghsa_mirrored_record():
    rec = _rec("GO-2024-1234", aliases=["CVE-2024-33333"])
    store.upsert_osv(rec, ecosystem_source="Go")
    found = store.find_osv_by_alias("CVE-2024-33333")
    assert len(found) == 1
    assert found[0]["osv_id"] == "GO-2024-1234"


def test_search_osv_by_package():
    store.upsert_osv(_rec("RUSTSEC-2024-0001",
                         affected=[OsvAffectedRange(ecosystem="crates.io", package="mycrate")]),
                     ecosystem_source="crates.io")
    results = store.search_osv_by_package("crates.io", "mycrate")
    assert len(results) == 1


def test_counts_reports_by_ecosystem_and_withdrawal():
    store.upsert_osv(_rec("PYSEC-2024-2"), ecosystem_source="PyPI")
    store.upsert_osv(_rec("GO-2024-5555", withdrawn="2026-01-01T00:00:00Z"), ecosystem_source="Go")
    c = store.counts()
    assert c["osv_by_ecosystem_source"]["PyPI"] >= 1
    assert c["osv_by_ecosystem_source"]["Go"] >= 1
    assert c["osv_withdrawn"] >= 1


def test_sync_state_roundtrip_and_accumulates_total():
    store.set_sync_state("ghsa", status="running", records_seen_delta=10)
    store.set_sync_state("ghsa", status="succeeded", records_seen_delta=5)
    state = store.get_sync_state("ghsa")
    assert state["last_status"] == "succeeded"
    assert state["records_seen_total"] == 15
