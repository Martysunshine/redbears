"""OS-distro fix cross-reference on CVE answers: Debian/Alpine package-level
fix info surfaced via each OSV record's own real CVE alias — never inferred,
never surfaced for an ecosystem that isn't installed (Ubuntu)."""

from __future__ import annotations

from services.knowledge import security_answer
from services.knowledge.vulnerabilities import osv_store, retrieval, store
from services.knowledge.vulnerabilities.models import NvdCveEntry
from services.knowledge.vulnerabilities.sources.osv_schema import OsvAffectedRange, OsvRecord


def _osv_rec(rid, ecosystem, package, fixed=None, withdrawn=None, cve_alias="CVE-2026-70001"):
    return OsvRecord(
        record_id=rid, schema_version="1.6.0", summary="distro pkg vuln", details=None,
        published="2026-01-01T00:00:00Z", modified="2026-01-01T00:00:00Z", withdrawn=withdrawn,
        aliases=[cve_alias], cve_aliases=[cve_alias], ghsa_alias=None, cwe_ids=[], references=[],
        affected=[OsvAffectedRange(ecosystem=ecosystem, package=package, introduced="0", fixed=fixed)],
    )


def test_get_cve_surfaces_debian_and_alpine_fixes():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2026-70001", description="d")])
    osv_store.upsert_osv(_osv_rec("OSV-DEB-1", "Debian", "libexample", fixed="1:2.3-1"),
                         ecosystem_source="Debian")
    osv_store.upsert_osv(_osv_rec("OSV-ALP-1", "Alpine", "libexample", fixed="2.3-r1"),
                         ecosystem_source="Alpine")
    rec = retrieval.get_cve("CVE-2026-70001")
    distros = {d["distro"] for d in rec["distro_fixes"]}
    assert distros == {"Debian", "Alpine"}
    fixed = {d["distro"]: d["fixed"] for d in rec["distro_fixes"]}
    assert fixed["Debian"] == "1:2.3-1"
    assert fixed["Alpine"] == "2.3-r1"


def test_get_cve_excludes_non_distro_ecosystem_and_withdrawn():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2026-70002", description="d")])
    osv_store.upsert_osv(_osv_rec("OSV-NPM-1", "npm", "some-lib", fixed="1.0.0",
                                  cve_alias="CVE-2026-70002"), ecosystem_source="npm")
    osv_store.upsert_osv(_osv_rec("OSV-DEB-2", "Debian", "libwithdrawn", fixed="1.0",
                                  withdrawn="2026-02-01T00:00:00Z", cve_alias="CVE-2026-70002"),
                         ecosystem_source="Debian")
    rec = retrieval.get_cve("CVE-2026-70002")
    # npm is not a distro ecosystem -> excluded; the Debian record IS withdrawn but
    # get_cve still returns it (withdrawn filtering happens at the answer layer)
    assert all(d["distro"] == "Debian" for d in rec["distro_fixes"])
    assert rec["distro_fixes"][0]["withdrawn"] is True


def test_answer_cve_surfaces_distro_fix_and_hides_withdrawn():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2026-70003", description="d")])
    osv_store.upsert_osv(_osv_rec("OSV-DEB-3", "Debian", "libgood", fixed="9.9",
                                  cve_alias="CVE-2026-70003"), ecosystem_source="Debian")
    osv_store.upsert_osv(_osv_rec("OSV-DEB-4", "Debian", "libwithdrawn2", fixed="1.0",
                                  withdrawn="2026-02-01T00:00:00Z", cve_alias="CVE-2026-70003"),
                         ecosystem_source="Debian")
    rec = retrieval.get_cve("CVE-2026-70003")
    answer = security_answer._answer_cve(rec)
    assert "Debian libgood: fixed in 9.9" in answer["defensive_actions"]
    assert "libwithdrawn2" not in answer["defensive_actions"]


def test_answer_cve_no_distro_data_has_no_distro_mention():
    store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2026-70004", description="d")])
    rec = retrieval.get_cve("CVE-2026-70004")
    answer = security_answer._answer_cve(rec)
    assert "Distro packages" not in answer["defensive_actions"]
