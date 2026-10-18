"""OSV-schema parser (shared by GHSA + OSV connectors) — offline, using
real-shaped fixtures pulled from actual github/advisory-database records."""

from __future__ import annotations

from services.knowledge.vulnerabilities.sources.osv_schema import parse_osv_record

_REAL_GHSA = {
    "schema_version": "1.4.0",
    "id": "GHSA-264p-99wq-f4j6",
    "modified": "2025-11-04T16:48:17Z",
    "published": "2024-01-03T22:04:08Z",
    "aliases": ["CVE-2024-21634"],
    "summary": "Ion Java StackOverflow vulnerability",
    "details": "A potential denial-of-service issue exists...",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
    "affected": [{
        "package": {"ecosystem": "Maven", "name": "com.amazon.ion:ion-java"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.10.5"}]}],
    }],
    "references": [{"type": "WEB", "url": "https://github.com/amazon-ion/ion-java/security/advisories/GHSA-264p-99wq-f4j6"}],
    "database_specific": {"cwe_ids": ["CWE-674"], "severity": "HIGH", "github_reviewed": True},
}

_WITHDRAWN_GHSA = {
    "schema_version": "1.4.0",
    "id": "GHSA-23rx-79r7-6cpx",
    "modified": "2026-01-22T20:31:21Z",
    "published": "2024-01-19T21:30:36Z",
    "withdrawn": "2026-01-22T20:31:21Z",
    "aliases": [],
    "summary": "Duplicate Advisory: Sandbox escape",
    "details": "This advisory has been withdrawn because it is a duplicate.",
    "severity": [],
    "affected": [],
    "references": [],
    "database_specific": {"cwe_ids": [], "severity": "HIGH", "github_reviewed": True},
}


def test_parse_real_ghsa_shaped_record():
    rec = parse_osv_record(_REAL_GHSA)
    assert rec.record_id == "GHSA-264P-99WQ-F4J6"
    assert rec.cve_aliases == ["CVE-2024-21634"]
    assert rec.ghsa_alias is None  # the record's OWN id is the GHSA id, not an alias of itself
    assert rec.severity_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert rec.database_severity == "HIGH"
    assert rec.cwe_ids == ["CWE-674"]
    assert len(rec.affected) == 1
    assert rec.affected[0].ecosystem == "Maven"
    assert rec.affected[0].package == "com.amazon.ion:ion-java"
    assert rec.affected[0].introduced == "0"
    assert rec.affected[0].fixed == "1.10.5"


def test_parse_withdrawn_record_sets_withdrawn_timestamp():
    rec = parse_osv_record(_WITHDRAWN_GHSA)
    assert rec.withdrawn == "2026-01-22T20:31:21Z"
    assert rec.affected == []


def test_parse_record_with_multiple_cves_and_packages():
    raw = {
        "id": "OSV-TEST-0001", "aliases": ["CVE-2024-00001", "CVE-2024-00002"],
        "affected": [
            {"package": {"ecosystem": "npm", "name": "pkg-a"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "pkg-b"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.0"}]}]},
        ],
    }
    rec = parse_osv_record(raw)
    assert set(rec.cve_aliases) == {"CVE-2024-00001", "CVE-2024-00002"}
    assert len(rec.affected) == 2
    ecosystems = {a.ecosystem for a in rec.affected}
    assert ecosystems == {"npm", "PyPI"}


def test_parse_rejects_missing_id():
    assert parse_osv_record({"summary": "no id here"}) is None


def test_parse_never_fabricates_missing_fields():
    rec = parse_osv_record({"id": "OSV-TEST-0002"})
    assert rec.summary is None
    assert rec.cwe_ids == []
    assert rec.affected == []
    assert rec.severity_vector is None


def test_parse_ghsa_alias_extracted_when_record_is_not_itself_ghsa():
    raw = {"id": "PYSEC-2024-1", "aliases": ["CVE-2024-99999", "GHSA-2345-6789-cfgh"]}
    rec = parse_osv_record(raw)
    assert rec.ghsa_alias == "GHSA-2345-6789-CFGH"
    assert rec.cve_aliases == ["CVE-2024-99999"]


def test_parse_affected_with_no_ranges_still_records_the_package():
    raw = {"id": "OSV-TEST-0003", "affected": [{"package": {"ecosystem": "Go", "name": "example.com/pkg"}}]}
    rec = parse_osv_record(raw)
    assert len(rec.affected) == 1
    assert rec.affected[0].introduced is None
    assert rec.affected[0].fixed is None
