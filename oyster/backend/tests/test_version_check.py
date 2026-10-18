"""Deterministic package/version evaluation: real range math against
installed GHSA/OSV data, and — the hard requirement — never claims a version
is safe when the range or the version string can't be confidently compared,
and never claims 'not vulnerable' just because nothing is installed."""

from __future__ import annotations

from services.knowledge.vulnerabilities import version_check as vc
from services.knowledge.vulnerabilities.osv_store import init_db, upsert_ghsa, upsert_osv
from services.knowledge.vulnerabilities.sources.osv_schema import OsvAffectedRange, OsvRecord


def _rec(rid, package, ecosystem="npm", introduced="0", fixed=None, last_affected=None,
        withdrawn=None):
    return OsvRecord(
        record_id=rid, schema_version="1.6.0", summary="test", details=None,
        published="2026-01-01T00:00:00Z", modified="2026-01-01T00:00:00Z", withdrawn=withdrawn,
        aliases=[], cwe_ids=[], severity_vector=None, severity_type=None, database_severity=None,
        references=[],
        affected=[OsvAffectedRange(ecosystem=ecosystem, package=package, introduced=introduced,
                                   fixed=fixed, last_affected=last_affected)],
    )


def test_compare_versions_basic():
    assert vc.compare_versions("1.2.3", "1.2.10") == -1
    assert vc.compare_versions("1.2.10", "1.2.3") == 1
    assert vc.compare_versions("1.2.3", "1.2.3") == 0
    assert vc.compare_versions("2.0.0", "1.9.9") == 1


def test_compare_versions_prerelease_and_unparseable():
    assert vc.compare_versions("1.0.0-rc1", "1.0.0") == -1
    assert vc.compare_versions("1.0.0", "1.0.0-rc1") == 1
    assert vc.compare_versions("1.0", "not-a-version") is None
    assert vc.compare_versions("^1.2.3", "1.0.0") is None  # range syntax, not a version


def test_not_found_is_never_reported_as_safe():
    r = vc.check_version("npm", "totally-unheard-of-pkg-xyz", "1.0.0")
    assert r["status"] == "not_found"
    assert "not evidence" in r["note"]


def test_version_in_fixed_range_is_vulnerable():
    init_db()
    upsert_ghsa(_rec("GHSA-VVVV-VVVV-VVVV", "left-pad-test", introduced="0", fixed="1.3.0"))
    r = vc.check_version("npm", "left-pad-test", "1.2.0")
    assert r["status"] == "vulnerable"
    assert r["fixed_versions"] == ["1.3.0"]


def test_version_at_or_above_fixed_is_not_vulnerable():
    init_db()
    upsert_ghsa(_rec("GHSA-WWWW-WWWW-WWWW", "left-pad-test2", introduced="0", fixed="1.3.0"))
    r = vc.check_version("npm", "left-pad-test2", "1.3.0")
    assert r["status"] == "not_affected_by_installed_advisories"


def test_open_ended_range_with_no_fix_stays_affected():
    init_db()
    upsert_osv(_rec("OSV-2026-0001", "no-fix-pkg", introduced="2.0.0"),
              ecosystem_source="npm")
    r = vc.check_version("npm", "no-fix-pkg", "5.0.0")
    assert r["status"] == "vulnerable"
    assert r["fixed_versions"] == []


def test_unparseable_query_version_is_indeterminate_not_guessed():
    init_db()
    upsert_ghsa(_rec("GHSA-XXXX-XXXX-XXXX", "weird-versioning", introduced="0", fixed="2.0.0"))
    r = vc.check_version("npm", "weird-versioning", "1.0.0-beta+build.2024.01.01.abcdef")
    assert r["status"] == "indeterminate"


def test_withdrawn_advisory_excluded_from_verdict():
    init_db()
    upsert_ghsa(_rec("GHSA-YYYY-YYYY-YYYY", "withdrawn-pkg", introduced="0", fixed="1.0.0",
                     withdrawn="2026-01-02T00:00:00Z"))
    r = vc.check_version("npm", "withdrawn-pkg", "0.5.0")
    # the only matching advisory is withdrawn -> nothing active says "affected"
    assert r["status"] == "not_affected_by_installed_advisories"
    assert r["matches"][0]["withdrawn"] is True


def test_last_affected_inclusive_boundary():
    init_db()
    upsert_osv(_rec("OSV-2026-0002", "last-affected-pkg", introduced="1.0.0",
                    last_affected="1.5.0"), ecosystem_source="npm")
    assert vc.check_version("npm", "last-affected-pkg", "1.5.0")["status"] == "vulnerable"
    assert vc.check_version("npm", "last-affected-pkg", "1.5.1")["status"] == \
        "not_affected_by_installed_advisories"
