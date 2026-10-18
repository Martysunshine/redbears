"""NVD CVE 2.0 API parser — offline, small hand-authored fixture (real shape)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from services.knowledge.vulnerabilities.sources import nvd

_CVE_OBJ = {
    "id": "CVE-2021-44228",
    "sourceIdentifier": "security@apache.org",
    "published": "2021-12-10T10:15:09.143",
    "lastModified": "2024-01-01T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "es", "value": "spanish text should be skipped"},
        {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker-controlled endpoints."},
    ],
    "weaknesses": [
        {"source": "x", "type": "Primary", "description": [{"lang": "en", "value": "CWE-502"}]},
        {"source": "x", "type": "Secondary", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]},
    ],
    "references": [
        {"url": "https://example.org/a", "source": "x", "tags": ["Patch"]},
        {"url": "https://example.org/b", "source": "x", "tags": []},
    ],
    "configurations": [
        {"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:a:apache:log4j:1.0:*:*:*:*:*:*:*"},
        ]}]},
    ],
    "metrics": {
        "cvssMetricV31": [
            {"source": "sec", "type": "Secondary", "cvssData": {
                "vectorString": "CVSS:3.1/AV:N/secondary", "baseScore": 9.0, "baseSeverity": "CRITICAL"}},
            {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0,
                "baseSeverity": "CRITICAL"}},
        ],
        "cvssMetricV2": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "baseScore": 9.3, "baseSeverity": None}},
        ],
    },
}


def test_normalize_cve_obj_prefers_english_description():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    assert e.description.startswith("Apache Log4j2")


def test_normalize_cve_obj_filters_placeholder_cwe_ids():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    assert e.cwe_ids == ["CWE-502"]  # NVD-CWE-noinfo dropped, not a real CWE id


def test_normalize_cve_obj_prefers_v31_primary_over_secondary():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    assert e.cvss_v3_score == 10.0
    assert e.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert e.cvss_source == "nvd@nist.gov"


def test_normalize_cve_obj_extracts_v2_separately_from_v3():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    assert e.cvss_v2_score == 9.3
    assert e.cvss_v3_score != e.cvss_v2_score  # never conflated


def test_normalize_cve_obj_extracts_only_vulnerable_cpe_matches():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    assert len(e.affected_products) == 1
    assert e.affected_products[0]["vendor"] == "apache"
    assert e.affected_products[0]["product"] == "log4j"


def test_normalize_cve_obj_rejects_malformed_id():
    bad = dict(_CVE_OBJ, id="not-a-cve")
    assert nvd.normalize_cve_obj(bad) is None


def test_normalize_cve_obj_missing_metrics_is_none_not_a_crash():
    minimal = {"id": "CVE-2024-00001", "descriptions": []}
    e = nvd.normalize_cve_obj(minimal)
    assert e is not None
    assert e.cvss_v3_score is None
    assert e.cvss_v2_score is None
    assert e.description is None


def test_parse_cpe_extracts_vendor_product_version():
    parsed = nvd._parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert parsed == {"vendor": "apache", "product": "log4j", "version": "2.14.1",
                      "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}


def test_parse_cpe_returns_none_for_garbage():
    assert nvd._parse_cpe("not a cpe string") is None


# ---------------------------------------------------------------------------
# CVSS v4 + multi-source score preservation
# ---------------------------------------------------------------------------

_CVE_OBJ_V4 = dict(_CVE_OBJ, metrics={
    **_CVE_OBJ["metrics"],
    "cvssMetricV40": [
        {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
            "vectorString": "CVSS:4.0/AV:N/AC:L", "baseScore": 9.3, "baseSeverity": "CRITICAL"}},
    ],
})


def test_normalize_cve_obj_extracts_v4_when_present():
    e = nvd.normalize_cve_obj(_CVE_OBJ_V4)
    assert e.cvss_v4_score == 9.3
    assert e.cvss_v4_severity == "CRITICAL"
    assert e.cvss_v4_vector == "CVSS:4.0/AV:N/AC:L"


def test_normalize_cve_obj_prefers_v4_source_over_v3_when_both_present():
    e = nvd.normalize_cve_obj(_CVE_OBJ_V4)
    assert e.cvss_source == "nvd@nist.gov"  # v4's Primary source wins the preferred-score policy


def test_normalize_cve_obj_missing_v4_leaves_v4_fields_none():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    assert e.cvss_v4_score is None
    assert e.cvss_v4_vector is None


def test_all_cvss_scores_captures_every_source_and_version_separately():
    e = nvd.normalize_cve_obj(_CVE_OBJ)
    versions = {s["cvss_version"] for s in e.all_cvss_scores}
    assert versions == {"3.1", "2.0"}
    v31_entries = [s for s in e.all_cvss_scores if s["cvss_version"] == "3.1"]
    assert len(v31_entries) == 2  # Primary AND Secondary both preserved, not collapsed
    scores = {s["source"]: s["score"] for s in v31_entries}
    assert scores["nvd@nist.gov"] == 10.0
    assert scores["sec"] == 9.0


def test_all_cvss_scores_empty_when_no_metrics():
    e = nvd.normalize_cve_obj({"id": "CVE-2024-00002", "descriptions": []})
    assert e.all_cvss_scores == []


def test_chunk_windows_never_exceeds_max_days():
    from services.knowledge.vulnerabilities.sync import _chunk_windows
    start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    end = datetime(2020, 6, 1, tzinfo=timezone.utc)  # ~152 days
    windows = _chunk_windows(start, end, 120)
    assert len(windows) == 2
    for w_start, w_end in windows:
        assert (w_end - w_start) <= timedelta(days=120)
    assert windows[0][0] == start
    assert windows[-1][1] == end


def test_chunk_windows_single_window_when_under_max_days():
    from services.knowledge.vulnerabilities.sync import _chunk_windows
    start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=7)
    windows = _chunk_windows(start, end, 120)
    assert windows == [(start, end)]
