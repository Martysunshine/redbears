"""FIRST EPSS bulk-CSV parser — offline, small gzipped fixture (real shape)."""

from __future__ import annotations

import gzip

from services.knowledge.vulnerabilities.sources import epss

_CSV_BODY = (
    "#model_version:v2024.03.14,score_date:2024-03-14T00:00:00Z\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.97531,0.99998\n"
    "CVE-2024-00001,0.00042,0.12345\n"
    "not-a-cve,0.5,0.5\n"          # malformed id — must be dropped
    "CVE-2024-00002,1.5,0.5\n"     # out-of-range score — must be dropped
    "CVE-2024-00003,0.5,-0.1\n"    # out-of-range percentile — must be dropped
    "CVE-2024-00004,notanumber,0.5\n"  # malformed float — must be dropped, not crash
)


def _gz(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))


def test_normalize_extracts_valid_rows_and_score_date():
    entries, score_date = epss.normalize(_gz(_CSV_BODY))
    ids = {e.cve_id for e in entries}
    assert ids == {"CVE-2021-44228", "CVE-2024-00001"}
    assert score_date == "2024-03-14T00:00:00Z"


def test_normalize_drops_out_of_range_scores():
    entries, _ = epss.normalize(_gz(_CSV_BODY))
    assert all(0.0 <= e.score <= 1.0 for e in entries)
    assert all(0.0 <= e.percentile <= 1.0 for e in entries)


def test_normalize_drops_malformed_rows_without_crashing():
    entries, _ = epss.normalize(_gz(_CSV_BODY))
    assert not any(e.cve_id == "CVE-2024-00004" for e in entries)


def test_normalize_empty_file_returns_empty():
    entries, score_date = epss.normalize(_gz(""))
    assert entries == []
    assert score_date == ""


def test_normalize_header_only_returns_empty():
    entries, score_date = epss.normalize(_gz("#model_version:v1,score_date:2024-01-01T00:00:00Z\ncve,epss,percentile\n"))
    assert entries == []
    assert score_date == "2024-01-01T00:00:00Z"
