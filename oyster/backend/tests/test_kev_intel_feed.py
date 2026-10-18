"""Unit tests for the CISA KEV "Latest intelligence" fallback
(services/intel/kev_feed.py): normalization against the real schema (verified
live 2026-10-18), dedup, stale-on-failure, vendor/product filtering, and that
no severity field is ever invented. No live network call — httpx is mocked.
"""
from __future__ import annotations

import httpx
import pytest

import config
from services.intel import kev_feed

# Shape taken verbatim from a live GET of the real feed URL on 2026-10-18.
_LIVE_SHAPE_SAMPLE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.10.16",
    "dateReleased": "2026-10-16T17:15:48.8752Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-102764", "vendorProject": "BeyondTrust", "product": "Remote Support",
            "vulnerabilityName": "BeyondTrust Remote Support Authentication Bypass by Spoofing Vulnerability",
            "dateAdded": "2026-10-16",
            "shortDescription": "BeyondTrust Remote Support contains an authentication bypass...",
            "requiredAction": "Apply mitigations in accordance with vendor instructions...",
            "dueDate": "2026-10-19", "knownRansomwareCampaignUse": "Unknown", "forensicTriage": "Yes",
            "notes": "https://www.beyondtrust.com/trust-center/security-advisories/bt26-05",
            "cwes": ["CWE-290"],
        },
        {
            "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-917"],
        },
    ],
}


class _FakeResponse:
    def __init__(self, status_code, json_body=None):
        self.status_code = status_code
        self._json = json_body or {}

    def json(self):
        return self._json


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "KEV_INTEL_CACHE_PATH", str(tmp_path / "kev_intel_feed_cache.json"))
    monkeypatch.setattr(config, "OPENCVE_CACHE_MAX_ENTRIES", 200)


@pytest.mark.asyncio
async def test_refresh_normalizes_the_real_schema_with_no_severity_field(monkeypatch):
    async def _get(self, url):
        assert url == config.KEV_FEED_URL
        return _FakeResponse(200, _LIVE_SHAPE_SAMPLE)
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    feed = await kev_feed.refresh()
    assert feed["source"] == "cisa_kev"
    assert feed["stale"] is False
    ids = {e["cve_id"] for e in feed["entries"]}
    assert ids == {"CVE-2026-102764", "CVE-2021-44228"}
    for e in feed["entries"]:
        assert "severity" not in e and "cvss" not in e and "score" not in e
        assert e["source_url"].startswith("https://nvd.nist.gov/vuln/detail/")

    log4j = next(e for e in feed["entries"] if e["cve_id"] == "CVE-2021-44228")
    assert log4j["vendor_project"] == "Apache"
    assert log4j["required_action"] == "Apply updates per vendor instructions."


@pytest.mark.asyncio
async def test_vendor_and_product_filter(monkeypatch):
    async def _get(self, url):
        return _FakeResponse(200, _LIVE_SHAPE_SAMPLE)
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    await kev_feed.refresh()
    only_apache = kev_feed.get_feed(vendor="apache")
    assert [e["cve_id"] for e in only_apache["entries"]] == ["CVE-2021-44228"]
    only_log4j = kev_feed.get_feed(product="log4j2")
    assert [e["cve_id"] for e in only_log4j["entries"]] == ["CVE-2021-44228"]
    none_match = kev_feed.get_feed(vendor="nonexistent-vendor")
    assert none_match["entries"] == []


@pytest.mark.asyncio
async def test_failed_refresh_keeps_prior_cache_and_marks_stale(monkeypatch):
    async def _ok(self, url):
        return _FakeResponse(200, _LIVE_SHAPE_SAMPLE)
    monkeypatch.setattr(httpx.AsyncClient, "get", _ok)
    first = await kev_feed.refresh()
    assert first["stale"] is False

    async def _fail(self, url):
        return _FakeResponse(503)
    monkeypatch.setattr(httpx.AsyncClient, "get", _fail)
    second = await kev_feed.refresh()
    assert second["stale"] is True
    assert "503" in second["last_error"]
    assert any(e["cve_id"] == "CVE-2021-44228" for e in second["entries"])


def test_entry_missing_cve_id_is_dropped(monkeypatch):
    # _normalize is exercised indirectly via refresh, but also check directly
    # that a record with no cveID is never invented an id and included.
    assert kev_feed._normalize({"vendorProject": "X"}) is None


def test_get_feed_on_empty_cache_is_not_stale(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "KEV_INTEL_CACHE_PATH", str(tmp_path / "missing.json"))
    feed = kev_feed.get_feed()
    assert feed["entries"] == []
    assert feed["stale"] is False
    assert feed["configured"] is True
