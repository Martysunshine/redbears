"""Unit tests for the OpenCVE feed cache (services/intel/opencve_feed.py):
dedup by CVE ID, modified-record handling, stale-on-failed-refresh, and
newly_published/recently_modified classification. No live OpenCVE call —
opencve_adapter.list_cves is monkeypatched.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

import config
from services.integrations.base import IntegrationError, IntegrationStatus
from services.intel import opencve_feed


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "opc_org.test.secret")
    monkeypatch.setattr(config, "OPENCVE_CACHE_PATH", str(tmp_path / "opencve_feed_cache.json"))
    monkeypatch.setattr(config, "OPENCVE_CACHE_MAX_ENTRIES", 10)
    monkeypatch.setattr(config, "OPENCVE_RECENT_WINDOW_S", 7 * 86400)


def _iso(delta_days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=delta_days)).isoformat().replace("+00:00", "Z")


@pytest.mark.asyncio
async def test_refresh_populates_cache_and_dedupes(monkeypatch):
    async def _fake_list_cves(self, **kwargs):
        return {"count": 2, "next": None, "previous": None, "results": [
            {"cve_id": "CVE-2024-0001", "created_at": _iso(1), "updated_at": _iso(1), "description": "a"},
            {"cve_id": "CVE-2024-0002", "created_at": _iso(10), "updated_at": _iso(0.1), "description": "b"},
        ]}
    monkeypatch.setattr(opencve_feed.opencve_adapter.__class__, "list_cves", _fake_list_cves)

    feed = await opencve_feed.refresh()
    assert feed["stale"] is False
    assert feed["last_error"] is None
    ids = {e["cve_id"] for e in feed["entries"]}
    assert ids == {"CVE-2024-0001", "CVE-2024-0002"}

    newly = next(e for e in feed["entries"] if e["cve_id"] == "CVE-2024-0001")
    modified = next(e for e in feed["entries"] if e["cve_id"] == "CVE-2024-0002")
    assert newly["newly_published"] is True
    assert modified["newly_published"] is False  # created 10 days ago, outside the 7-day window
    assert modified["recently_modified"] is True


@pytest.mark.asyncio
async def test_refresh_keeps_newer_record_on_duplicate_fetch(monkeypatch):
    calls = {"n": 0}

    async def _fake_list_cves(self, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"count": 1, "next": None, "previous": None, "results": [
                {"cve_id": "CVE-2024-0003", "created_at": _iso(5), "updated_at": _iso(5), "description": "old"},
            ]}
        return {"count": 1, "next": None, "previous": None, "results": [
            {"cve_id": "CVE-2024-0003", "created_at": _iso(5), "updated_at": _iso(0.1), "description": "updated"},
        ]}
    monkeypatch.setattr(opencve_feed.opencve_adapter.__class__, "list_cves", _fake_list_cves)

    await opencve_feed.refresh()
    feed = await opencve_feed.refresh()
    entry = next(e for e in feed["entries"] if e["cve_id"] == "CVE-2024-0003")
    assert entry["description"] == "updated"


@pytest.mark.asyncio
async def test_failed_refresh_keeps_prior_cache_and_marks_stale(monkeypatch):
    async def _ok(self, **kwargs):
        return {"count": 1, "next": None, "previous": None, "results": [
            {"cve_id": "CVE-2024-0004", "created_at": _iso(1), "updated_at": _iso(1), "description": "x"},
        ]}
    monkeypatch.setattr(opencve_feed.opencve_adapter.__class__, "list_cves", _ok)
    first = await opencve_feed.refresh()
    assert first["stale"] is False

    async def _fail(self, **kwargs):
        raise IntegrationError("OpenCVE rate limit reached (429).", status=IntegrationStatus.UNAVAILABLE)
    monkeypatch.setattr(opencve_feed.opencve_adapter.__class__, "list_cves", _fail)
    second = await opencve_feed.refresh()

    assert second["stale"] is True
    assert "429" in second["last_error"]
    # the CVE from the successful refresh must still be there
    assert any(e["cve_id"] == "CVE-2024-0004" for e in second["entries"])


@pytest.mark.asyncio
async def test_refresh_not_configured_reports_clear_reason(monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "")
    feed = await opencve_feed.refresh()
    assert feed["stale"] is True
    assert "OPENCVE_API_TOKEN" in feed["last_error"]


def test_get_feed_on_empty_cache_is_not_stale(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_CACHE_PATH", str(tmp_path / "missing.json"))
    feed = opencve_feed.get_feed()
    assert feed["entries"] == []
    assert feed["stale"] is False
