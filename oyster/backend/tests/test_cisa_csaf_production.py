"""Production CISA CSAF synchronizer: resume/checkpoint, retry/backoff,
idempotent updates, quality-preserving merges, and failure isolation — all
offline (no live network)."""

from __future__ import annotations

import httpx
import pytest

from services.knowledge.vulnerabilities import store
from services.knowledge.vulnerabilities import sync as vsync
from services.knowledge.vulnerabilities.sources import cisa_csaf

# ---------------------------------------------------------------------------
# Store-level: upsert status tri-state, quality-preserving findings merge,
# checkpoint round-trip
# ---------------------------------------------------------------------------

_ADVISORY = {"advisory_id": "VA-26-100-01", "source": "cisa-csaf-it", "title": "Widget Corp Advisory",
            "publisher": "CISA", "initial_release_date": "2026-01-01T00:00:00Z",
            "current_release_date": "2026-01-01T00:00:00Z", "source_url": "https://example/va.json"}


def test_upsert_vendor_advisory_tristate():
    assert store.upsert_vendor_advisory(_ADVISORY) == "added"
    assert store.upsert_vendor_advisory(_ADVISORY) == "unchanged"
    changed = dict(_ADVISORY, current_release_date="2026-01-05T00:00:00Z")
    assert store.upsert_vendor_advisory(changed) == "updated"


def test_replace_vendor_findings_preserves_richer_prior_field():
    store.upsert_vendor_advisory(_ADVISORY)
    rich = [{"cve_id": "CVE-2026-99001", "cwe_id": "CWE-306", "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N", "severity": "HIGH",
            "description": "Full description.", "remediation": "Upgrade to 2.0.1.",
            "fixed_version": "2.0.1", "vendor_reference_url": "https://vendor.example/a"}]
    store.replace_vendor_findings("VA-26-100-01", rich)

    weaker = [{"cve_id": "CVE-2026-99001", "cwe_id": None, "cvss_score": None,
              "cvss_vector": None, "severity": None, "description": None,
              "remediation": None, "fixed_version": None, "vendor_reference_url": None}]
    store.replace_vendor_findings("VA-26-100-01", weaker)

    findings = store.get_vendor_advisories_for_cve("CVE-2026-99001")
    assert len(findings) == 1
    assert findings[0]["remediation"] == "Upgrade to 2.0.1."
    assert findings[0]["fixed_version"] == "2.0.1"
    assert findings[0]["cvss_score"] == 7.5


def test_replace_vendor_findings_no_duplicate_rows_across_updates():
    store.upsert_vendor_advisory(_ADVISORY)
    store.replace_vendor_findings("VA-26-100-01", [{"cve_id": "CVE-2026-99002", "remediation": "v1"}])
    store.replace_vendor_findings("VA-26-100-01", [{"cve_id": "CVE-2026-99002", "remediation": "v2 more detail"}])
    findings = store.get_vendor_advisories_for_cve("CVE-2026-99002")
    assert len(findings) == 1
    assert findings[0]["remediation"] == "v2 more detail"


def test_cisa_csaf_seen_checkpoint_roundtrip():
    assert store.get_cisa_csaf_seen("VA-26-200-01") is None
    store.record_cisa_csaf_seen("VA-26-200-01", feed_updated="2026-01-01T00:00:00Z",
                                content_hash="abc", status="ok")
    seen = store.get_cisa_csaf_seen("VA-26-200-01")
    assert seen["status"] == "ok"
    assert seen["feed_updated"] == "2026-01-01T00:00:00Z"
    assert store.cisa_csaf_seen_stats() == {"ok": 1}


# ---------------------------------------------------------------------------
# fetch_advisory_with_retry — real retry/backoff over a mocked transport
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_advisory_with_retry_recovers_from_429():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429)
        return httpx.Response(200, json={"document": {"title": "ok"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        data = await cisa_csaf.fetch_advisory_with_retry(client, "https://example/a.json", max_retries=4)
    assert data == {"document": {"title": "ok"}}
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_fetch_advisory_with_retry_gives_up_after_max_retries():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await cisa_csaf.fetch_advisory_with_retry(client, "https://example/a.json", max_retries=1)


@pytest.mark.asyncio
async def test_fetch_advisory_with_retry_does_not_retry_client_errors():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await cisa_csaf.fetch_advisory_with_retry(client, "https://example/a.json", max_retries=3)
    assert calls["n"] == 1  # 404 is not retried


# ---------------------------------------------------------------------------
# sync_cisa_advisories — end-to-end over a fake feed index + fake fetches
# ---------------------------------------------------------------------------

def _entry(aid, updated, url=None):
    return {"advisory_id": aid, "title": aid, "published": updated, "updated": updated,
           "content_url": url or f"https://example/{aid}.json", "source": "cisa-csaf-it"}


def _raw_for(cve_id, remediation="Upgrade now.", current_release_date="2026-01-01T00:00:00Z"):
    return {
        "document": {"title": "t", "publisher": {"name": "CISA"},
                    "tracking": {"initial_release_date": "2026-01-01T00:00:00Z",
                                "current_release_date": current_release_date}},
        "vulnerabilities": [{"cve": cve_id, "notes": [{"category": "summary", "text": "desc"}],
                             "remediations": [{"details": remediation}]}],
    }


@pytest.mark.asyncio
async def test_sync_resumes_and_skips_unchanged_advisories(monkeypatch):
    entries = [_entry("VA-1", "2026-01-01T00:00:00Z"), _entry("VA-2", "2026-01-01T00:00:00Z")]
    fetch_calls = {"n": 0}

    async def fake_index():
        return list(entries)

    async def fake_fetch(client, url, max_retries=None):
        fetch_calls["n"] += 1
        return _raw_for(f"CVE-2026-5000{fetch_calls['n']}")

    monkeypatch.setattr(cisa_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r1 = await vsync.sync_cisa_advisories()
    assert r1["added"] == 2
    assert fetch_calls["n"] == 2

    r2 = await vsync.sync_cisa_advisories()
    assert r2["unchanged"] == 2
    assert r2["added"] == 0
    assert fetch_calls["n"] == 2  # no re-fetch — pure checkpoint skip


@pytest.mark.asyncio
async def test_sync_refetches_and_updates_when_feed_updated_changes(monkeypatch):
    entries = [_entry("VA-3", "2026-01-01T00:00:00Z")]
    fetch_calls = {"n": 0}

    async def fake_index():
        return list(entries)

    async def fake_fetch(client, url, max_retries=None):
        fetch_calls["n"] += 1
        release_date = "2026-01-01T00:00:00Z" if fetch_calls["n"] == 1 else "2026-02-01T00:00:00Z"
        return _raw_for("CVE-2026-30003", remediation=f"Upgrade to build {fetch_calls['n']}.",
                        current_release_date=release_date)

    monkeypatch.setattr(cisa_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r1 = await vsync.sync_cisa_advisories()
    assert r1["added"] == 1

    entries[0] = _entry("VA-3", "2026-02-01T00:00:00Z")  # upstream republished
    r2 = await vsync.sync_cisa_advisories()
    assert r2["updated"] == 1
    assert fetch_calls["n"] == 2

    findings = store.get_vendor_advisories_for_cve("CVE-2026-30003")
    assert len(findings) == 1  # replaced, not duplicated
    assert "build 2" in findings[0]["remediation"]


@pytest.mark.asyncio
async def test_sync_isolates_partial_failure_and_reports_exact_totals(monkeypatch):
    entries = [_entry("VA-OK-1", "2026-01-01T00:00:00Z"),
              _entry("VA-BAD", "2026-01-01T00:00:00Z"),
              _entry("VA-OK-2", "2026-01-01T00:00:00Z")]

    async def fake_index():
        return list(entries)

    _cve_by_advisory = {"VA-OK-1": "CVE-2026-40001", "VA-OK-2": "CVE-2026-40002"}

    async def fake_fetch(client, url, max_retries=None):
        if "VA-BAD" in url:
            raise httpx.HTTPStatusError("boom", request=None, response=httpx.Response(500))
        aid = url.split("/")[-1].replace(".json", "")
        return _raw_for(_cve_by_advisory[aid])

    monkeypatch.setattr(cisa_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r = await vsync.sync_cisa_advisories()
    assert r["ok"] is True
    assert r["attempted"] == 3
    assert r["added"] == 2
    assert r["failed"] == 1
    assert r["successful"] == 2
    assert "VA-BAD" in r["failure_sample"][0]
    # the bad advisory must not have corrupted the good ones
    assert store.get_vendor_advisories_for_cve("CVE-2026-40001")
    assert store.get_vendor_advisories_for_cve("CVE-2026-40002")


@pytest.mark.asyncio
async def test_sync_malformed_csaf_document_does_not_crash_the_run(monkeypatch):
    entries = [_entry("VA-MALFORMED", "2026-01-01T00:00:00Z")]

    async def fake_index():
        return list(entries)

    async def fake_fetch(client, url, max_retries=None):
        return {"vulnerabilities": "not-a-list-this-is-malformed"}

    monkeypatch.setattr(cisa_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r = await vsync.sync_cisa_advisories()
    assert r["ok"] is True
    assert r["failed"] == 1
    assert r["attempted"] == 1


@pytest.mark.asyncio
async def test_sync_respects_max_advisories_bound(monkeypatch):
    entries = [_entry(f"VA-{i}", "2026-01-01T00:00:00Z") for i in range(5)]

    async def fake_index():
        return list(entries)

    calls = {"n": 0}

    async def fake_fetch(client, url, max_retries=None):
        calls["n"] += 1
        return _raw_for(f"CVE-2026-6000{calls['n']}")

    monkeypatch.setattr(cisa_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r = await vsync.sync_cisa_advisories(max_advisories=2)
    assert r["attempted"] == 2
    assert r["corpus_size"] == 5
