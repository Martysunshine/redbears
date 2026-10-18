"""Red Hat CSAF synchronizer: feed-index filtering (RHSA-only), advisory-id
derivation, product_status-based remediation extraction, resume/checkpoint,
and failure isolation — all offline (no live network)."""

from __future__ import annotations

import httpx
import pytest

from services.knowledge.vulnerabilities import store
from services.knowledge.vulnerabilities import sync as vsync
from services.knowledge.vulnerabilities.sources import cisa_csaf, redhat_csaf

_CHANGES_CSV = (
    '"2026/rhsa-2026_00001.json","2026-01-01T00:00:00+00:00"\n'
    '"2026/rhba-2026_00002.json","2026-01-02T00:00:00+00:00"\n'
    '"2026/rhea-2026_00003.json","2026-01-03T00:00:00+00:00"\n'
    '"2026/rhsa-2026_00004.json","2026-01-04T00:00:00+00:00"\n'
)


@pytest.mark.asyncio
async def test_fetch_feed_index_keeps_only_rhsa(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("changes.csv")
        return httpx.Response(200, text=_CHANGES_CSV)

    real_client_cls = httpx.AsyncClient

    class _Client(real_client_cls):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    entries = await redhat_csaf.fetch_feed_index()
    ids = {e["advisory_id"] for e in entries}
    assert ids == {"RHSA-2026:00001", "RHSA-2026:00004"}
    for e in entries:
        assert e["source"] == "redhat-csaf"
        assert e["content_url"].startswith(redhat_csaf.ADVISORIES_BASE)


def _raw_advisory(cve_id, fixed_nvrs=None, cwe_id="CWE-79"):
    return {
        "document": {"title": "Moderate: example security update",
                    "publisher": {"name": "Red Hat Product Security"},
                    "tracking": {"initial_release_date": "2026-01-01T00:00:00+00:00",
                                "current_release_date": "2026-01-01T00:00:00+00:00"}},
        "vulnerabilities": [{
            "cve": cve_id,
            "cwe": {"id": cwe_id, "name": "whatever"},
            "notes": [{"category": "description", "text": "Real description text."}],
            "product_status": {"fixed": fixed_nvrs or []},
            "references": [{"category": "self", "url": f"https://access.redhat.com/security/cve/{cve_id}"}],
        }],
    }


def test_normalize_advisory_derives_remediation_from_product_status():
    entry = {"advisory_id": "RHSA-2026:00001", "content_url": "https://example/a.json",
             "source": "redhat-csaf", "title": "t"}
    raw = _raw_advisory("CVE-2026-12345", fixed_nvrs=["pkg-0:1.2.3-1.el9.x86_64", "pkg-0:1.2.3-1.el9.src"])
    advisory, findings, inj = redhat_csaf.normalize_advisory(raw, entry)
    assert advisory["advisory_id"] == "RHSA-2026:00001"
    assert advisory["publisher"] == "Red Hat Product Security"
    assert len(findings) == 1
    f = findings[0]
    assert f["cve_id"] == "CVE-2026-12345"
    assert f["cwe_id"] == "CWE-79"
    assert "pkg-0:1.2.3-1.el9.x86_64" in f["fixed_version"]
    assert f["remediation"].startswith("Fixed in:")
    assert f["vendor_reference_url"] == "https://access.redhat.com/security/cve/CVE-2026-12345"


def test_normalize_advisory_never_fabricates_missing_remediation():
    entry = {"advisory_id": "RHSA-2026:00002", "content_url": "https://example/a.json",
             "source": "redhat-csaf", "title": "t"}
    raw = _raw_advisory("CVE-2026-12346", fixed_nvrs=[])
    _, findings, _ = redhat_csaf.normalize_advisory(raw, entry)
    assert findings[0]["fixed_version"] is None
    assert findings[0]["remediation"] is None


def test_normalize_advisory_skips_non_cve_entries():
    entry = {"advisory_id": "RHSA-2026:00003", "content_url": "https://example/a.json",
             "source": "redhat-csaf", "title": "t"}
    raw = {"document": {"tracking": {}}, "vulnerabilities": [{"cve": "not-a-real-cve-id"}]}
    _, findings, _ = redhat_csaf.normalize_advisory(raw, entry)
    assert findings == []


# ---------------------------------------------------------------------------
# sync_redhat_advisories — end-to-end over a fake feed index + fake fetches
# ---------------------------------------------------------------------------

def _entry(aid, updated, url=None):
    return {"advisory_id": aid, "content_url": url or f"https://example/{aid}.json",
           "updated": updated, "source": "redhat-csaf"}


@pytest.mark.asyncio
async def test_sync_resumes_and_skips_unchanged(monkeypatch):
    entries = [_entry("RHSA-2026:1001", "2026-01-01T00:00:00Z"),
              _entry("RHSA-2026:1002", "2026-01-01T00:00:00Z")]
    fetch_calls = {"n": 0}

    async def fake_index():
        return list(entries)

    async def fake_fetch(client, url, max_retries=None):
        fetch_calls["n"] += 1
        return _raw_advisory(f"CVE-2026-7000{fetch_calls['n']}", fixed_nvrs=["pkg-0:1-1.el9"])

    monkeypatch.setattr(redhat_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r1 = await vsync.sync_redhat_advisories()
    assert r1["added"] == 2
    assert fetch_calls["n"] == 2

    r2 = await vsync.sync_redhat_advisories()
    assert r2["unchanged"] == 2
    assert r2["added"] == 0
    assert fetch_calls["n"] == 2  # pure checkpoint skip, no re-fetch


@pytest.mark.asyncio
async def test_sync_isolates_partial_failure(monkeypatch):
    entries = [_entry("RHSA-2026:OK1", "2026-01-01T00:00:00Z"),
              _entry("RHSA-2026:BAD", "2026-01-01T00:00:00Z"),
              _entry("RHSA-2026:OK2", "2026-01-01T00:00:00Z")]

    async def fake_index():
        return list(entries)

    _cve_by_advisory = {"RHSA-2026:OK1": "CVE-2026-8001", "RHSA-2026:OK2": "CVE-2026-8002"}

    async def fake_fetch(client, url, max_retries=None):
        if "BAD" in url:
            raise httpx.HTTPStatusError("boom", request=None, response=httpx.Response(500))
        aid = url.split("/")[-1].replace(".json", "")
        return _raw_advisory(_cve_by_advisory[aid])

    monkeypatch.setattr(redhat_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r = await vsync.sync_redhat_advisories()
    assert r["ok"] is True
    assert r["attempted"] == 3
    assert r["added"] == 2
    assert r["failed"] == 1
    assert store.get_vendor_advisories_for_cve("CVE-2026-8001")
    assert store.get_vendor_advisories_for_cve("CVE-2026-8002")


@pytest.mark.asyncio
async def test_sync_respects_max_advisories_bound(monkeypatch):
    entries = [_entry(f"RHSA-2026:{i}", "2026-01-01T00:00:00Z") for i in range(5)]

    async def fake_index():
        return list(entries)

    async def fake_fetch(client, url, max_retries=None):
        return _raw_advisory("CVE-2026-9001")

    monkeypatch.setattr(redhat_csaf, "fetch_feed_index", fake_index)
    monkeypatch.setattr(cisa_csaf, "fetch_advisory_with_retry", fake_fetch)

    r = await vsync.sync_redhat_advisories(max_advisories=2)
    assert r["attempted"] == 2
    assert r["corpus_size"] == 5


def test_redhat_csaf_seen_checkpoint_is_isolated_from_cisa(monkeypatch=None):
    assert store.get_redhat_csaf_seen("RHSA-2026:ISOL") is None
    store.record_redhat_csaf_seen("RHSA-2026:ISOL", feed_updated="2026-01-01T00:00:00Z",
                                  content_hash=None, status="ok")
    assert store.get_cisa_csaf_seen("RHSA-2026:ISOL") is None  # never wrote CISA's table
    assert store.get_redhat_csaf_seen("RHSA-2026:ISOL")["status"] == "ok"
