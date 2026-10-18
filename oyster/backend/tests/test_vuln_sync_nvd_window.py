"""NVD windowed sync — the ``embed`` switch that lets a large historical
backfill write full structured SQL data without also bulk-embedding every
CVE into Chroma (storage discipline: exact-id lookups don't need a vector)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from services import rag_service
from services.knowledge.vulnerabilities import store
from services.knowledge.vulnerabilities import sync as vsync
from services.knowledge.vulnerabilities.sources import nvd


def _fake_cve(cve_id: str) -> dict:
    return {"id": cve_id, "descriptions": [{"lang": "en", "value": f"description for {cve_id}"}],
           "vulnStatus": "Analyzed", "metrics": {}}


@pytest.mark.asyncio
async def test_backfill_defaults_to_no_embed_but_writes_full_sql(monkeypatch, fake_embedding):
    calls = {"n": 0}

    async def counting_upsert(chunk_id, text, metadata):
        calls["n"] += 1

    monkeypatch.setattr(rag_service, "upsert_vulnerability_chunk_async", counting_upsert)

    async def fake_fetch_window(start_iso, end_iso, **kw):
        return [_fake_cve("CVE-2020-00001")]

    monkeypatch.setattr(nvd, "fetch_window", fake_fetch_window)

    r = await vsync.sync_nvd_backfill(datetime(2020, 1, 1, tzinfo=timezone.utc),
                                      datetime(2020, 2, 1, tzinfo=timezone.utc))
    assert r["ok"] is True
    assert r["added"] == 1
    assert calls["n"] == 0  # no Chroma writes during a bulk backfill
    rec = store.get_vulnerability("CVE-2020-00001")
    assert rec["description"] == "description for CVE-2020-00001"  # SQL still fully populated


@pytest.mark.asyncio
async def test_incremental_sync_still_embeds_by_default(monkeypatch, fake_embedding):
    calls = {"n": 0}

    async def counting_upsert(chunk_id, text, metadata):
        calls["n"] += 1

    monkeypatch.setattr(rag_service, "upsert_vulnerability_chunk_async", counting_upsert)

    async def fake_fetch_window(start_iso, end_iso, **kw):
        return [_fake_cve("CVE-2026-00002")]

    monkeypatch.setattr(nvd, "fetch_window", fake_fetch_window)

    r = await vsync.sync_nvd_incremental(days=7)
    assert r["ok"] is True
    assert calls["n"] == 1  # recent/incremental CVEs stay semantically searchable


@pytest.mark.asyncio
async def test_backfill_can_still_opt_into_embedding(monkeypatch, fake_embedding):
    calls = {"n": 0}

    async def counting_upsert(chunk_id, text, metadata):
        calls["n"] += 1

    monkeypatch.setattr(rag_service, "upsert_vulnerability_chunk_async", counting_upsert)

    async def fake_fetch_window(start_iso, end_iso, **kw):
        return [_fake_cve("CVE-2020-00003")]

    monkeypatch.setattr(nvd, "fetch_window", fake_fetch_window)

    r = await vsync.sync_nvd_backfill(datetime(2020, 1, 1, tzinfo=timezone.utc),
                                      datetime(2020, 2, 1, tzinfo=timezone.utc), embed=True)
    assert r["ok"] is True
    assert calls["n"] == 1
