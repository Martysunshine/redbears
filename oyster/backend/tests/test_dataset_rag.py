"""Dataset RAG — governance gate, capped/deduped/sensitive-filtered ingestion,
citation labeling, enable/disable, cross-project-safe (global, not user data).

Network calls (``hf_source``) and embedding (``rag_service``) are faked so
these tests are fast, deterministic, and never touch the network — the real
end-to-end path (HuggingFace datasets-server + live embedding) was verified
manually against the running server, not re-verified here.
"""

from __future__ import annotations

import pytest

import config
from services import rag_service
from services.knowledge.datasets import gate, hf_source
from services.knowledge.datasets import service as dataset_service
from services.knowledge.datasets import store as ds_store


@pytest.fixture(autouse=True)
def _ds_db():
    ds_store.init_db()
    yield


_FAKE_ROWS = [
    {"row_index": 0, "row": {"user": "How do I detect lateral movement?", "assistant": "Use event correlation."}},
    {"row_index": 1, "row": {"user": "How do I detect lateral movement?", "assistant": "Use event correlation."}},
    {"row_index": 2, "row": {"user": "my password=SuperSecretValue123", "assistant": "noted"}},
    {"row_index": 3, "row": {"user": "What is SQL injection?", "assistant": "An injection flaw..."}},
]


@pytest.fixture
def fake_hf(monkeypatch):
    async def fake_health(hf_id):
        return {"available": True, "reason": None}

    async def fake_sha(hf_id):
        return "fakesha0000"

    async def fake_splits(hf_id):
        return [{"config": "default", "split": "train"}]

    async def fake_fetch(hf_id, config_name, split, row_limit):
        return _FAKE_ROWS[:row_limit]

    monkeypatch.setattr(hf_source, "health", fake_health)
    monkeypatch.setattr(hf_source, "discover_sha", fake_sha)
    monkeypatch.setattr(hf_source, "discover_splits", fake_splits)
    monkeypatch.setattr(hf_source, "fetch_rows", fake_fetch)


@pytest.fixture
def fake_embedding(monkeypatch):
    async def fake_ingest(dataset_id, rows_payload):
        return len(rows_payload)

    async def fake_delete(dataset_id):
        return None

    async def fake_search(query, top_k=6, dataset_ids=None):
        return [{"content": "fake", "dataset_id": (dataset_ids or ["?"])[0], "row_index": 0,
                "source_url": "https://example.test", "score": 0.5}]

    monkeypatch.setattr(rag_service, "ingest_dataset_rows_async", fake_ingest)
    monkeypatch.setattr(rag_service, "delete_dataset_async", fake_delete)
    monkeypatch.setattr(rag_service, "search_dataset_async", fake_search)


# ---------------------------------------------------------------------------
# Governance gate
# ---------------------------------------------------------------------------

def test_approved_dataset_is_rag_eligible():
    decision = gate.evaluate_for_rag("fenrir-v2.1")
    assert decision["found"] is True
    assert decision["allowed"] is True
    assert decision["hf_dataset_id"] == "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1"


def test_eval_only_dataset_blocked():
    decision = gate.evaluate_for_rag("cybersecurityeval")
    assert decision["found"] is True
    assert decision["allowed"] is False


def test_nc_licence_dataset_blocked():
    decision = gate.evaluate_for_rag("ctf-dojo")
    assert decision["allowed"] is False


def test_malware_adjacent_dataset_blocked():
    decision = gate.evaluate_for_rag("maldict")
    assert decision["allowed"] is False


def test_unknown_dataset_not_found():
    decision = gate.evaluate_for_rag("does-not-exist")
    assert decision["found"] is False
    assert decision["allowed"] is False


# ---------------------------------------------------------------------------
# Install pipeline: row cap, dedup, sensitive-content filtering
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_governance_blocked_dataset_never_touches_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("hf_source should never be called for a governance-blocked dataset")
    monkeypatch.setattr(hf_source, "health", boom)

    result = await dataset_service.install("cybersecurityeval")
    assert result["ok"] is False
    assert result["blocked"] is True


@pytest.mark.asyncio
async def test_install_respects_row_cap_dedup_and_sensitive_filter(monkeypatch, fake_hf, fake_embedding):
    monkeypatch.setattr(config, "DATASET_MAX_ROWS", 3)  # rows 0,1,2 only
    result = await dataset_service.install("fenrir-v2.1")
    assert result["ok"] is True
    assert result["rows_fetched"] == 3
    assert result["rows_stored"] == 1       # row 1 is an exact dup of row 0
    assert result["rows_deduped"] == 1
    assert result["rows_blocked_sensitive"] == 1  # row 2 has a password= pattern
    assert dataset_service.is_installed("fenrir-v2.1")

    await dataset_service.uninstall("fenrir-v2.1")


@pytest.mark.asyncio
async def test_install_full_sample_without_cap(monkeypatch, fake_hf, fake_embedding):
    monkeypatch.setattr(config, "DATASET_MAX_ROWS", 10)
    result = await dataset_service.install("fenrir-v2.1")
    assert result["ok"] is True
    assert result["rows_fetched"] == 4
    assert result["rows_stored"] == 2   # row0 (row1 deduped), row3 — row2 sensitive-blocked
    assert result["rows_deduped"] == 1
    assert result["rows_blocked_sensitive"] == 1

    await dataset_service.uninstall("fenrir-v2.1")


@pytest.mark.asyncio
async def test_cross_dataset_dedup(monkeypatch, fake_hf, fake_embedding):
    """Verbatim overlap between two installed datasets is deduped globally,
    not just within a single dataset's own import."""
    monkeypatch.setattr(config, "DATASET_MAX_ROWS", 1)  # just row 0

    r1 = await dataset_service.install("fenrir-v2.1")
    assert r1["rows_stored"] == 1

    # trendyol-cyber-instruct is also rag_eligible; fetch the SAME fake row 0
    r2 = await dataset_service.install("trendyol-cyber-instruct")
    assert r2["rows_stored"] == 0
    assert r2["rows_deduped"] == 1  # identical text already seen under fenrir-v2.1

    await dataset_service.uninstall("fenrir-v2.1")
    await dataset_service.uninstall("trendyol-cyber-instruct")


# ---------------------------------------------------------------------------
# Enable/disable, search labeling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_excludes_disabled_datasets(monkeypatch, fake_hf, fake_embedding):
    monkeypatch.setattr(config, "DATASET_MAX_ROWS", 2)
    await dataset_service.install("fenrir-v2.1")

    results = await dataset_service.search("lateral movement")
    assert results  # enabled by default after install
    assert results[0]["source_type"] == "dataset"
    assert "not an authoritative source" in results[0]["disclaimer"]

    dataset_service.set_enabled("fenrir-v2.1", False)
    assert await dataset_service.search("lateral movement") == []

    await dataset_service.uninstall("fenrir-v2.1")


@pytest.mark.asyncio
async def test_uninstall_removes_install_state(monkeypatch, fake_hf, fake_embedding):
    monkeypatch.setattr(config, "DATASET_MAX_ROWS", 1)
    await dataset_service.install("fenrir-v2.1")
    assert dataset_service.is_installed("fenrir-v2.1")

    ok = await dataset_service.uninstall("fenrir-v2.1")
    assert ok is True
    assert dataset_service.is_installed("fenrir-v2.1") is False
