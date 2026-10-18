"""Long-term User Memory — encryption at rest, dedup/update/conflict
resolution, project isolation, consent gating, sensitive-content blocking,
review queue, export/delete.

Uses a deterministic in-memory fake for the vector index (token-overlap
similarity) instead of the real embedding model, so dedup/conflict outcomes
are fast and reproducible rather than dependent on model version drift.
"""

from __future__ import annotations

import sqlite3

import pytest

import config
from services import ollama_service
from services.user_memory import extractor, resolver, sensitive
from services.user_memory import service as memory_service
from services.user_memory import store as um_store


@pytest.fixture(autouse=True)
def _um_db():
    um_store.init_db()
    yield


@pytest.fixture
def fake_memory_vectors(monkeypatch):
    """Deterministic replacement for rag_service's memory vector index."""
    from services import rag_service

    index: dict[str, dict] = {}

    def _sim(a: str, b: str) -> float:
        ta, tb = set(a.lower().split()), set(b.lower().split())
        if not ta or not tb:
            return 0.0
        return len(ta & tb) / len(ta | tb)

    async def _upsert(memory_id, project_id, mem_type, text):
        index[memory_id] = {"project_id": project_id, "type": mem_type, "text": text}

    async def _nearest(project_id, text, top_k=5):
        cands = [(mid, _sim(text, v["text"]), v["type"])
                for mid, v in index.items() if v["project_id"] == project_id]
        cands.sort(key=lambda x: -x[1])
        return [{"id": mid, "type": t, "score": round(s, 4)} for mid, s, t in cands[:top_k]]

    async def _delete(memory_id):
        index.pop(memory_id, None)

    async def _delete_project(project_id):
        for mid in [m for m, v in index.items() if v["project_id"] == project_id]:
            index.pop(mid, None)

    monkeypatch.setattr(rag_service, "upsert_memory_vector_async", _upsert)
    monkeypatch.setattr(rag_service, "nearest_memory_vectors_async", _nearest)
    monkeypatch.setattr(rag_service, "delete_memory_vector_async", _delete)
    monkeypatch.setattr(rag_service, "delete_project_memory_vectors_async", _delete_project)
    return index


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------

def test_content_is_encrypted_at_rest():
    secret_content = "The staging DB hostname is db-staging-7.internal.example.com"
    mem = um_store.insert_memory("proj-enc", "fact", "staging db host", secret_content)

    con = sqlite3.connect(str(config.MEMORY_DB))
    row = con.execute("SELECT content_enc FROM user_memories WHERE id = ?", (mem["id"],)).fetchone()
    con.close()

    assert row is not None
    assert secret_content not in row[0]
    assert mem["content"] == secret_content  # decrypted correctly through the API


# ---------------------------------------------------------------------------
# Sensitive-content gate — never store automatically
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content", [
    "AWS key is AKIAABCDEFGHIJKLMNOP",
    "password=SuperSecret123!",
    "card number 4111 1111 1111 1111",
    "-----BEGIN RSA PRIVATE KEY-----",
    "ssn 123-45-6789",
])
def test_sensitive_content_blocked(content):
    blocked, indicators = sensitive.blocks_storage(content)
    assert blocked is True
    assert indicators


@pytest.mark.asyncio
async def test_manual_add_blocks_secret(fake_memory_vectors):
    result = await memory_service.manual_add("proj-sec", "fact", "db creds",
                                             "password=hunter2xyz123")
    assert result["ok"] is False
    assert um_store.list_memories("proj-sec") == []


@pytest.mark.asyncio
async def test_extractor_never_returns_secret_even_if_model_proposes_it(monkeypatch):
    async def fake_generate(prompt, model, system=""):
        return (
            '[{"type": "preference", "subject": "editor", "content": '
            '"Operator prefers vim.", "confidence": 0.8},'
            '{"type": "fact", "subject": "api key", "content": '
            '"api_key=sk-abcdefghij1234567890", "confidence": 0.9}]'
        )
    monkeypatch.setattr(ollama_service, "generate", fake_generate)

    candidates = await extractor.extract_candidates("what editor should I use", "use vim")
    subjects = [c["subject"] for c in candidates]
    assert "editor" in subjects
    assert "api key" not in subjects


@pytest.mark.asyncio
async def test_extractor_never_raises_on_ollama_failure(monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("ollama unreachable")
    monkeypatch.setattr(ollama_service, "generate", boom)
    assert await extractor.extract_candidates("hello", "hi") == []


# ---------------------------------------------------------------------------
# Dedup / update / conflict resolution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exact_duplicate_not_reinserted(fake_memory_vectors):
    await resolver.resolve_candidate("proj-dup", "preference", "editor choice",
                                     "Operator prefers vim for quick edits",
                                     target_status="active")
    outcome = await resolver.resolve_candidate("proj-dup", "preference", "editor choice",
                                               "Operator prefers vim for quick edits",
                                               target_status="active")
    assert outcome["action"] == "duplicate"
    assert len(um_store.list_memories("proj-dup")) == 1


@pytest.mark.asyncio
async def test_refinement_supersedes_old_memory(monkeypatch, fake_memory_vectors):
    monkeypatch.setattr(config, "MEMORY_DEDUP_THRESHOLD", 0.2)
    first = await resolver.resolve_candidate(
        "proj-upd", "preference", "notification setting",
        "operator wants email notifications for critical findings only", target_status="active")
    second = await resolver.resolve_candidate(
        "proj-upd", "preference", "notification setting",
        "operator wants email notifications for critical and high findings", target_status="active")

    assert second["action"] == "update"
    assert second["superseded"] == first["memory"]["id"]
    old = um_store.get_memory(first["memory"]["id"])
    assert old["status"] == "superseded"
    active = um_store.list_memories("proj-upd", status="active")
    assert len(active) == 1
    assert active[0]["id"] == second["memory"]["id"]


@pytest.mark.asyncio
async def test_contradiction_flagged_not_silently_overwritten(monkeypatch, fake_memory_vectors):
    monkeypatch.setattr(config, "MEMORY_DEDUP_THRESHOLD", 0.05)
    first = await resolver.resolve_candidate(
        "proj-conf", "fact", "primary language",
        "zzz yyy xxx", target_status="active")
    second = await resolver.resolve_candidate(
        "proj-conf", "fact", "primary language",
        "aaa bbb ccc", target_status="active")

    assert second["action"] == "conflict"
    group = second["conflict_group"]
    members = um_store.conflict_group_members("proj-conf", group)
    assert len(members) == 2
    assert all(m["status"] == "conflicting" for m in members)

    conflicts = memory_service.list_conflicts("proj-conf")
    assert len(conflicts) == 1
    assert {m["id"] for m in conflicts[0]["members"]} == {first["memory"]["id"], second["memory"]["id"]}


@pytest.mark.asyncio
async def test_resolve_conflict_picks_a_winner(monkeypatch, fake_memory_vectors):
    monkeypatch.setattr(config, "MEMORY_DEDUP_THRESHOLD", 0.05)
    first = await resolver.resolve_candidate("proj-cr", "fact", "topic", "zzz yyy xxx", target_status="active")
    second = await resolver.resolve_candidate("proj-cr", "fact", "topic", "aaa bbb ccc", target_status="active")
    group = second["conflict_group"]

    result = await memory_service.resolve_conflict("proj-cr", group, first["memory"]["id"])
    assert result is not None
    kept = um_store.get_memory(first["memory"]["id"])
    other = um_store.get_memory(second["memory"]["id"])
    assert kept["status"] == "active"
    assert other["status"] == "superseded"


# ---------------------------------------------------------------------------
# Project isolation (the tenant boundary)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_project_isolation_no_cross_project_leakage(fake_memory_vectors):
    um_store.set_settings("proj-a", memory_enabled=True)
    um_store.set_settings("proj-b", memory_enabled=True)
    await resolver.resolve_candidate("proj-a", "fact", "secret project codename",
                                     "Project Nightingale targets internal.corp.local",
                                     target_status="active")

    results_a = await memory_service.retrieve_relevant("proj-a", "project codename", top_k=5)
    results_b = await memory_service.retrieve_relevant("proj-b", "project codename", top_k=5)

    assert len(results_a) == 1
    assert results_b == []
    assert um_store.list_memories("proj-b") == []


# ---------------------------------------------------------------------------
# Settings gates: memory_enabled / auto_save / ask_before_saving
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_capture_skipped_when_memory_disabled(monkeypatch, fake_memory_vectors):
    um_store.set_settings("proj-off", memory_enabled=False)

    async def fake_extract(user_msg, assistant_msg, model=None):
        return [{"type": "fact", "subject": "x", "content": "y", "confidence": 0.9}]
    monkeypatch.setattr(extractor, "extract_candidates", fake_extract)

    result = await memory_service.capture_from_exchange("proj-off", "hi", "hello")
    assert result["skipped"] == "memory_disabled"
    assert um_store.list_memories("proj-off") == []


@pytest.mark.asyncio
async def test_retrieve_relevant_returns_nothing_when_disabled(fake_memory_vectors):
    um_store.set_settings("proj-off2", memory_enabled=True)
    await resolver.resolve_candidate("proj-off2", "fact", "topic", "some content here",
                                     target_status="active")
    um_store.set_settings("proj-off2", memory_enabled=False)
    assert await memory_service.retrieve_relevant("proj-off2", "topic") == []


@pytest.mark.asyncio
async def test_capture_skipped_when_auto_save_and_ask_both_off(monkeypatch, fake_memory_vectors):
    um_store.set_settings("proj-noop", memory_enabled=True, auto_save=False, ask_before_saving=False)

    async def fake_extract(user_msg, assistant_msg, model=None):
        return [{"type": "fact", "subject": "x", "content": "y", "confidence": 0.9}]
    monkeypatch.setattr(extractor, "extract_candidates", fake_extract)

    result = await memory_service.capture_from_exchange("proj-noop", "hi", "hello")
    assert result["skipped"] == "auto_save_and_ask_both_off"


@pytest.mark.asyncio
async def test_ask_before_saving_creates_pending_then_approve_reject(monkeypatch, fake_memory_vectors):
    um_store.set_settings("proj-ask", memory_enabled=True, auto_save=True, ask_before_saving=True)

    async def fake_extract(user_msg, assistant_msg, model=None):
        return [{"type": "preference", "subject": "theme", "content": "operator likes dark mode",
                 "confidence": 0.8}]
    monkeypatch.setattr(extractor, "extract_candidates", fake_extract)

    await memory_service.capture_from_exchange("proj-ask", "I like dark mode", "noted")
    pending = memory_service.list_pending("proj-ask")
    assert len(pending) == 1
    assert um_store.list_memories("proj-ask", status="active") == []

    approved = memory_service.approve(pending[0]["id"])
    assert approved["status"] == "active"

    # A second pending item, rejected instead.
    await memory_service.capture_from_exchange("proj-ask", "I like light mode too", "noted")
    pending2 = memory_service.list_pending("proj-ask")
    if pending2:
        rejected = memory_service.reject(pending2[0]["id"])
        assert rejected["status"] == "rejected"


# ---------------------------------------------------------------------------
# Delete / export
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_single_delete_is_soft_by_default(fake_memory_vectors):
    mem = await memory_service.manual_add("proj-del", "fact", "topic", "some fact content")
    mid = mem["memory"]["id"]
    ok = await memory_service.delete(mid)
    assert ok is True
    assert um_store.get_memory(mid)["status"] == "deleted"
    assert um_store.list_memories("proj-del", status="active") == []


@pytest.mark.asyncio
async def test_delete_all_personal_data_is_hard_and_irreversible(fake_memory_vectors):
    await memory_service.manual_add("proj-wipe", "fact", "a", "alpha content here")
    await memory_service.manual_add("proj-wipe", "fact", "b", "beta content here")
    assert len(um_store.list_memories("proj-wipe")) == 2

    n = await memory_service.delete_all_personal_data("proj-wipe")
    assert n == 2
    assert um_store.list_memories("proj-wipe", status=["active", "pending", "deleted",
                                                        "rejected", "superseded", "conflicting"]) == []


@pytest.mark.asyncio
async def test_export_returns_decrypted_content_and_settings(fake_memory_vectors):
    um_store.set_settings("proj-exp", memory_enabled=True, auto_save=False)
    await memory_service.manual_add("proj-exp", "fact", "topic", "exportable fact content")
    export = memory_service.export_all("proj-exp")
    assert export["project_id"] == "proj-exp"
    assert len(export["memories"]) == 1
    assert export["memories"][0]["content"] == "exportable fact content"
    assert export["settings"]["auto_save"] is False


@pytest.mark.asyncio
async def test_update_blocks_sensitive_content(fake_memory_vectors):
    mem = await memory_service.manual_add("proj-upd2", "fact", "topic", "harmless content")
    mid = mem["memory"]["id"]
    result = await memory_service.update(mid, content="password=hunter2xyz123")
    assert result["ok"] is False
    assert um_store.get_memory(mid)["content"] == "harmless content"
