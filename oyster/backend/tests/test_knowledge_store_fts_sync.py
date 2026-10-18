"""Regression tests for the 2026-09-14 ``fts_available()`` race-condition fix.

Root cause (see the docstring on ``store.fts_available()``): the lazy
``_fts_ok`` cache was read-checked-then-set with no lock, while every OTHER
function touching the FTS table already took ``store._lock``. Two callers
racing the very first check (a real, reproducible scenario during connector
install / pack uninstall, both of which fan work out to worker threads) could
run the create/drop FTS5 probe on two connections against the same on-disk
file at once; a transient ``sqlite3.OperationalError`` from that race was
indistinguishable from "FTS5 not compiled in" and got cached as ``False``
forever — silently degrading every later ``replace_chunks()``/
``delete_chunks()`` call in that process to a canonical-storage-only write,
with no error raised anywhere. This was found live: a real ingestion left
581 orphaned ``knowledge_chunks_fts`` rows after a pack uninstall+reinstall.

Every test here builds its own isolated temp SQLite database
(``store._DB_PATH`` monkeypatched, fresh ``store.init_db()``) and its own
isolated temp Chroma collection (a throwaway ``PersistentClient`` under
``tmp_path``, with ``rag_service``'s collection getters monkeypatched to
return it) — never the real knowledge store, never the real vector store.
"""
from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from services import rag_service
from services.knowledge import pack_service, store


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    db_path = str(tmp_path / "memory.db")
    monkeypatch.setattr(store, "_DB_PATH", db_path)
    monkeypatch.setattr(store, "_fts_ok", None)
    store.init_db()
    return db_path


@pytest.fixture
def isolated_vectors(tmp_path, monkeypatch):
    import chromadb
    from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

    client = chromadb.PersistentClient(path=str(tmp_path / "vector_db"))
    ef = SentenceTransformerEmbeddingFunction(model_name=rag_service.EMBED_MODEL)
    knowledge_col = client.get_or_create_collection(
        "test_knowledge", embedding_function=ef, metadata={"hnsw:space": "cosine"}
    )
    vuln_col = client.get_or_create_collection(
        "test_vuln", embedding_function=ef, metadata={"hnsw:space": "cosine"}
    )
    monkeypatch.setattr(rag_service, "_get_knowledge_collection", lambda: knowledge_col)
    monkeypatch.setattr(rag_service, "_get_vuln_collection", lambda: vuln_col)
    return knowledge_col, vuln_col


def _seed_pack(pack_id: str, n: int, *, vectors=None) -> None:
    con = sqlite3.connect(store._DB_PATH)
    con.execute(
        "INSERT INTO knowledge_packs (pack_id, version, title, installed_at, updated_at) "
        "VALUES (?, 'v1', ?, 'now', 'now')",
        (pack_id, pack_id),
    )
    for i in range(n):
        cid = f"kp::{pack_id}::{i}"
        con.execute(
            "INSERT INTO knowledge_chunks (id, pack_id, content, content_hash, created_at) "
            "VALUES (?, ?, ?, ?, 'now')",
            (cid, pack_id, f"{pack_id} chunk {i} about detection and mitigation", f"h{pack_id}{i}"),
        )
        con.execute(
            "INSERT INTO knowledge_chunks_fts (chunk_id, pack_id, content) VALUES (?, ?, ?)",
            (cid, pack_id, f"{pack_id} chunk {i} about detection and mitigation"),
        )
    con.commit()
    con.close()
    if vectors is not None:
        col, _ = vectors
        ids = [f"kp::{pack_id}::{i}" for i in range(n)]
        col.add(
            ids=ids,
            documents=[f"{pack_id} chunk {i}" for i in range(n)],
            metadatas=[{"knowledge_pack": pack_id} for _ in range(n)],
        )


def _counts(pack_id: str, vectors=None) -> dict:
    con = sqlite3.connect(store._DB_PATH)
    kc = con.execute("SELECT COUNT(*) FROM knowledge_chunks WHERE pack_id=?", (pack_id,)).fetchone()[0]
    fts = con.execute("SELECT COUNT(*) FROM knowledge_chunks_fts WHERE pack_id=?", (pack_id,)).fetchone()[0]
    con.close()
    out = {"knowledge_chunks": kc, "knowledge_chunks_fts": fts}
    if vectors is not None:
        col, _ = vectors
        out["vectors"] = len(col.get(where={"knowledge_pack": pack_id})["ids"])
    return out


# --- uninstall correctness ---------------------------------------------------

async def test_uninstall_removes_canonical_rows(isolated_store, isolated_vectors):
    _seed_pack("pack-a", 5, vectors=isolated_vectors)
    assert _counts("pack-a")["knowledge_chunks"] == 5

    ok = await pack_service.uninstall("pack-a")

    assert ok is True
    assert _counts("pack-a")["knowledge_chunks"] == 0


async def test_uninstall_removes_matching_fts_rows(isolated_store, isolated_vectors):
    _seed_pack("pack-a", 5, vectors=isolated_vectors)
    assert _counts("pack-a")["knowledge_chunks_fts"] == 5

    await pack_service.uninstall("pack-a")

    assert _counts("pack-a")["knowledge_chunks_fts"] == 0


async def test_uninstall_removes_vector_embeddings(isolated_store, isolated_vectors):
    _seed_pack("pack-a", 5, vectors=isolated_vectors)
    assert _counts("pack-a", isolated_vectors)["vectors"] == 5

    await pack_service.uninstall("pack-a")

    assert _counts("pack-a", isolated_vectors)["vectors"] == 0


async def test_uninstall_leaves_other_packs_untouched(isolated_store, isolated_vectors):
    _seed_pack("pack-a", 5, vectors=isolated_vectors)
    _seed_pack("pack-b", 3, vectors=isolated_vectors)

    await pack_service.uninstall("pack-a")

    b = _counts("pack-b", isolated_vectors)
    assert b == {"knowledge_chunks": 3, "knowledge_chunks_fts": 3, "vectors": 3}


async def test_repeated_uninstall_is_safe(isolated_store, isolated_vectors):
    _seed_pack("pack-a", 5, vectors=isolated_vectors)

    first = await pack_service.uninstall("pack-a")
    second = await pack_service.uninstall("pack-a")  # already gone

    assert first is True
    assert second is False  # is_installed() correctly reports it's already gone
    assert _counts("pack-a", isolated_vectors) == {"knowledge_chunks": 0, "knowledge_chunks_fts": 0, "vectors": 0}


async def test_counts_agree_across_canonical_fts_and_vectors(isolated_store, isolated_vectors):
    _seed_pack("pack-a", 7, vectors=isolated_vectors)
    before = _counts("pack-a", isolated_vectors)
    assert before["knowledge_chunks"] == before["knowledge_chunks_fts"] == before["vectors"] == 7

    await pack_service.uninstall("pack-a")

    after = _counts("pack-a", isolated_vectors)
    assert after["knowledge_chunks"] == after["knowledge_chunks_fts"] == after["vectors"] == 0


# --- the actual race that caused the bug -------------------------------------

def test_fts_available_probes_at_most_once_under_concurrent_first_access(isolated_store, monkeypatch):
    """The actual mechanism of the fix, tested deterministically (a plain
    threading.Barrier race is GIL-timing luck and can pass even on the buggy
    code — this doesn't rely on timing luck). ``_detect_fts`` is the racy
    create/drop DDL probe; it must run AT MOST ONCE per process no matter how
    many threads call ``fts_available()`` concurrently for the first time.
    Before the fix (no lock around the check), every concurrent caller sees
    ``_fts_ok is None`` and redundantly re-runs the probe — each such
    redundant run was a chance for a transient OperationalError to get
    cached as the final, permanent, wrong value."""
    call_count = 0
    real_detect = store._detect_fts

    def counting_detect(con):
        nonlocal call_count
        call_count += 1
        time.sleep(0.05)  # hold the lock long enough that concurrent callers genuinely queue up
        return real_detect(con)

    monkeypatch.setattr(store, "_detect_fts", counting_detect)
    store._fts_ok = None

    threads = [threading.Thread(target=store.fts_available) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count == 1, (
        f"_detect_fts ran {call_count} times for one process's first access — "
        "concurrent callers are not being serialized, so a transient probe "
        "failure in any one of them can still poison the cache for the whole process"
    )
    assert store._fts_ok is True


def test_fts_available_serialization_reproduces_the_original_bug_when_removed(isolated_store, monkeypatch):
    """Negative control: with the lock removed (simulating the pre-fix code
    exactly), the same scenario DOES call the probe multiple times — proving
    the test above is actually exercising the fix, not passing vacuously."""
    call_count = 0
    real_detect = store._detect_fts

    def counting_detect(con):
        nonlocal call_count
        call_count += 1
        time.sleep(0.05)
        return real_detect(con)

    def unlocked_fts_available():
        # The exact pre-fix implementation: no lock at all.
        if store._fts_ok is None:
            with store.conn() as c:
                store._fts_ok = counting_detect(c)
        return store._fts_ok

    monkeypatch.setattr(store, "_detect_fts", counting_detect)
    store._fts_ok = None

    threads = [threading.Thread(target=unlocked_fts_available) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count > 1, (
        "expected the unlocked pre-fix implementation to call the probe more than "
        "once under concurrency — if this fails, the reproduction itself is unreliable"
    )


# --- interrupted deletion fails safely ---------------------------------------

def test_interrupted_delete_chunks_leaves_no_partial_state(isolated_store, monkeypatch):
    """If the FTS half of delete_chunks() raises mid-transaction, the
    canonical-storage half must NOT be left partially deleted — the whole
    operation is one transaction with a single commit, so an exception before
    that commit must roll back everything, not just stop partway."""
    _seed_pack("pack-a", 5)
    assert _counts("pack-a")["knowledge_chunks"] == 5

    real_conn = store.conn

    class _FailOnFtsDelete:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, *args, **kwargs):
            if "DELETE FROM knowledge_chunks_fts" in sql:
                raise sqlite3.OperationalError("simulated interruption")
            return self._inner.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def _patched_conn():
        return _FailOnFtsDelete(real_conn())

    monkeypatch.setattr(store, "conn", _patched_conn)

    with pytest.raises(sqlite3.OperationalError):
        store.delete_chunks("pack-a")

    monkeypatch.setattr(store, "conn", real_conn)
    after = _counts("pack-a")
    assert after["knowledge_chunks"] == 5, (
        "canonical rows were deleted even though the transaction never committed "
        "— an interrupted delete must fail atomically, not partially"
    )
    assert after["knowledge_chunks_fts"] == 5
