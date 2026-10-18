"""services/knowledge/metrics.py's indexed_percentage (2026-09-15).

Ported from main commit c7f0e52d after the release reconciliation found this
branch never had it. Regression: indexed_percentage used to divide by every
embedding id in EVERY Chroma collection, so an unrelated collection's
embeddings inflated the ratio above 100% and masked genuinely unindexed
knowledge_chunks rows one-for-one. These build a minimal, isolated
memory.db + chroma.sqlite3 pair so the fix is covered deterministically.
"""

from __future__ import annotations

import sqlite3

import config
from services.knowledge import metrics


def _make_memory_db(path, rows):
    """rows: list of (id, pack_id, content, content_hash, canonical_url, doc_id)."""
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, pack_id TEXT, content TEXT, "
        "content_hash TEXT, canonical_url TEXT, doc_id TEXT, created_at TEXT)"
    )
    for r in rows:
        con.execute("INSERT INTO knowledge_chunks VALUES (?, ?, ?, ?, ?, ?, ?)", (*r, "2026-09-01"))
    con.commit()
    con.close()


def _make_vector_db(path, collections: dict[str, list[str]]):
    """collections: name -> list of embedding_id values."""
    path.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path / "chroma.sqlite3"))
    con.execute("CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, collection TEXT)")
    con.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY, segment_id TEXT, embedding_id TEXT)")
    for i, (name, eids) in enumerate(collections.items()):
        cid, sid = f"col-{i}", f"seg-{i}"
        con.execute("INSERT INTO collections VALUES (?, ?)", (cid, name))
        con.execute("INSERT INTO segments VALUES (?, ?)", (sid, cid))
        for eid in eids:
            con.execute("INSERT INTO embeddings (segment_id, embedding_id) VALUES (?, ?)", (sid, eid))
    con.commit()
    con.close()


def test_unrelated_collection_no_longer_inflates_coverage_past_100_percent(tmp_path, monkeypatch):
    memory_db = tmp_path / "memory.db"
    vector_db = tmp_path / "vector_db"

    # 2 real knowledge chunks, both genuinely indexed in oyster_knowledge.
    _make_memory_db(memory_db, [
        ("c1", "some-pack", "a" * 50, "hash1", "https://example.invalid/1", "d1"),
        ("c2", "some-pack", "b" * 50, "hash2", "https://example.invalid/2", "d2"),
    ])
    # An unrelated collection (e.g. a dataset-eval or user-memory index) with
    # its OWN embedding ids that never appear in knowledge_chunks at all —
    # this is exactly what pushed the ratio above 100% before the fix.
    _make_vector_db(vector_db, {
        "oyster_knowledge": ["c1", "c2"],
        "oyster_dataset_eval": ["eval-1", "eval-2", "eval-3", "eval-4", "eval-5"],
    })

    monkeypatch.setattr(config, "MEMORY_DB", str(memory_db))
    monkeypatch.setattr(config, "VECTOR_DB_DIR", str(vector_db))

    result = metrics.compute()
    assert result["indexed_percentage"] == 100.0
    assert result["indexed_percentage"] <= 100.0, "coverage of knowledge_chunks can never exceed 100%"


def test_genuinely_unindexed_row_still_lowers_coverage(tmp_path, monkeypatch):
    """The fix must not accidentally make every row look indexed -- a chunk
    genuinely absent from Chroma must still count against the ratio."""
    memory_db = tmp_path / "memory.db"
    vector_db = tmp_path / "vector_db"

    _make_memory_db(memory_db, [
        ("c1", "some-pack", "a" * 50, "hash1", "https://example.invalid/1", "d1"),
        ("c2", "some-pack", "b" * 50, "hash2", "https://example.invalid/2", "d2"),
    ])
    # Only c1 is actually indexed; c2 is a real gap. Also include a large
    # unrelated collection to prove it no longer masks the gap.
    _make_vector_db(vector_db, {
        "oyster_knowledge": ["c1"],
        "oyster_user_memory": ["mem-1", "mem-2", "mem-3"],
    })

    monkeypatch.setattr(config, "MEMORY_DB", str(memory_db))
    monkeypatch.setattr(config, "VECTOR_DB_DIR", str(vector_db))

    result = metrics.compute()
    assert result["indexed_percentage"] == 50.0
