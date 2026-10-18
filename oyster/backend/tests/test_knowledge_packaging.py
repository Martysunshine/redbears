"""Tests for the knowledge-base packaging + restore (portable deployment).

Deterministic, on tiny synthetic stores in temp dirs — proves:
  * the export copies KB tables but NEVER personal tables (privacy),
  * generated columns (e.g. kg_nodes virtual cols) are handled,
  * a full package -> restore round-trip reproduces the eligible count on a
    fresh target and the restored DB contains no personal tables.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import config
from scripts import package_knowledge, restore_knowledge

_LONG = "A complete, meaningful cybersecurity knowledge fact about an attack technique and its mitigation." * 2


def _mk_source(tmp: Path) -> tuple[Path, Path]:
    """Build a synthetic source store: KB tables + a personal table + a table with
    a generated column, plus a matching Chroma index."""
    mem = tmp / "memory.db"
    con = sqlite3.connect(str(mem))
    # KB table
    con.execute("CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, pack_id TEXT, pack_version TEXT, "
                "doc_id TEXT, source_type TEXT, title TEXT, publisher TEXT, canonical_url TEXT, "
                "content_hash TEXT, content TEXT, created_at TEXT)")
    for i in range(120):
        con.execute("INSERT INTO knowledge_chunks (id,pack_id,canonical_url,content_hash,content,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (f"k{i}", "owasp-x", "https://example.com/x", f"h{i}", _LONG, "2026-01-01T00:00:00+00:00"))
    con.execute("CREATE TABLE knowledge_packs (pack_id TEXT PRIMARY KEY, version TEXT, licence TEXT, "
                "trust_level TEXT, pack_kind TEXT, content_checksum TEXT, doc_count INT, chunk_count INT)")
    con.execute("INSERT INTO knowledge_packs VALUES ('owasp-x','v1','CC','official','markdown','abc',1,120)")
    # table with a GENERATED VIRTUAL column (like kg_nodes)
    con.execute("CREATE TABLE kg_nodes (node_id TEXT PRIMARY KEY, attrs TEXT, "
                "source TEXT GENERATED ALWAYS AS (json_extract(attrs,'$.source')) VIRTUAL)")
    con.execute("INSERT INTO kg_nodes (node_id, attrs) VALUES ('n1', '{\"source\":\"mitre\"}')")
    # a PERSONAL table that must never be exported
    con.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY, title TEXT)")
    con.execute("INSERT INTO conversations VALUES ('c1','my private chat')")
    con.commit()
    con.close()

    vec = tmp / "vector_db"
    vec.mkdir()
    ch = sqlite3.connect(str(vec / "chroma.sqlite3"))
    ch.execute("CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT)")
    ch.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, collection TEXT, scope TEXT)")
    ch.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY AUTOINCREMENT, segment_id TEXT, "
               "embedding_id TEXT, seq_id BLOB, created_at TIMESTAMP)")
    ch.execute("INSERT INTO collections VALUES ('c0','oyster_knowledge')")
    ch.execute("INSERT INTO segments VALUES ('s0','c0','VECTOR')")
    for i in range(120):
        ch.execute("INSERT INTO embeddings (segment_id,embedding_id,seq_id) VALUES ('s0',?,?)", (f"k{i}", b""))
    ch.commit()
    ch.close()
    return mem, vec


def test_export_excludes_personal_and_handles_generated_cols(tmp_path):
    src_mem, _ = _mk_source(tmp_path)
    dst = tmp_path / "export.db"
    counts = package_knowledge.export_knowledge_db(src_mem, dst)

    con = sqlite3.connect(str(dst))
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    # KB present, personal absent
    assert "knowledge_chunks" in tables
    assert "kg_nodes" in tables                       # generated-column table copied
    assert "conversations" not in tables              # personal table excluded
    assert package_knowledge.FORBIDDEN_TABLES.isdisjoint(tables)
    # FTS regenerated to full coverage
    fts = con.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0]
    assert fts == 120
    assert counts["knowledge_chunks"] == 120
    assert con.execute("SELECT COUNT(*) FROM kg_nodes").fetchone()[0] == 1
    con.close()


def test_package_restore_roundtrip(tmp_path, monkeypatch):
    # --- package from a synthetic SOURCE ---
    src = tmp_path / "source"
    src.mkdir()
    src_mem, src_vec = _mk_source(src)
    monkeypatch.setattr(config, "MEMORY_DB", src_mem)
    monkeypatch.setattr(config, "VECTOR_DB_DIR", src_vec)
    monkeypatch.setattr(config, "DATA_DIR", src)
    out_dir = tmp_path / "packages"
    result = package_knowledge.build_package(out_dir, encrypt=False, force=True)  # <100k -> force
    archive = Path(result["archive"])
    assert archive.exists()
    assert result["eligible_unique_searchable_chunks"] == 120

    # --- restore into a fresh TARGET ---
    tgt = tmp_path / "target"
    tgt.mkdir()
    monkeypatch.setattr(config, "MEMORY_DB", tgt / "memory.db")
    monkeypatch.setattr(config, "VECTOR_DB_DIR", tgt / "vector_db")
    monkeypatch.setattr(config, "DATA_DIR", tgt)
    r = restore_knowledge.restore(archive, decrypt=False)
    assert r["restored_eligible"] == 120

    # restored memory.db must contain KB but no personal tables
    con = sqlite3.connect(str(tgt / "memory.db"))
    tables = {x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert "knowledge_chunks" in tables
    assert "conversations" not in tables
