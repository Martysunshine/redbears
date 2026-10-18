"""Vector-store privacy gate for scripts/package_knowledge.py (2026-09-15).

Ported from Martin's main commit 95c190b8 after the release reconciliation
found this branch never had it. No test existed for this file on main either
(verified manually against the live store there) — these build a minimal,
synthetic Chroma-schema SQLite file so the gate is covered deterministically,
without touching the real multi-GB vector store.
"""

from __future__ import annotations

import sqlite3

import pytest

from scripts import package_knowledge as pk


def _make_chroma_sqlite(path, collections: dict[str, int]) -> None:
    """collection_name -> embedding_count, in a minimal schema shaped enough
    to satisfy _vector_collections' actual query (collections/segments/embeddings
    with the same join structure Chroma itself uses)."""
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, collection TEXT)")
    con.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY, segment_id TEXT)")
    for i, (name, count) in enumerate(collections.items()):
        cid, sid = f"col-{i}", f"seg-{i}"
        con.execute("INSERT INTO collections VALUES (?, ?)", (cid, name))
        con.execute("INSERT INTO segments VALUES (?, ?)", (sid, cid))
        for j in range(count):
            con.execute("INSERT INTO embeddings (segment_id) VALUES (?)", (sid,))
    con.commit()
    con.close()


@pytest.fixture
def vector_db_dir(tmp_path):
    d = tmp_path / "vector_db"
    d.mkdir()
    return d


def test_missing_chroma_file_returns_empty_not_a_crash(vector_db_dir):
    assert pk._vector_collections(vector_db_dir) == {}


def test_knowledge_only_store_passes_without_extra(vector_db_dir):
    _make_chroma_sqlite(vector_db_dir / "chroma.sqlite3",
                        {"oyster_knowledge": 100, "oyster_vulnerabilities": 20})
    found = pk._assert_vector_db_is_knowledge_only(vector_db_dir, force=False)
    assert found == {"oyster_knowledge": 100, "oyster_vulnerabilities": 20}


def test_extra_collection_refuses_without_force(vector_db_dir):
    _make_chroma_sqlite(vector_db_dir / "chroma.sqlite3",
                        {"oyster_knowledge": 100, "oyster_docs": 12})
    with pytest.raises(SystemExit, match="REFUSING to package"):
        pk._assert_vector_db_is_knowledge_only(vector_db_dir, force=False)


def test_extra_collection_with_force_packages_anyway_and_reports_it(vector_db_dir, capsys):
    _make_chroma_sqlite(vector_db_dir / "chroma.sqlite3",
                        {"oyster_knowledge": 100, "oyster_docs": 12, "oyster_user_memory": 65})
    found = pk._assert_vector_db_is_knowledge_only(vector_db_dir, force=True)
    assert found == {"oyster_knowledge": 100, "oyster_docs": 12, "oyster_user_memory": 65}
    out = capsys.readouterr().out
    assert "oyster_docs: 12" in out
    assert "--force: packaging anyway" in out


def test_unreadable_store_is_treated_as_unknown_and_refuses(vector_db_dir, monkeypatch):
    """Unknown must not pass a privacy gate -- an unreadable file must refuse,
    not silently succeed as if it held nothing."""
    chroma = vector_db_dir / "chroma.sqlite3"
    chroma.write_text("not a real sqlite file")
    with pytest.raises(SystemExit, match="REFUSING to package"):
        pk._assert_vector_db_is_knowledge_only(vector_db_dir, force=False)


def test_manifest_records_exactly_what_shipped(vector_db_dir):
    _make_chroma_sqlite(vector_db_dir / "chroma.sqlite3", {"oyster_knowledge": 5})
    found = pk._assert_vector_db_is_knowledge_only(vector_db_dir, force=False)
    assert found == {"oyster_knowledge": 5}
