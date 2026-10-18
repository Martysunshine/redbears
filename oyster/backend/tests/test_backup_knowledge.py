"""scripts/backup_knowledge.py (2026-09-15).

New file ported into this branch from main commit 4a171754 (this branch never
had it) as part of the release reconciliation. No test existed on main either.
These cover the pure helpers and a full end-to-end run against a small
synthetic data directory (real SQLite files, WAL mode, a genuine Chroma-shaped
schema) -- not the real multi-GB store.
"""

from __future__ import annotations

import sqlite3

from scripts import backup_knowledge as bk


def _make_memory_db(path, rows=1):
    con = sqlite3.connect(str(path))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, content TEXT)")
    for i in range(rows):
        con.execute("INSERT INTO knowledge_chunks VALUES (?, ?)", (f"c{i}", "x" * 50))
    con.commit()
    con.close()


def _make_chroma(path, collections: dict[str, int]):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, collection TEXT)")
    con.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY, segment_id TEXT)")
    for i, (name, n) in enumerate(collections.items()):
        cid, sid = f"col-{i}", f"seg-{i}"
        con.execute("INSERT INTO collections VALUES (?, ?)", (cid, name))
        con.execute("INSERT INTO segments VALUES (?, ?)", (sid, cid))
        for _ in range(n):
            con.execute("INSERT INTO embeddings (segment_id) VALUES (?)", (sid,))
    con.commit()
    con.close()


# --- pure helpers -------------------------------------------------------------

def test_human_formats_sizes_reasonably():
    assert bk.human(500) == "500B"
    assert "KB" in bk.human(2048)
    assert "MB" in bk.human(5 * 1024 * 1024)
    assert "GB" in bk.human(2 * 1024 * 1024 * 1024)


def test_sha256_is_deterministic(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"some content")
    assert bk.sha256(f) == bk.sha256(f)
    assert len(bk.sha256(f)) == 64


def test_collection_counts_missing_file_returns_empty_not_a_crash(tmp_path):
    assert bk.collection_counts(tmp_path / "nope.sqlite3") == {}


def test_collection_counts_reads_real_schema(tmp_path):
    chroma = tmp_path / "chroma.sqlite3"
    _make_chroma(chroma, {"oyster_knowledge": 3, "oyster_vulnerabilities": 1})
    assert bk.collection_counts(chroma) == {"oyster_knowledge": 3, "oyster_vulnerabilities": 1}


def test_integrity_ok_true_for_a_real_database(tmp_path):
    db = tmp_path / "memory.db"
    _make_memory_db(db)
    assert bk.integrity_ok(db) is True


def test_integrity_ok_false_for_a_corrupt_file(tmp_path):
    db = tmp_path / "memory.db"
    db.write_text("not a real sqlite file")
    assert bk.integrity_ok(db) is False


def test_online_copy_captures_wal_commits_a_plain_copy_would_miss(tmp_path):
    """The whole reason this script exists instead of cp -r: WAL commits not
    yet checkpointed into the main file must still be captured."""
    src = tmp_path / "src.db"
    _make_memory_db(src, rows=1)
    con = sqlite3.connect(str(src))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("INSERT INTO knowledge_chunks VALUES ('c-wal', 'not yet checkpointed')")
    con.commit()
    con.close()  # deliberately no checkpoint

    dst = tmp_path / "dst.db"
    bk.online_copy(src, dst)

    con = sqlite3.connect(str(dst))
    count = con.execute("SELECT COUNT(*) FROM knowledge_chunks WHERE id='c-wal'").fetchone()[0]
    con.close()
    assert count == 1, "online_copy must capture WAL-only commits"


# --- end-to-end ----------------------------------------------------------------

def test_main_produces_a_verified_snapshot_with_matching_counts(tmp_path, capsys):
    data = tmp_path / "data"
    data.mkdir()
    _make_memory_db(data / "memory.db", rows=2)
    _make_chroma(data / "vector_db" / "chroma.sqlite3", {"oyster_knowledge": 2})
    (data / ".memory_key").write_bytes(b"fake-key-material")

    dest = tmp_path / "backups"
    dest.mkdir()

    # main() reads sys.argv directly via argparse; call it the same way the
    # script's own CLI would, with a controlled argv.
    import sys
    old_argv = sys.argv
    sys.argv = ["backup_knowledge.py", "--data", str(data), "--dest", str(dest), "--stamp", "test-run"]
    try:
        rc = bk.main()
    finally:
        sys.argv = old_argv

    assert rc == 0
    snapshot = dest / "oyster-knowledge-test-run"
    assert (snapshot / "memory.db").exists()
    assert (snapshot / "vector_db" / "chroma.sqlite3").exists()
    manifest = (snapshot / "manifest.json").exists()
    assert manifest
    assert (dest / "oyster-knowledge-test-run.key").exists()
    assert not (dest / "oyster-knowledge-test-run.key").stat().st_mode & 0o077, \
        "key file must not be group/world readable"


def test_main_fails_loudly_on_a_row_count_shortfall(tmp_path, monkeypatch):
    """A backup that under-counts what the live store had must fail the run,
    not report success with a silently incomplete snapshot."""
    data = tmp_path / "data"
    data.mkdir()
    _make_memory_db(data / "memory.db", rows=1)
    _make_chroma(data / "vector_db" / "chroma.sqlite3", {"oyster_knowledge": 5})
    dest = tmp_path / "backups"
    dest.mkdir()

    # Force the post-copy recount to look short, simulating a partial copy.
    real_counts = bk.collection_counts
    call_count = {"n": 0}

    def flaky_counts(path):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return real_counts(path)  # live count, read before copying
        return {"oyster_knowledge": 1}  # backup count, simulating lost rows

    monkeypatch.setattr(bk, "collection_counts", flaky_counts)

    import sys
    old_argv = sys.argv
    sys.argv = ["backup_knowledge.py", "--data", str(data), "--dest", str(dest), "--stamp", "test-shortfall"]
    try:
        rc = bk.main()
    finally:
        sys.argv = old_argv

    assert rc == 1
