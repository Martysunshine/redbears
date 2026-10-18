"""restore_knowledge.py's destructive-restore guards (2026-09-15).

Ported from main commit f7485df2 after the release reconciliation found this
branch never had it. The original bug: the docstring said KB tables were
"replaced (merged)" implying target data was preserved, but _merge_kb DROPs
every KB table and the whole vector_db is superseded -- pointing this at a
populated store would silently destroy it. These tests cover the four guards
added: refuse a populated target, refuse a missing checksum sidecar, --dry-run
writes nothing, and --force is required to override either refusal.

2026-09-15 (second pass): added end-to-end coverage the unit tests above don't
reach -- a real restore() call against a real tar archive, exercising the
full extract/verify/write pipeline rather than just the helper functions in
isolation. Closes three gaps: (1) --dry-run writes nothing even when driven
through the whole function, not just _preflight in isolation; (2) a busy
store is proven, not just asserted, by holding a real SQLite lock; (3) the
one failure mode this script can reliably preserve the target against -- a
tampered/corrupt package -- is proven to leave the target byte-identical.
"""

from __future__ import annotations

import hashlib
import sqlite3
import tarfile

import pytest

from scripts import restore_knowledge as rk


def _make_populated_memory_db(path):
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, content TEXT)")
    con.execute("INSERT INTO knowledge_chunks VALUES ('c1', 'hello')")
    con.commit()
    con.close()


def _make_populated_vector_db(path):
    path.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path / "chroma.sqlite3"))
    con.execute("CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, collection TEXT)")
    con.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY, segment_id TEXT)")
    con.execute("INSERT INTO collections VALUES ('col-1', 'oyster_knowledge')")
    con.execute("INSERT INTO segments VALUES ('seg-1', 'col-1')")
    con.execute("INSERT INTO embeddings (segment_id) VALUES ('seg-1')")
    con.commit()
    con.close()


# --- _store_population -------------------------------------------------------

def test_store_population_empty_target_reports_nothing(tmp_path):
    pop = rk._store_population(tmp_path / "memory.db", tmp_path / "vector_db")
    assert pop == {"kb_rows": 0, "collections": {}, "readable": True}


def test_store_population_counts_real_rows_and_embeddings(tmp_path):
    memory_db = tmp_path / "memory.db"
    vector_db = tmp_path / "vector_db"
    _make_populated_memory_db(memory_db)
    _make_populated_vector_db(vector_db)
    pop = rk._store_population(memory_db, vector_db)
    assert pop["kb_rows"] == 1
    assert pop["collections"] == {"oyster_knowledge": 1}
    assert pop["readable"] is True


def test_store_population_unreadable_db_is_treated_as_unreadable(tmp_path):
    memory_db = tmp_path / "memory.db"
    memory_db.write_text("not a real sqlite file")
    pop = rk._store_population(memory_db, tmp_path / "vector_db")
    assert pop["readable"] is False


# --- _preflight ---------------------------------------------------------------

def test_preflight_allows_a_genuinely_empty_target(tmp_path):
    pop = rk._preflight(tmp_path / "memory.db", tmp_path / "vector_db", force=False)
    assert pop["kb_rows"] == 0


def test_preflight_refuses_a_populated_target_without_force(tmp_path):
    memory_db = tmp_path / "memory.db"
    _make_populated_memory_db(memory_db)
    with pytest.raises(SystemExit, match="REFUSING.*already holds a knowledge base"):
        rk._preflight(memory_db, tmp_path / "vector_db", force=False)


def test_preflight_dry_run_reports_but_never_raises_on_populated_target(tmp_path, capsys):
    memory_db = tmp_path / "memory.db"
    _make_populated_memory_db(memory_db)
    pop = rk._preflight(memory_db, tmp_path / "vector_db", force=False, dry_run=True)
    assert pop["kb_rows"] == 1
    assert "would REFUSE here" in capsys.readouterr().out


def test_preflight_force_proceeds_over_a_populated_target(tmp_path, capsys):
    memory_db = tmp_path / "memory.db"
    _make_populated_memory_db(memory_db)
    pop = rk._preflight(memory_db, tmp_path / "vector_db", force=True)
    assert pop["kb_rows"] == 1
    assert "proceeding over a populated" in capsys.readouterr().out


def test_preflight_unreadable_store_is_treated_as_populated_and_refuses(tmp_path):
    memory_db = tmp_path / "memory.db"
    memory_db.write_text("not a real sqlite file")
    with pytest.raises(SystemExit, match="REFUSING"):
        rk._preflight(memory_db, tmp_path / "vector_db", force=False)


# --- _verify_archive_checksum --------------------------------------------------

def test_verify_checksum_refuses_missing_sidecar_by_default(tmp_path):
    archive = tmp_path / "package.tar.gz"
    archive.write_bytes(b"fake archive contents")
    with pytest.raises(SystemExit, match="REFUSING.*cannot be verified"):
        rk._verify_archive_checksum(archive)


def test_verify_checksum_allows_missing_sidecar_with_allow_unverified(tmp_path, capsys):
    archive = tmp_path / "package.tar.gz"
    archive.write_bytes(b"fake archive contents")
    rk._verify_archive_checksum(archive, allow_unverified=True)
    assert "UNVERIFIED" in capsys.readouterr().out


def test_verify_checksum_passes_on_a_matching_sidecar(tmp_path):
    archive = tmp_path / "package.tar.gz"
    archive.write_bytes(b"fake archive contents")
    sidecar = tmp_path / "package.tar.gz.sha256"
    sidecar.write_text(f"{rk._sha256(archive)}  package.tar.gz\n")
    rk._verify_archive_checksum(archive)  # must not raise


def test_verify_checksum_rejects_a_mismatched_sidecar(tmp_path):
    archive = tmp_path / "package.tar.gz"
    archive.write_bytes(b"fake archive contents")
    sidecar = tmp_path / "package.tar.gz.sha256"
    sidecar.write_text("0" * 64 + "  package.tar.gz\n")
    with pytest.raises(SystemExit, match="CHECKSUM MISMATCH"):
        rk._verify_archive_checksum(archive)


# --- _is_in_use ----------------------------------------------------------------

def test_is_in_use_returns_none_when_nothing_exists(tmp_path):
    assert rk._is_in_use(tmp_path / "memory.db", tmp_path / "vector_db") is None


def test_is_in_use_detects_a_real_held_exclusive_lock(tmp_path):
    """Not just asserted -- an actual second connection has to be refused.

    A held BEGIN EXCLUSIVE is what a live, mid-write backend looks like from
    the outside. _is_in_use must report the busy file rather than silently
    treating a locked-but-existing database as free.
    """
    db = tmp_path / "memory.db"
    holder = sqlite3.connect(str(db))
    holder.execute("CREATE TABLE t (x INTEGER)")
    holder.commit()
    holder.execute("BEGIN EXCLUSIVE")
    holder.execute("INSERT INTO t VALUES (1)")
    try:
        assert rk._is_in_use(db, tmp_path / "vector_db") == "memory.db"
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    # once released, the same file must read back as free
    assert rk._is_in_use(db, tmp_path / "vector_db") is None


# --- end-to-end: real archive through restore() --------------------------------

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_package(tmp_path, name="pkg", tamper=False):
    """A minimal but real oyster-kb package archive + its .sha256 sidecar.

    Shaped exactly like package_knowledge.py's output: oyster_knowledge.db
    (a real, empty, forbidden-table-free SQLite file), manifest.json (with
    per-file sha256es), and a vector_db/ directory. When tamper=True, the
    on-disk oyster_knowledge.db bytes are changed AFTER the manifest hash is
    computed, so the archive's own file checksum verification must catch it
    -- simulating a corrupted/truncated download.
    """
    staging = tmp_path / f"{name}_staging"
    staging.mkdir()

    kb_db = staging / "oyster_knowledge.db"
    con = sqlite3.connect(str(kb_db))
    con.execute("CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, content TEXT)")
    con.execute("INSERT INTO knowledge_chunks VALUES ('c1', 'restored content')")
    con.commit()
    con.close()
    kb_sha = _sha256_file(kb_db)

    vector_db = staging / "vector_db"
    vector_db.mkdir()
    (vector_db / "chroma.sqlite3").write_bytes(b"fake-chroma-bytes-from-package")
    vec_sha = _sha256_bytes(b"fake-chroma-bytes-from-package")

    if tamper:
        # Corrupt the file on disk without updating the manifest -- the
        # checksum recorded below is now wrong, on purpose.
        kb_db.write_bytes(b"corrupted mid-transfer")

    manifest = {
        "eligible_unique_searchable_chunks": 1,
        "git_commit": "deadbeef",
        "files": {
            "oyster_knowledge.db": {"sha256": kb_sha},
            "vector_db/chroma.sqlite3": {"sha256": vec_sha},
        },
    }
    import json
    (staging / "manifest.json").write_text(json.dumps(manifest))

    archive = tmp_path / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(kb_db, arcname="oyster_knowledge.db")
        tf.add(staging / "manifest.json", arcname="manifest.json")
        tf.add(vector_db, arcname="vector_db")

    sidecar = tmp_path / f"{name}.tar.gz.sha256"
    sidecar.write_text(f"{_sha256_file(archive)}  {archive.name}\n")
    return archive


def _populated_target(tmp_path):
    memory_db = tmp_path / "target" / "memory.db"
    vector_db = tmp_path / "target" / "vector_db"
    memory_db.parent.mkdir(parents=True)
    con = sqlite3.connect(str(memory_db))
    con.execute("CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, content TEXT)")
    con.execute("INSERT INTO knowledge_chunks VALUES ('original', 'pre-existing data')")
    con.commit()
    con.close()
    vector_db.mkdir()
    (vector_db / "chroma.sqlite3").write_bytes(b"original-live-chroma-bytes")
    return memory_db, vector_db


def test_restore_dry_run_end_to_end_writes_nothing_against_a_populated_target(tmp_path, monkeypatch):
    memory_db, vector_db = _populated_target(tmp_path)
    before_mem, before_vec = _sha256_file(memory_db), _sha256_file(vector_db / "chroma.sqlite3")

    monkeypatch.setattr(rk.config, "MEMORY_DB", str(memory_db))
    monkeypatch.setattr(rk.config, "VECTOR_DB_DIR", str(vector_db))

    archive = _build_package(tmp_path)
    result = rk.restore(archive, decrypt=False, dry_run=True)

    assert result["dry_run"] is True
    assert result["passed"] is True
    # nothing about the live store may have moved
    assert _sha256_file(memory_db) == before_mem
    assert _sha256_file(vector_db / "chroma.sqlite3") == before_vec
    assert list(memory_db.parent.glob("*.bak-*")) == []
    assert list(vector_db.parent.glob("vector_db.bak-*")) == []


def test_restore_refuses_and_preserves_target_on_checksum_mismatch(tmp_path, monkeypatch):
    """The one failure mode this script can reliably guarantee preserves the
    target: a tampered/corrupt package. Verification happens before the
    write phase (rename/copy/merge), so a caught mismatch must leave the
    target completely untouched -- not partially migrated."""
    memory_db, vector_db = _populated_target(tmp_path)
    before_mem, before_vec = _sha256_file(memory_db), _sha256_file(vector_db / "chroma.sqlite3")

    monkeypatch.setattr(rk.config, "MEMORY_DB", str(memory_db))
    monkeypatch.setattr(rk.config, "VECTOR_DB_DIR", str(vector_db))

    archive = _build_package(tmp_path, name="tampered", tamper=True)
    with pytest.raises(SystemExit, match="CHECKSUM MISMATCH"):
        rk.restore(archive, decrypt=False, force=True)

    assert _sha256_file(memory_db) == before_mem, "target memory.db must be untouched after a caught mismatch"
    assert _sha256_file(vector_db / "chroma.sqlite3") == before_vec, \
        "target vector_db must be untouched after a caught mismatch"
    assert list(memory_db.parent.glob("*.bak-*")) == [], "no backup should exist -- nothing was ever replaced"
    assert list(vector_db.parent.glob("vector_db.bak-*")) == []
