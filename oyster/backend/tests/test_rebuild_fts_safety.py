"""Safety-focused tests for the 2026-09-14 ``rebuild_fts.py`` rewrite.

These exercise the specific guarantees the rewrite adds on top of the original
additive/idempotent repair (already covered by
``test_knowledge_100k_audit.py::test_fts_rebuild_is_additive_and_idempotent``):
genuinely read-only ``--dry-run``, bounded batches, crash/interruption safety,
lock-contention and disk-space pre-flight refusals, verification that never
reports PASS on a mismatch, and a rollback path.

Every test builds its OWN isolated temp-directory SQLite database — never the
real knowledge store, never a shared fixture that could leak state between
tests, and never anything under ``config.MEMORY_DB`` unless explicitly
overridden via ``db_path=``.
"""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from scripts import rebuild_fts

_LONG = "This is a complete, meaningful cybersecurity knowledge fact about detecting and mitigating an attack technique." * 2


def _build_memory_db(path: Path, chunks: list[dict], with_fts_ids: list[str] | None = None) -> None:
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, pack_id TEXT, content TEXT)"
    )
    for c in chunks:
        con.execute(
            "INSERT INTO knowledge_chunks (id, pack_id, content) VALUES (?,?,?)",
            (c["id"], c["pack_id"], c.get("content", _LONG)),
        )
    con.execute(
        "CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(chunk_id UNINDEXED, pack_id UNINDEXED, "
        "content, tokenize='porter unicode61')"
    )
    for cid in (with_fts_ids or []):
        row = next((c for c in chunks if c["id"] == cid), None)
        if row:
            con.execute("INSERT INTO knowledge_chunks_fts (chunk_id,pack_id,content) VALUES (?,?,?)",
                        (cid, row["pack_id"], row.get("content", _LONG)))
    con.commit()
    con.close()


def _chunks(n: int) -> list[dict]:
    return [{"id": f"k{i}", "pack_id": "p", "content": _LONG} for i in range(n)]


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _fts_count(path: Path) -> int:
    con = sqlite3.connect(str(path))
    try:
        return con.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0]
    finally:
        con.close()


# --- dry-run is genuinely read-only -----------------------------------------

def test_dry_run_performs_zero_writes(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(10), with_fts_ids=["k0"])
    before = _sha256(mem)

    result = rebuild_fts.rebuild(dry_run=True, db_path=mem)
    assert result["missing_from_fts"] == 9
    assert result["total_chunks"] == 10
    assert result["fts_before"] == 1

    after = _sha256(mem)
    assert before == after, "dry-run must not change a single byte of the target file"
    assert not (tmp_path / "memory.db-wal").exists()
    assert not (tmp_path / "memory.db-journal").exists()


def test_dry_run_on_fully_populated_store_reports_zero_missing(tmp_path):
    mem = tmp_path / "memory.db"
    ids = [f"k{i}" for i in range(6)]
    _build_memory_db(mem, _chunks(6), with_fts_ids=ids)
    before = _sha256(mem)
    result = rebuild_fts.rebuild(dry_run=True, db_path=mem)
    assert result["missing_from_fts"] == 0
    assert _sha256(mem) == before


def test_dry_run_on_nonexistent_target_reports_gracefully_without_creating_it(tmp_path):
    missing = tmp_path / "does_not_exist.db"
    result = rebuild_fts.rebuild(dry_run=True, db_path=missing)
    assert result["missing_from_fts"] == 0
    assert "note" in result
    assert not missing.exists()


# --- populated database, basic apply ----------------------------------------

def test_apply_on_populated_database_inserts_only_the_gap(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(10), with_fts_ids=["k0", "k1", "k2"])
    result = rebuild_fts.rebuild(db_path=mem)
    assert result["passed"] is True
    assert result["inserted"] == 7
    assert result["fts_after"] == 10
    assert result["still_missing"] == 0
    assert result["integrity_ok"] is True


# --- batch boundaries --------------------------------------------------------

def test_batch_boundaries_are_respected(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(25), with_fts_ids=[])
    batch_lens: list[int] = []
    result = rebuild_fts.rebuild(db_path=mem, batch_size=10, on_batch=lambda total, n: batch_lens.append(n))
    assert result["inserted"] == 25
    assert batch_lens == [10, 10, 5]  # last batch is the remainder, not padded


def test_batch_boundaries_exact_multiple(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(20), with_fts_ids=[])
    batch_lens: list[int] = []
    rebuild_fts.rebuild(db_path=mem, batch_size=5, on_batch=lambda total, n: batch_lens.append(n))
    assert batch_lens == [5, 5, 5, 5]


# --- interruption halfway through -------------------------------------------

def _flaky_connect_factory(target_path, fail_at_call: int, call_counter: dict):
    """``sqlite3.Connection`` is an immutable C type — its methods cannot be
    monkeypatched directly. Instead, wrap ``sqlite3.connect`` so that a
    connection opened to ``target_path`` (and only that path — every read-only
    verification connection elsewhere is untouched) is built via a subclass
    whose ``executemany`` raises on the ``fail_at_call``-th INSERT batch,
    simulating a crash at exactly that point."""
    orig_connect = sqlite3.connect

    class _FlakyConnection(sqlite3.Connection):
        def executemany(self, sql, params):
            if "INSERT INTO knowledge_chunks_fts" in sql:
                call_counter["n"] += 1
                if call_counter["n"] == fail_at_call:
                    raise sqlite3.OperationalError("simulated crash mid-run")
            return super().executemany(sql, params)

    def patched_connect(database, *args, **kwargs):
        if str(database) == str(target_path):
            return orig_connect(database, *args, factory=_FlakyConnection, **kwargs)
        return orig_connect(database, *args, **kwargs)

    return patched_connect


def test_interruption_mid_run_loses_only_the_uncommitted_batch_and_resumes(tmp_path, monkeypatch):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(25), with_fts_ids=[])

    monkeypatch.setattr(
        rebuild_fts.sqlite3, "connect",
        _flaky_connect_factory(mem, fail_at_call=2, call_counter={"n": 0}),
    )
    with pytest.raises(sqlite3.OperationalError):
        rebuild_fts.rebuild(db_path=mem, batch_size=10)
    monkeypatch.undo()

    # Only the first (successfully committed) batch landed — never a partial one.
    assert _fts_count(mem) == 10

    # A rerun with no fault injected simply resumes and finishes the rest.
    result = rebuild_fts.rebuild(db_path=mem, batch_size=10)
    assert result["passed"] is True
    assert result["fts_after"] == 25
    assert result["inserted"] == 15  # only what was still missing


# --- atomicity: a failed batch inserts nothing partial ----------------------

def test_failed_batch_inserts_nothing_partial(tmp_path, monkeypatch):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(10), with_fts_ids=[])

    monkeypatch.setattr(
        rebuild_fts.sqlite3, "connect",
        _flaky_connect_factory(mem, fail_at_call=1, call_counter={"n": 0}),
    )
    with pytest.raises(sqlite3.OperationalError):
        rebuild_fts.rebuild(db_path=mem, batch_size=10)
    monkeypatch.undo()

    # All-or-nothing: not 1..9 rows, exactly zero — the batch's own transaction
    # rolled back in full.
    assert _fts_count(mem) == 0


# --- lock contention ----------------------------------------------------------

def test_apply_refuses_when_another_connection_holds_a_write_transaction(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(3), with_fts_ids=[])

    holder = sqlite3.connect(str(mem))
    holder.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(rebuild_fts.RebuildRefused, match="active writer"):
            rebuild_fts.rebuild(db_path=mem)
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    assert _fts_count(mem) == 0  # refused before any write was attempted


def test_force_skips_the_lock_preflight_check_when_nothing_is_actually_locked(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(3), with_fts_ids=[])
    result = rebuild_fts.rebuild(db_path=mem, force=True)
    assert result["passed"] is True
    assert result["inserted"] == 3


# --- invalid batch sizes ------------------------------------------------------

@pytest.mark.parametrize("bad", [0, -1, -100])
def test_zero_or_negative_batch_size_refused(tmp_path, bad):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(3), with_fts_ids=[])
    with pytest.raises(rebuild_fts.RebuildRefused):
        rebuild_fts.rebuild(db_path=mem, batch_size=bad)
    assert _fts_count(mem) == 0


def test_non_int_batch_size_refused(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(3), with_fts_ids=[])
    with pytest.raises(rebuild_fts.RebuildRefused):
        rebuild_fts.rebuild(db_path=mem, batch_size="2000")  # type: ignore[arg-type]


def test_oversized_batch_size_refused(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(3), with_fts_ids=[])
    with pytest.raises(rebuild_fts.RebuildRefused):
        rebuild_fts.rebuild(db_path=mem, batch_size=rebuild_fts.MAX_BATCH_SIZE + 1)


# --- insufficient disk space --------------------------------------------------

def test_insufficient_disk_space_refuses_without_force(tmp_path, monkeypatch):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(5), with_fts_ids=[])

    class _FakeUsage:
        free = 1  # effectively zero

    monkeypatch.setattr(rebuild_fts.shutil, "disk_usage", lambda path: _FakeUsage())
    with pytest.raises(rebuild_fts.RebuildRefused, match="disk space"):
        rebuild_fts.rebuild(db_path=mem)
    assert _fts_count(mem) == 0


def test_insufficient_disk_space_force_bypasses(tmp_path, monkeypatch):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(5), with_fts_ids=[])

    class _FakeUsage:
        free = 1

    monkeypatch.setattr(rebuild_fts.shutil, "disk_usage", lambda path: _FakeUsage())
    result = rebuild_fts.rebuild(db_path=mem, force=True)
    assert result["passed"] is True
    assert result["inserted"] == 5


# --- count mismatch / failed verification never reports PASS -----------------

def test_evaluate_fails_closed_on_missing_rows():
    assert rebuild_fts._evaluate(still_missing=1, integrity_ok=True) is False


def test_evaluate_fails_closed_on_bad_integrity():
    assert rebuild_fts._evaluate(still_missing=0, integrity_ok=False) is False


def test_evaluate_passes_only_when_both_clean():
    assert rebuild_fts._evaluate(still_missing=0, integrity_ok=True) is True


def test_apply_reports_fail_when_integrity_check_fails_even_though_insert_succeeded(tmp_path, monkeypatch):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(5), with_fts_ids=[])
    monkeypatch.setattr(rebuild_fts, "_integrity_ok", lambda path: False)

    result = rebuild_fts.rebuild(db_path=mem)
    assert result["inserted"] == 5           # the insert itself worked
    assert result["integrity_ok"] is False
    assert result["passed"] is False          # never reported as PASS regardless


# --- rollback ------------------------------------------------------------------

def test_rollback_undoes_exactly_one_apply_run(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(10), with_fts_ids=["k0", "k1"])

    result = rebuild_fts.rebuild(db_path=mem)
    assert result["inserted"] == 8
    assert result["fts_after"] == 10

    rb = rebuild_fts.rollback(result["manifest_path"], db_path=mem)
    assert rb["deleted"] == 8
    assert rb["fts_after_rollback"] == 2
    assert rb["restored_to_pre_run_count"] is True
    assert rb["matches_expected"] is True
    assert rb["integrity_ok"] is True

    # Source of truth (knowledge_chunks) is never touched by rollback.
    con = sqlite3.connect(str(mem))
    assert con.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0] == 10
    con.close()


def test_rollback_refuses_manifest_target_mismatch_without_force(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(3), with_fts_ids=[])
    result = rebuild_fts.rebuild(db_path=mem)

    other = tmp_path / "other.db"
    _build_memory_db(other, _chunks(3), with_fts_ids=[])

    with pytest.raises(rebuild_fts.RebuildRefused, match="does not match"):
        rebuild_fts.rollback(result["manifest_path"], db_path=other)


# --- repeated / idempotent execution ------------------------------------------

def test_repeated_apply_is_idempotent(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(15), with_fts_ids=[])

    first = rebuild_fts.rebuild(db_path=mem, batch_size=4)
    assert first["inserted"] == 15
    assert first["passed"] is True

    second = rebuild_fts.rebuild(db_path=mem, batch_size=4)
    assert second["inserted"] == 0
    assert second["passed"] is True
    assert second["fts_after"] == 15


# --- no loss of unrelated tables or user data ---------------------------------

def test_unrelated_tables_and_rows_are_never_touched(tmp_path):
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, _chunks(5), with_fts_ids=[])

    con = sqlite3.connect(str(mem))
    con.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY, title TEXT)")
    con.execute("INSERT INTO conversations VALUES ('c1', 'A private conversation title')")
    con.commit()
    con.close()

    result = rebuild_fts.rebuild(db_path=mem)
    assert result["passed"] is True
    rebuild_fts.rollback(result["manifest_path"], db_path=mem)

    con = sqlite3.connect(str(mem))
    row = con.execute("SELECT title FROM conversations WHERE id='c1'").fetchone()
    con.close()
    assert row == ("A private conversation title",)


# --- ambiguous / unsafe targets ------------------------------------------------

def test_apply_refuses_nonexistent_target(tmp_path):
    missing = tmp_path / "does_not_exist.db"
    with pytest.raises(rebuild_fts.RebuildRefused, match="does not exist"):
        rebuild_fts.rebuild(db_path=missing)


def test_apply_refuses_a_directory_as_target(tmp_path):
    a_dir = tmp_path / "not_a_file"
    a_dir.mkdir()
    with pytest.raises(rebuild_fts.RebuildRefused, match="not a regular file"):
        rebuild_fts.rebuild(db_path=a_dir)
