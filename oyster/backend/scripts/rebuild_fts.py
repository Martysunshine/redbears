#!/usr/bin/env python3
"""Repair the knowledge lexical (FTS5) index so it covers EVERY provenance chunk.

Background: ``knowledge_chunks_fts`` is the lexical half of the Knowledge
Service's hybrid retrieval (vector + FTS, fused by reciprocal-rank fusion in
``services/knowledge/retrieval.py``). The git/STIX connectors populate it via
``store.replace_chunks`` / ``store.upsert_chunk``, but a batch of later bulk
ingestions (the docs packs, detection-content packs and the vulnerability feeds)
loaded rows into ``knowledge_chunks`` + Chroma without ever writing the FTS row —
so the vector half indexes 100% of chunks while the lexical half lagged far
behind. Vector search still covers every chunk, so retrieval never broke, but
exact-term / identifier lexical matching was blind to the newer packs.

This repair is **purely additive**: it inserts ONLY the FTS rows that are
missing (``knowledge_chunks`` ids absent from ``knowledge_chunks_fts``). It never
deletes or modifies a ``knowledge_chunks`` row and never touches Chroma.
Idempotent — a rerun inserts nothing once nothing is missing, and a rerun after
an interruption simply resumes (see "Safety design" below).

Safety design (2026-09-14 rewrite — see the commit body / AI_HANDOFF.md for why)
----------------------------------------------------------------------------
The previous version of this script had two real bugs, found by inspection, not
assumed from a bug report:

1. ``--dry-run`` was not actually read-only. It ran ``CREATE VIRTUAL TABLE IF
   NOT EXISTS`` (twice — once for an FTS5-availability probe, once for
   ``knowledge_chunks_fts`` itself) and created a temp table, unconditionally,
   even in dry-run mode. Against an already-populated database these are
   effectively no-ops, but a script named ``--dry-run`` must never issue a
   single write statement against the real target — the promise is that
   nothing is contingent on database state.
2. The actual insert was ONE unbatched statement covering every missing row
   (potentially ~70k+ rows against production). That holds SQLite's write lock
   for the statement's entire duration; a live service's own connections queue
   behind it and fail once they exceed their own ``busy_timeout`` (Oyster's
   services use a short one — seconds, not minutes).

This version fixes both, plus adds the guards a script that may eventually run
against a live production database needs:

* **Dry-run is enforced read-only by SQLite itself**, not merely by our own
  code discipline: it opens the target with ``file:...?mode=ro`` (SQLite's own
  read-only URI mode), so ANY write attempt would raise
  ``sqlite3.OperationalError`` rather than silently succeeding. The FTS5
  availability probe runs against an isolated ``:memory:`` connection that
  never touches the target file at all. The "missing" count is computed by
  diffing two id sets in Python (no temp table, no write of any kind).
* **Apply is batched.** Each batch is its own bounded ``BEGIN IMMEDIATE`` /
  ``INSERT`` / ``COMMIT`` — the write lock is held for roughly one batch's
  duration, then released, so a live service's queued connections get a turn
  between batches instead of blocking for the whole rebuild. A crash or kill
  mid-batch loses at most that one in-flight batch (never committed, so never
  partially present); every prior batch stays committed. Because "missing" is
  always recomputed from current state, a rerun after an interruption simply
  continues — no resume token needed.
* **Pre-flight refusals** (skippable with ``force=True`` / ``--force``, and
  each one is refuse-first, i.e. fails closed): a lock-contention probe (an
  ``BEGIN IMMEDIATE`` + immediate ``ROLLBACK`` on a short timeout — this is
  best-effort like ``restore_knowledge.py``'s equivalent guard: it catches an
  active writer transaction, not merely another process with the file open for
  reading) and a disk-space estimate (``missing_count`` × average chunk length
  × an FTS5 overhead factor, compared against free space on the target's
  volume via ``shutil.disk_usage``; this is a heuristic safety margin, not an
  exact prediction).
* **Verification, not just counts.** After every batch is applied, the run
  recomputes the still-missing count AND runs ``PRAGMA integrity_check`` on a
  fresh connection. The result dict's ``passed`` field is only ``True`` when
  both are clean — the CLI never prints PASS on a count mismatch or a failed
  integrity check, even if every batch's own INSERT nominally "succeeded".
* **No table swap.** A shadow-table-plus-atomic-rename design was considered
  (per the "shortest atomic swap" instinct that applies to a *replacing*
  rebuild) and deliberately NOT used here: this repair only ever ADDS rows to
  the existing ``knowledge_chunks_fts`` table, so the live table is never
  dropped, replaced, or in a state where it is "missing" — every reader at
  every moment sees either the pre-run state or a fully-committed superset of
  it. An FTS5 virtual-table rename is extra engineering risk (it must rename
  the module's own shadow tables too, and its behaviour is not identical across
  SQLite versions) that buys nothing here, since there is no moment this
  additive repair needs to hide.
* **A rollback path exists even though this is additive-only.** Every apply
  run writes a manifest (``data/reports/fts_rebuild_<timestamp>.json`` +
  ``..._latest.json``, gitignored) listing exactly which chunk ids it
  inserted. ``rollback(manifest_path)`` / ``--rollback <path>`` deletes exactly
  those ids from ``knowledge_chunks_fts`` (never touches ``knowledge_chunks``,
  the source of truth) and verifies the count returns to the manifest's
  ``fts_before``.
* **Never touches any table besides ``knowledge_chunks_fts``.** ``knowledge_chunks``
  is read-only in every code path in this script.

Run (from ``backend/``):
    python -m scripts.rebuild_fts                       # apply (batched, verified)
    python -m scripts.rebuild_fts --dry-run              # report the gap only, zero writes
    python -m scripts.rebuild_fts --batch-size 500       # smaller batches
    python -m scripts.rebuild_fts --force                # skip lock/disk pre-flight refusals
    python -m scripts.rebuild_fts --rollback <manifest>  # undo exactly one prior apply run
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402

BATCH = 2000
MAX_BATCH_SIZE = 50_000
# Missing-row content estimate is multiplied by this to size the disk-space
# check: FTS5's porter/unicode61 tokenizer index plus its shadow tables
# (`_content`, `_docsize`, `_idx`, ...) run larger than the raw text alone —
# this is a heuristic margin, not a measured constant.
_DISK_OVERHEAD_FACTOR = 3.0
_DISK_SAFETY_MARGIN = 1.5
_LOCK_PROBE_TIMEOUT_S = 0.2


class RebuildRefused(RuntimeError):
    """Raised for a pre-flight refusal (lock contention, disk space, bad batch
    size, missing/ambiguous target) — distinct from a genuine SQLite failure,
    so callers and tests can tell "we chose not to run" from "it broke"."""


def _resolve_db_path(db_path) -> Path:
    p = Path(db_path if db_path is not None else config.MEMORY_DB).resolve()
    return p


def _fts5_available() -> bool:
    """Whether this Python's sqlite3 build supports FTS5 — checked on an
    isolated in-memory connection that never touches the target database."""
    con = sqlite3.connect(":memory:")
    try:
        con.execute("CREATE VIRTUAL TABLE probe USING fts5(x)")
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        con.close()


def _fts_table_exists(con: sqlite3.Connection) -> bool:
    row = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name='knowledge_chunks_fts'"
    ).fetchone()
    return row is not None


def _counts(con: sqlite3.Connection, fts_exists: bool) -> tuple[int, int]:
    total = con.execute("SELECT COUNT(*) FROM knowledge_chunks").fetchone()[0]
    fts = con.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0] if fts_exists else 0
    return total, fts


def _missing_count_readonly(con: sqlite3.Connection, fts_exists: bool) -> int:
    have = {r[0] for r in con.execute("SELECT chunk_id FROM knowledge_chunks_fts")} if fts_exists else set()
    missing = 0
    for (cid,) in con.execute("SELECT id FROM knowledge_chunks"):
        if cid not in have:
            missing += 1
    return missing


def _integrity_ok(db_path: Path) -> bool:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    except sqlite3.Error:
        return False
    finally:
        con.close()


def _evaluate(*, still_missing: int, integrity_ok: bool) -> bool:
    """The single source of truth for whether a run may be reported as
    'passed'. Kept as a small pure function so the pass/fail logic itself is
    directly unit-testable without needing to simulate real corruption."""
    return still_missing == 0 and integrity_ok


def _probe_lock_contention(db_path: Path) -> bool:
    """Best-effort: True if another connection currently holds a write
    transaction. Like ``restore_knowledge.py``'s equivalent guard, this catches
    an ACTIVE WRITER, not merely another process with the file open — SQLite
    grants the lock whenever no connection is mid-write."""
    try:
        con = sqlite3.connect(str(db_path), timeout=_LOCK_PROBE_TIMEOUT_S)
    except sqlite3.Error:
        return False
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute("ROLLBACK")
        return False
    except sqlite3.OperationalError:
        return True
    finally:
        con.close()


def _estimate_bytes_needed(con: sqlite3.Connection, missing_count: int) -> int:
    if missing_count <= 0:
        return 0
    row = con.execute("SELECT AVG(LENGTH(COALESCE(content, ''))) FROM knowledge_chunks").fetchone()
    avg_len = float(row[0] or 0.0)
    return int(missing_count * avg_len * _DISK_OVERHEAD_FACTOR)


def _reports_dir() -> Path:
    d = Path(config.DATA_DIR) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _write_manifest(payload: dict) -> Path:
    reports_dir = _reports_dir()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = reports_dir / f"fts_rebuild_{ts}.json"
    latest = reports_dir / "fts_rebuild_latest.json"
    text = json.dumps(payload, indent=2)
    out.write_text(text)
    latest.write_text(text)
    return out


def rebuild(
    dry_run: bool = False,
    *,
    batch_size: int = BATCH,
    force: bool = False,
    db_path=None,
    on_batch: Callable[[int, int], None] | None = None,
) -> dict:
    """Fill every gap in ``knowledge_chunks_fts``.

    ``dry_run=True`` performs ZERO writes (enforced by SQLite's own read-only
    connection mode, not just care in this function) and reports the gap.
    Otherwise, inserts the missing rows in bounded, independently-committed
    batches of ``batch_size`` and returns a result dict whose ``passed`` field
    is only ``True`` when the post-run count AND ``PRAGMA integrity_check``
    both check out. ``on_batch(inserted_so_far, batch_len)`` is called after
    every committed batch — used for progress reporting and is exactly what the
    tests hook to verify batching/interruption behaviour.

    Raises :class:`RebuildRefused` for a pre-flight refusal (bad batch size,
    missing target, active writer, insufficient disk space) rather than
    attempting a write and hoping — every refusal here is a decision made
    BEFORE any write is issued.
    """
    if not isinstance(batch_size, int) or batch_size <= 0:
        raise RebuildRefused(f"batch_size must be a positive int, got {batch_size!r}")
    if batch_size > MAX_BATCH_SIZE:
        raise RebuildRefused(f"batch_size {batch_size} exceeds the maximum {MAX_BATCH_SIZE}")

    target = _resolve_db_path(db_path)

    if not _fts5_available():
        return {"error": "sqlite build has no FTS5; lexical falls back to LIKE — nothing to rebuild"}

    if dry_run:
        if not target.exists():
            return {"dry_run": True, "total_chunks": 0, "fts_before": 0, "missing_from_fts": 0,
                     "note": f"target does not exist: {target}"}
        con = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=30)
        try:
            fts_exists = _fts_table_exists(con)
            total_chunks, fts_before = _counts(con, fts_exists)
            missing = _missing_count_readonly(con, fts_exists)
        finally:
            con.close()
        return {
            "dry_run": True,
            "target": str(target),
            "total_chunks": total_chunks,
            "fts_before": fts_before,
            "missing_from_fts": missing,
        }

    # --- apply path -----------------------------------------------------
    if not target.exists():
        raise RebuildRefused(f"refusing to apply: target database does not exist: {target}")
    if not target.is_file():
        raise RebuildRefused(f"refusing to apply: target is not a regular file: {target}")

    if not force and _probe_lock_contention(target):
        raise RebuildRefused(
            f"refusing to apply: {target} appears to have an active writer transaction "
            "right now (best-effort check). Re-run once it is idle, or pass force=True / "
            "--force if you are certain it is safe."
        )

    con = sqlite3.connect(str(target), timeout=30)
    con.execute("PRAGMA busy_timeout = 30000")
    try:
        con.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks_fts "
            "USING fts5(chunk_id UNINDEXED, pack_id UNINDEXED, content, "
            "tokenize='porter unicode61')"
        )
        total_chunks, fts_before = _counts(con, True)

        have = {r[0] for r in con.execute("SELECT chunk_id FROM knowledge_chunks_fts")}
        missing_count = con.execute(
            "SELECT COUNT(*) FROM knowledge_chunks WHERE id NOT IN "
            "(SELECT chunk_id FROM knowledge_chunks_fts)"
        ).fetchone()[0] if total_chunks else 0

        if not force and missing_count:
            needed = _estimate_bytes_needed(con, missing_count)
            free = shutil.disk_usage(target.parent).free
            if free < needed * _DISK_SAFETY_MARGIN:
                raise RebuildRefused(
                    f"refusing to apply: insufficient disk space — estimated ~{needed / 1e6:.1f}MB "
                    f"needed for {missing_count} missing rows (with a {_DISK_SAFETY_MARGIN}x safety "
                    f"margin), but only {free / 1e6:.1f}MB free at {target.parent}. Free up "
                    "space, or pass force=True / --force if the estimate is overly cautious."
                )

        inserted_ids: list[str] = []
        pending: list[tuple[str, str, str]] = []
        total_inserted = 0

        def _flush() -> None:
            nonlocal pending, total_inserted
            if not pending:
                return
            con.execute("BEGIN IMMEDIATE")
            try:
                con.executemany(
                    "INSERT INTO knowledge_chunks_fts (chunk_id, pack_id, content) VALUES (?,?,?)",
                    pending,
                )
            except Exception:
                con.execute("ROLLBACK")
                raise
            con.commit()
            total_inserted += len(pending)
            inserted_ids.extend(row[0] for row in pending)
            if on_batch is not None:
                on_batch(total_inserted, len(pending))
            pending = []

        cur = con.execute("SELECT id, pack_id, content FROM knowledge_chunks")
        while True:
            rows = cur.fetchmany(batch_size)
            if not rows:
                break
            for cid, pack_id, content in rows:
                if cid in have:
                    continue
                pending.append((cid, pack_id, content or ""))
                if len(pending) >= batch_size:
                    _flush()
        _flush()  # remainder shorter than one full batch

        total_chunks_after, fts_after = _counts(con, True)
    finally:
        con.close()

    # Always re-verify with a fresh read-only connection rather than trusting
    # the write connection's own counts — this is the one place a "PASS" claim
    # has to be earned, not assumed, and the read-only re-scan is cheap (no
    # write lock, so it never contends with the live service either).
    con2 = sqlite3.connect(f"file:{target}?mode=ro", uri=True, timeout=30)
    try:
        still_missing = _missing_count_readonly(con2, True)
    finally:
        con2.close()

    integrity_ok = _integrity_ok(target)
    passed = _evaluate(still_missing=still_missing, integrity_ok=integrity_ok)

    result = {
        "dry_run": False,
        "target": str(target),
        "total_chunks": total_chunks_after,
        "fts_before": fts_before,
        "fts_after": fts_after,
        "inserted": total_inserted,
        "still_missing": still_missing,
        "integrity_ok": integrity_ok,
        "passed": passed,
        "batch_size": batch_size,
    }

    manifest = {
        **result,
        "inserted_chunk_ids": inserted_ids,
        "run_at": datetime.now(timezone.utc).isoformat(),
    }
    result["manifest_path"] = str(_write_manifest(manifest))
    return result


def rollback(manifest_path, *, db_path=None, force: bool = False) -> dict:
    """Undo exactly one prior :func:`rebuild` apply run: delete exactly the
    chunk ids that run inserted from ``knowledge_chunks_fts``. Never touches
    ``knowledge_chunks`` — that table is the source of truth and this script
    never writes to it in either direction."""
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    target = _resolve_db_path(db_path if db_path is not None else manifest.get("target"))

    if not force and manifest.get("target") and Path(manifest["target"]).resolve() != target:
        raise RebuildRefused(
            f"refusing to rollback: manifest target {manifest['target']!r} does not match "
            f"resolved target {target}. Pass force=True / --force if this is intentional."
        )
    if not target.exists():
        raise RebuildRefused(f"refusing to rollback: target database does not exist: {target}")
    if not force and _probe_lock_contention(target):
        raise RebuildRefused(f"refusing to rollback: {target} appears to have an active writer transaction right now.")

    ids = manifest.get("inserted_chunk_ids", [])
    con = sqlite3.connect(str(target), timeout=30)
    con.execute("PRAGMA busy_timeout = 30000")
    try:
        fts_exists = _fts_table_exists(con)
        _, fts_before_rollback = _counts(con, fts_exists)
        batch_size = manifest.get("batch_size", BATCH)
        deleted = 0
        for i in range(0, len(ids), batch_size):
            batch = ids[i:i + batch_size]
            con.execute("BEGIN IMMEDIATE")
            con.executemany("DELETE FROM knowledge_chunks_fts WHERE chunk_id = ?", [(x,) for x in batch])
            con.commit()
            deleted += len(batch)
        _, fts_after_rollback = _counts(con, fts_exists)
    finally:
        con.close()

    expected_after = fts_before_rollback - deleted
    return {
        "target": str(target),
        "manifest_path": str(manifest_path),
        "requested": len(ids),
        "deleted": deleted,
        "fts_before_rollback": fts_before_rollback,
        "fts_after_rollback": fts_after_rollback,
        "matches_expected": fts_after_rollback == expected_after,
        "restored_to_pre_run_count": fts_after_rollback == manifest.get("fts_before"),
        "integrity_ok": _integrity_ok(target),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Rebuild the knowledge FTS lexical index (additive, batched).")
    ap.add_argument("--dry-run", action="store_true", help="Report the gap without any write. Genuinely read-only.")
    ap.add_argument("--batch-size", type=int, default=BATCH, help=f"Rows per committed batch (default {BATCH}).")
    ap.add_argument("--force", action="store_true",
                     help="Skip the lock-contention and disk-space pre-flight refusals.")
    ap.add_argument("--db-path", default=None, help="Override the target database path (default: config.MEMORY_DB).")
    ap.add_argument("--rollback", default=None, metavar="MANIFEST_PATH",
                     help="Undo exactly one prior apply run, using its manifest JSON.")
    args = ap.parse_args()

    if args.rollback:
        try:
            result = rollback(args.rollback, db_path=args.db_path, force=args.force)
        except RebuildRefused as exc:
            print(f"REFUSED: {exc}")
            return 3
        print("FTS rollback:", json.dumps(result, indent=2))
        return 0 if result["matches_expected"] and result["integrity_ok"] else 1

    def _progress(total_inserted: int, batch_len: int) -> None:
        print(f"  ...committed batch of {batch_len} (running total inserted: {total_inserted})", flush=True)

    started = time.monotonic()
    try:
        result = rebuild(dry_run=args.dry_run, batch_size=args.batch_size, force=args.force,
                          db_path=args.db_path, on_batch=None if args.dry_run else _progress)
    except RebuildRefused as exc:
        print(f"REFUSED: {exc}")
        return 3
    elapsed = time.monotonic() - started

    print(f"FTS rebuild ({elapsed:.1f}s):", json.dumps(result, indent=2))
    if args.dry_run:
        return 0
    if "error" in result:
        return 2
    if not result["passed"]:
        print("RESULT: FAIL — counts or integrity check did not verify clean. Do not treat this as PASS.")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
