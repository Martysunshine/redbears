#!/usr/bin/env python3
"""Consistent, verified snapshot of Oyster's knowledge store.

Why this is not `cp -r data/ backup/`
-------------------------------------
`memory.db` runs in WAL mode. A plain copy captures the main database file
without the write-ahead log, so it silently yields a STALE database — every
commit since the last checkpoint is missing, and nothing about the copy looks
wrong. SQLite's online backup API is the only correct way to copy a live WAL
database, and it is what this script uses for both SQLite files.

The Chroma segment directories are an HNSW index *derived* from
`chroma.sqlite3`. Chroma treats the SQLite file as authoritative and replays
into a stale segment, so the safe ordering is: snapshot SQLite first, then copy
the segments. That way the segments can only ever be newer than the metadata,
which Chroma tolerates; the reverse would leave dangling references.

A backup is not a backup until it has been read back. Every run re-opens what it
wrote, runs `PRAGMA integrity_check`, recounts every Chroma collection, and
compares those counts against the live store. A mismatch fails the run loudly
rather than leaving a plausible-looking corrupt archive.

The encryption key
------------------
`memory.db` is encrypted at rest with `data/.memory_key`. A snapshot without
that key is unrecoverable, so `--include-key` (default on) writes it BESIDE the
snapshot rather than inside the archive, mode 0600, so you can choose to store
it somewhere other than the data. The manifest always records which of the two
happened; a restore that finds no key says so instead of failing obscurely.

Running it
----------
On the VPS, against the bind-mounted store (no container needed — `data/` is
mounted from the host at `/root/voiceiq/oyster/backend/data`):

    python3 scripts/backup_knowledge.py \
        --data /root/voiceiq/oyster/backend/data \
        --dest /root/oyster-backups --archive

Then pull it off the box, because a snapshot on the same disk is a copy, not a
backup. Do NOT trust `scp` here: it has twice died mid-transfer on this link
with "connection reset by peer" while still reporting success, leaving a
truncated archive. Use rsync (`--partial --append-verify`) where it exists, and
always compare the SHA-256 against the value this script prints. A short file
and a wrong hash are the same failure; only the hash catches both.

This is deliberately NOT the counterpart of `restore_knowledge.py`. That script
replaces the store (it DROPs the 33 KB tables and swaps `vector_db` wholesale)
and must not be pointed at a populated production directory. What this produces
is a verified archive to restore FROM, by hand, into an empty target.

2026-09-15: ported into this branch (oyster/verified-100k-knowledge) from
main commit 4a171754, which this branch never had, as part of the release
reconciliation for missing production-safety fixes. Content is reproduced
faithfully from main; nothing here has been adapted to this branch's
`config.py`, since the script deliberately takes its own `--data` path rather
than importing the backend config, so it can run standalone against a bind
mount with no backend process involved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tarfile
import time
from pathlib import Path

DATA = Path("/app/data")
SQLITE_FILES = ("memory.db", "vector_db/chroma.sqlite3")
KEY_FILE = ".memory_key"

# Copied wholesale: small, and stale backups of them are harmless.
EXTRA_FILES = ("documents.json",)
EXTRA_DIRS = ("artifacts", "training", "uploads", "socmat")


def log(msg: str) -> None:
    print(f"[backup] {msg}", flush=True)


def sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def online_copy(src: Path, dst: Path) -> None:
    """Copy a live SQLite database using the online backup API.

    Opening read-only means this never blocks writers and never creates a
    -wal/-shm beside the source. `backup()` handles a database being written
    underneath it by restarting the pages it needs.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        dst.unlink()
    source = sqlite3.connect(f"file:{src}?mode=ro", uri=True, timeout=60)
    target = sqlite3.connect(str(dst), timeout=60)
    try:
        source.backup(target)
        # 2026-09-15: added during the release reconciliation port. backup()
        # copies the source's page-level WAL flag along with everything else,
        # so `dst` comes out of this call marked as a WAL-mode database even
        # though no -wal/-shm file was ever created FOR IT. A later read-only
        # connection (integrity_ok, restore_knowledge, or an operator's own
        # sqlite3 file:...?mode=ro) then fails with "unable to open database
        # file", because SQLite can't set up the WAL shared-memory index a
        # read-only connection needs. Checkpointing and switching to DELETE
        # mode here folds the WAL back into the main file, so the snapshot is
        # a normal, self-contained, read-only-safe single file.
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        target.execute("PRAGMA journal_mode=DELETE")
    finally:
        target.close()
        source.close()


def collection_counts(chroma_sqlite: Path) -> dict:
    """Rows per Chroma collection, by name.

    Chroma keys everything on the collection UUID, not the name, so this joins
    through `segments` -> `embeddings`. Returning {} rather than raising keeps a
    schema change from turning a good backup into a failed run; the caller
    treats {} as "could not verify" and says so.
    """
    try:
        con = sqlite3.connect(f"file:{chroma_sqlite}?mode=ro", uri=True, timeout=60)
    except sqlite3.Error:
        return {}
    try:
        rows = con.execute(
            """
            SELECT c.name, COUNT(e.id)
              FROM collections c
              LEFT JOIN segments s ON s.collection = c.id
              LEFT JOIN embeddings e ON e.segment_id = s.id
             GROUP BY c.name
            """
        ).fetchall()
        return {name: int(n) for name, n in rows}
    except sqlite3.Error:
        return {}
    finally:
        con.close()


def integrity_ok(db: Path) -> bool:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=120)
    try:
        return con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    except sqlite3.Error:
        return False
    finally:
        con.close()


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024.0
    return f"{n:.1f}GB"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dest", required=True, help="directory to write the snapshot into")
    ap.add_argument("--data", default=str(DATA), help="Oyster data directory")
    ap.add_argument("--archive", action="store_true", help="also produce a .tar.gz")
    ap.add_argument("--no-include-key", action="store_true",
                    help="do NOT copy .memory_key; the snapshot will not be restorable alone")
    ap.add_argument("--stamp", default="", help="snapshot name (default: derived from mtime)")
    args = ap.parse_args()

    data = Path(args.data)
    if not data.is_dir():
        log(f"FATAL: data dir {data} does not exist")
        return 2

    # Derived from the newest file rather than the clock, so two runs over an
    # idle store produce the same name instead of silently piling up copies.
    stamp = args.stamp or time.strftime(
        "%Y%m%d-%H%M%S", time.gmtime(max(p.stat().st_mtime for p in data.rglob("*") if p.is_file()))
    )
    dest = Path(args.dest) / f"oyster-knowledge-{stamp}"
    if dest.exists():
        log(f"FATAL: {dest} already exists — refusing to overwrite a snapshot")
        return 2
    dest.mkdir(parents=True)
    log(f"snapshot -> {dest}")

    live_counts = collection_counts(data / "vector_db/chroma.sqlite3")
    log(f"live collections: {live_counts or '(could not read)'}")

    manifest = {
        "stamp": stamp,
        "source": str(data),
        "sqlite": {},
        "segments": {},
        "live_collection_counts": live_counts,
        "key_included": False,
    }

    # 1. SQLite first — see module docstring for why the order matters.
    for rel in SQLITE_FILES:
        src, dst = data / rel, dest / rel
        if not src.exists():
            log(f"WARN: {rel} missing, skipping")
            continue
        log(f"online-copy {rel} ({human(src.stat().st_size)}) ...")
        online_copy(src, dst)
        manifest["sqlite"][rel] = {"bytes": dst.stat().st_size, "sha256": sha256(dst)}

    # 2. Chroma segment dirs (everything in vector_db that is not the SQLite file).
    vdb = data / "vector_db"
    if vdb.is_dir():
        for child in sorted(vdb.iterdir()):
            if child.is_dir():
                log(f"copy segment {child.name} ...")
                shutil.copytree(child, dest / "vector_db" / child.name)
                manifest["segments"][child.name] = sum(
                    p.stat().st_size for p in (dest / "vector_db" / child.name).rglob("*") if p.is_file()
                )

    # 3. Small auxiliary state.
    for rel in EXTRA_FILES:
        if (data / rel).exists():
            shutil.copy2(data / rel, dest / rel)
    for rel in EXTRA_DIRS:
        if (data / rel).is_dir():
            shutil.copytree(data / rel, dest / rel, dirs_exist_ok=True)

    # 4. The key, beside the snapshot rather than inside it.
    if not args.no_include_key and (data / KEY_FILE).exists():
        key_dst = Path(args.dest) / f"oyster-knowledge-{stamp}.key"
        shutil.copy2(data / KEY_FILE, key_dst)
        os.chmod(key_dst, 0o600)
        manifest["key_included"] = True
        log(f"key written to {key_dst.name} (mode 0600) — store this separately from the data")
    else:
        log("NOTE: no key copied — memory.db in this snapshot cannot be decrypted alone")

    # 5. Verify. A backup that has not been read back is a hope, not a backup.
    log("verifying ...")
    problems = []
    for rel in manifest["sqlite"]:
        if not integrity_ok(dest / rel):
            problems.append(f"integrity_check failed: {rel}")
        else:
            log(f"  integrity ok: {rel}")

    backup_counts = collection_counts(dest / "vector_db/chroma.sqlite3")
    manifest["backup_collection_counts"] = backup_counts
    if live_counts and backup_counts != live_counts:
        # Writes during the copy are expected and fine; a SHORTFALL is not.
        for name, n in live_counts.items():
            got = backup_counts.get(name, 0)
            if got < n:
                problems.append(f"collection {name}: live {n} -> backup {got} (LOST ROWS)")
        for name, n in backup_counts.items():
            if name not in live_counts:
                log(f"  note: collection {name} ({n}) appeared during copy")
    if backup_counts:
        log(f"  backup collections: {backup_counts}")

    total = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
    manifest["total_bytes"] = total
    manifest["problems"] = problems
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    if problems:
        log("VERIFICATION FAILED:")
        for p in problems:
            log(f"  - {p}")
        log(f"snapshot left at {dest} for inspection — DO NOT trust it")
        return 1

    log(f"verified OK — {human(total)} at {dest}")

    if args.archive:
        tgz = Path(args.dest) / f"oyster-knowledge-{stamp}.tar.gz"
        log(f"archiving -> {tgz.name} ...")
        with tarfile.open(tgz, "w:gz") as tf:
            tf.add(dest, arcname=dest.name)
        os.chmod(tgz, 0o600)
        log(f"archive {human(tgz.stat().st_size)} sha256={sha256(tgz)[:16]}...")

    return 0


if __name__ == "__main__":
    sys.exit(main())
