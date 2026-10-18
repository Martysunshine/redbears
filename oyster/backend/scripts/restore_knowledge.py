#!/usr/bin/env python3
"""Restore a packaged knowledge base onto this machine and verify it.

Reverses ``package_knowledge.py``: verifies the archive checksum, (optionally)
decrypts, extracts, verifies every file's sha256 against the manifest, then
installs the knowledge base into the local Oyster store and runs the audit to
prove the target holds the expected >=100k chunks.

THIS REPLACES THE KNOWLEDGE BASE. IT DOES NOT MERGE ONE IN.
------------------------------------------------------------------------------
An earlier version of this docstring said the KB tables were "replaced
(merged)", which read as though a restore would add to what was already here.
It does not. ``_merge_kb`` DROPs each of the 33 KB tables in the target and
recreates it from the package, and the whole ``vector_db`` directory is moved
aside and superseded. Whatever the target held in those tables is gone from the
live store afterwards — recoverable only from the ``.bak-*`` copies this makes.

So the destination for a restore is an EMPTY or SCRATCH store. Pointing it at a
populated production directory is a destructive operation, and ``_preflight``
below refuses to do it without ``--force``.

What is genuinely preserved: tables outside ``KB_TABLES`` (personal data, user
memory, settings) are untouched by the merge step. But note those rows keep
referring to a vector store that has just been swapped underneath them, so
target-side documents and memories can be left pointing at embeddings that are
no longer there.

Never run this against a store a container is still serving. The rename at
``vector_db.rename(bak)`` does not stop a running process: it keeps its open
file handles on the now-renamed inode and goes on writing into the backup,
where those writes are silently lost. ``_preflight`` tries to take an exclusive
lock precisely to catch that.

Safety:
  * Refuses a populated target unless ``--force`` (see ``_preflight``).
  * Refuses while another process holds the store open, unless ``--force``.
  * A missing ``.sha256`` sidecar is fatal unless ``--allow-unverified``; it used
    to print a warning and continue into the destructive phase.
  * ``--dry-run`` reports what would be replaced and changes nothing.
  * The existing ``vector_db`` is renamed, not deleted, and ``memory.db`` is
    copied first. Both land beside the originals, so restoring needs free space
    for a second copy of the store.

Run (from ``backend/``, venv active, backend NOT running):
    python -m scripts.restore_knowledge --package /path/oyster-kb-<stamp>.tar.zst --dry-run
    python -m scripts.restore_knowledge --package /path/oyster-kb-<stamp>.tar.zst
    python -m scripts.restore_knowledge --package <file>.enc --decrypt   # needs OYSTER_PKG_PASSPHRASE
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402
from scripts import audit_knowledge  # noqa: E402
from scripts.package_knowledge import FORBIDDEN_TABLES, KB_TABLES  # noqa: E402


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _verify_archive_checksum(archive: Path, allow_unverified: bool = False) -> None:
    sidecar = archive.parent / (archive.name + ".sha256")
    if not sidecar.exists():
        # This used to warn and carry on into the destructive phase, which meant
        # a truncated download — the exact failure this link produces, twice
        # observed — would be unpacked over the live store. An unverifiable
        # archive is refused; --allow-unverified is for a package you built
        # yourself and never moved.
        if not allow_unverified:
            raise SystemExit(
                f"REFUSING: no {sidecar.name} beside the archive, so it cannot be verified.\n"
                f"  A truncated or corrupt package would be unpacked over the target store.\n"
                f"  Re-download it with its .sha256, or pass --allow-unverified if you are\n"
                f"  certain of this file's provenance."
            )
        print(f"  ! no {sidecar.name} sidecar — proceeding UNVERIFIED (--allow-unverified)")
        return
    expected = sidecar.read_text().split()[0]
    actual = _sha256(archive)
    if expected != actual:
        raise SystemExit(f"ARCHIVE CHECKSUM MISMATCH\n  expected {expected}\n  actual   {actual}")
    print("  archive sha256 OK")


def _store_population(memory_db: Path, vector_db: Path) -> dict:
    """What the target already holds, in the terms that matter for a restore.

    Counted read-only and defensively: a target that cannot be opened is treated
    as populated, because refusing a restore we could have allowed is a wasted
    minute, and allowing one we should have refused is unrecoverable.
    """
    info = {"kb_rows": 0, "collections": {}, "readable": True}

    if memory_db.exists():
        try:
            con = sqlite3.connect(f"file:{memory_db}?mode=ro", uri=True, timeout=10)
            try:
                have = {r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                for t in KB_TABLES:
                    if t in have:
                        info["kb_rows"] += con.execute(
                            f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            finally:
                con.close()
        except sqlite3.Error:
            info["readable"] = False

    chroma = vector_db / "chroma.sqlite3"
    if chroma.exists():
        try:
            con = sqlite3.connect(f"file:{chroma}?mode=ro", uri=True, timeout=10)
            try:
                info["collections"] = {
                    name: int(n) for name, n in con.execute(
                        "SELECT c.name, COUNT(e.id) FROM collections c "
                        "LEFT JOIN segments s ON s.collection = c.id "
                        "LEFT JOIN embeddings e ON e.segment_id = s.id GROUP BY c.name")
                }
            finally:
                con.close()
        except sqlite3.Error:
            info["readable"] = False

    return info


def _is_in_use(memory_db: Path, vector_db: Path) -> str | None:
    """Name a store file another process is holding, or None.

    A restore renames ``vector_db`` aside. That does not disturb a process which
    already has the files open — it keeps writing through its existing handles,
    into what is now the backup, and those writes are lost when the backup is
    later discarded. An exclusive lock is the cheap way to notice a container is
    still serving this directory before anything has moved.

    BEST-EFFORT, and measured as such: verified against the live production
    store with the container up and serving, this returned None. SQLite grants
    an exclusive lock whenever no other connection is mid-write, so an idle-but-
    running backend is invisible to it. It catches a busy writer, not an open
    file. The populated-store check is the guard that actually holds; treat this
    as a second chance, never as clearance to restore onto a running service.
    Confirm the container is stopped yourself.
    """
    for db in (memory_db, vector_db / "chroma.sqlite3"):
        if not db.exists():
            continue
        try:
            con = sqlite3.connect(str(db), timeout=2)
            try:
                con.execute("BEGIN EXCLUSIVE")
                con.execute("ROLLBACK")
            finally:
                con.close()
        except sqlite3.OperationalError:
            return db.name
        except sqlite3.DatabaseError:
            # 2026-09-15: a corrupt/non-SQLite file raises DatabaseError, not
            # OperationalError -- a sibling under sqlite3.Error, not a subclass,
            # so the original except clause let this crash instead of degrading.
            # _store_population's separate readable=False check already refuses
            # an unreadable store; this just has to not blow up while checking
            # for a lock, not add a second opinion about readability.
            continue
    return None


def _preflight(memory_db: Path, vector_db: Path, force: bool, dry_run: bool = False) -> dict:
    """Refuse a destructive restore onto a store that is populated or live.

    A dry run writes nothing, so it reports what would be refused instead of
    refusing — otherwise the one command that is safe to point at production is
    also the one you cannot use to find out what would happen.
    """
    pop = _store_population(memory_db, vector_db)
    total_vectors = sum(pop["collections"].values())
    populated = pop["kb_rows"] > 0 or total_vectors > 0 or not pop["readable"]

    print("Target store:")
    print(f"  memory.db   : {memory_db}  ({pop['kb_rows']:,} rows across KB tables)")
    print(f"  vector_db   : {vector_db}  ({total_vectors:,} embeddings"
          f"{', ' + ', '.join(f'{k} {v:,}' for k, v in sorted(pop['collections'].items())) if pop['collections'] else ''})")
    if not pop["readable"]:
        print("  ! could not read one of the stores — treating as populated")

    busy = _is_in_use(memory_db, vector_db)
    if busy and dry_run:
        print(f"  ! {busy} is open in another process — a real run would REFUSE here")
    elif busy and not force:
        raise SystemExit(
            f"\nREFUSING: {busy} is open in another process — the backend is probably running.\n"
            f"  Renaming vector_db under a live process does not stop it writing; those writes\n"
            f"  go to the renamed directory and are lost. Stop the container first:\n"
            f"      docker compose stop oyster-backend\n"
            f"  Then re-run. --force overrides this and will lose data."
        )

    if populated and dry_run:
        print("  ! target is populated — a real run would REFUSE here without --force")
    elif populated and not force:
        raise SystemExit(
            "\nREFUSING: the target already holds a knowledge base.\n"
            "  This script REPLACES it — it DROPs every KB table and swaps the whole\n"
            "  vector store. It does not add the package to what is here.\n"
            "  Restore into an empty directory instead (set OYSTER_MEMORY_DB and\n"
            "  OYSTER_VECTOR_DB_DIR at a scratch path), or take a verified backup first:\n"
            "      python3 scripts/backup_knowledge.py --data <data dir> --dest <somewhere> --archive\n"
            "  --force proceeds and destroys what is listed above."
        )

    if force and (populated or busy):
        print("  ! --force: proceeding over a populated/in-use store")
    return pop


def _merge_kb(kb_db: Path, target_db: Path) -> None:
    """Replace the KB tables in ``target_db`` with those from ``kb_db``; create
    the target if absent. Personal tables in the target are left untouched."""
    if not target_db.exists():
        shutil.copy2(kb_db, target_db)
        return
    con = sqlite3.connect(str(target_db))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute(f"ATTACH 'file:{kb_db}?mode=ro' AS pkg", ())
    pkg_tables = {r[0] for r in con.execute("SELECT name FROM pkg.sqlite_master WHERE type='table'")}
    for t in KB_TABLES:
        if t not in pkg_tables:
            continue
        con.execute(f"DROP TABLE IF EXISTS main.\"{t}\"")
        create_sql = con.execute(
            "SELECT sql FROM pkg.sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()[0]
        con.execute(create_sql)
        cols = [r[1] for r in con.execute(f"PRAGMA main.table_info(\"{t}\")")]  # excludes generated cols
        collist = ",".join(f'"{c}"' for c in cols)
        con.execute(f"INSERT INTO main.\"{t}\" ({collist}) SELECT {collist} FROM pkg.\"{t}\"")
        for (isql,) in con.execute(
            "SELECT sql FROM pkg.sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (t,)):
            try:
                con.execute(isql)
            except sqlite3.OperationalError:
                pass
    con.execute("DROP TABLE IF EXISTS main.knowledge_chunks_fts")
    con.execute(
        "CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(chunk_id UNINDEXED, "
        "pack_id UNINDEXED, content, tokenize='porter unicode61')")
    con.execute(
        "INSERT INTO knowledge_chunks_fts (chunk_id,pack_id,content) "
        "SELECT id, pack_id, COALESCE(content,'') FROM knowledge_chunks")
    con.execute("DETACH pkg")
    con.commit()
    con.close()


def restore(package: Path, decrypt: bool, force: bool = False,
            dry_run: bool = False, allow_unverified: bool = False) -> dict:
    memory_db = Path(config.MEMORY_DB)
    vector_db = Path(config.VECTOR_DB_DIR)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    print(f"Restoring from {package.name}")
    # Before anything is read from the archive: decide whether this target may
    # be written to at all. Cheap, and it fails while the store is still intact.
    _preflight(memory_db, vector_db, force=force, dry_run=dry_run)
    _verify_archive_checksum(package, allow_unverified=allow_unverified)

    work = Path(tempfile.mkdtemp(prefix="oyster_restore_"))
    try:
        archive = package
        if decrypt or package.suffix == ".enc":
            if not os.environ.get("OYSTER_PKG_PASSPHRASE"):
                raise SystemExit("decryption requires OYSTER_PKG_PASSPHRASE in the environment")
            dec = work / package.name.replace(".enc", "")
            subprocess.run(
                ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                 "-in", str(package), "-out", str(dec), "-pass", "env:OYSTER_PKG_PASSPHRASE"],
                check=True)
            archive = dec
            print("  decrypted OK")

        extract = work / "extract"
        extract.mkdir()
        subprocess.check_call(["tar", "-xf", str(archive), "-C", str(extract)])

        manifest = json.loads((extract / "manifest.json").read_text())
        print(f"  manifest: {manifest['eligible_unique_searchable_chunks']:,} eligible chunks, "
              f"commit {manifest.get('git_commit')}")

        # verify per-file checksums
        for rel, meta in manifest["files"].items():
            fp = extract / rel
            if not fp.exists():
                raise SystemExit(f"missing file in archive: {rel}")
            if _sha256(fp) != meta["sha256"]:
                raise SystemExit(f"CHECKSUM MISMATCH for {rel}")
        print(f"  verified {len(manifest['files'])} file checksums OK")

        # privacy re-check on the packaged DB
        kb_db = extract / "oyster_knowledge.db"
        con = sqlite3.connect(f"file:{kb_db}?mode=ro", uri=True)
        tabs = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        con.close()
        leaked = tabs & FORBIDDEN_TABLES
        if leaked:
            raise SystemExit(f"REFUSING restore: package contains personal tables {sorted(leaked)}")

        if dry_run:
            # Everything above is read-only: checksums, manifest, privacy check.
            # Everything below replaces the store. This is the line between them.
            print("\n--dry-run: archive verified, nothing written.")
            print("  A real run would from here:")
            print(f"    - rename {vector_db.name} -> {vector_db.name}.bak-<stamp> and put the package's in its place")
            print(f"    - copy {memory_db.name} aside, then DROP and repopulate {len(KB_TABLES)} KB tables")
            return {"restored_eligible": 0, "passed": True, "dry_run": True,
                    "memory_db": str(memory_db), "vector_db": str(vector_db)}

        # back up + place vector_db
        vector_db.parent.mkdir(parents=True, exist_ok=True)
        if vector_db.exists():
            bak = vector_db.with_name(f"{vector_db.name}.bak-{stamp}")
            vector_db.rename(bak)
            print(f"  backed up existing vector_db -> {bak.name}")
        shutil.move(str(extract / "vector_db"), str(vector_db))
        print("  vector_db placed")

        # merge KB tables into memory.db (backup first if present)
        if memory_db.exists():
            shutil.copy2(memory_db, memory_db.with_name(f"{memory_db.name}.bak-{stamp}"))
            print(f"  backed up existing memory.db -> {memory_db.name}.bak-{stamp}")
        memory_db.parent.mkdir(parents=True, exist_ok=True)
        _merge_kb(kb_db, memory_db)
        print("  knowledge tables merged into memory.db")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\nAuditing restored store…")
    audit = audit_knowledge.audit(floor=40, threshold=100_000)
    eligible = audit["eligible"]["eligible_unique_searchable_chunks"]
    print(f"  eligible unique searchable chunks: {eligible:,}  ->  {'PASS' if audit['passed'] else 'FAIL'}")
    return {
        "restored_eligible": eligible,
        "passed": audit["passed"],
        "memory_db": str(memory_db),
        "vector_db": str(vector_db),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Restore + verify a packaged knowledge base.")
    ap.add_argument("--package", required=True, help="Path to the .tar.zst / .tar.gz / .enc archive.")
    ap.add_argument("--decrypt", action="store_true", help="Decrypt first (needs OYSTER_PKG_PASSPHRASE).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Verify the archive and report what would be replaced. Writes nothing.")
    ap.add_argument("--force", action="store_true",
                    help="Proceed even though the target is populated or in use. DESTROYS the existing KB.")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="Proceed without a .sha256 sidecar. Only for a package you built and never moved.")
    args = ap.parse_args()
    result = restore(Path(args.package), decrypt=args.decrypt, force=args.force,
                     dry_run=args.dry_run, allow_unverified=args.allow_unverified)
    if result.get("dry_run"):
        return 0
    print("=" * 66)
    print(f"RESTORE {'OK' if result['passed'] else 'FAILED'} — {result['restored_eligible']:,} eligible chunks")
    print("=" * 66)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
