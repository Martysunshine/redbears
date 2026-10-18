#!/usr/bin/env python3
"""Package the verified knowledge base for secure, out-of-Git transfer.

Produces a portable, checksummed archive of the ACTIVE knowledge store so the
exact ``106k+`` verified chunks can be restored on another machine (Martin's box,
a deployment server) without pushing a 2 GB database into GitHub.

Privacy by construction — this NEVER copies the whole ``memory.db``. It exports
only a strict allow-list of knowledge/vulnerability/graph/controls tables into a
fresh SQLite file; every operator-personal table (conversations, user memories,
findings, projects, execution history, training, datasets) is excluded, and the
result is asserted to contain none of them.

``vector_db`` is a different matter, and the distinction is the whole privacy
story. It is tarred WHOLE, so every Chroma collection in it travels — the SQLite
table allow-list does not apply there at all. This docstring used to assert the
store held only ``oyster_knowledge`` and ``oyster_vulnerabilities``; nothing
checked that, and on the production store it is false. It holds
``oyster_knowledge``, ``oyster_dataset_eval``, ``oyster_user_memory`` and
``oyster_docs`` — and ``oyster_docs`` contains real uploaded document text.

``_assert_vector_db_is_knowledge_only`` now enumerates the collections and
refuses to package when any fall outside the allow-list, so the claim is
enforced rather than repeated. ``--force`` packages anyway, and the manifest
records exactly which collections shipped.

The archive is written under ``data/packages/`` (gitignored) with a JSON manifest
(per-file sha256 + audit summary + git commit + embedding model) and a ``.sha256``
of the archive itself. Optional AES-256 encryption via ``--encrypt`` (passphrase
from ``OYSTER_PKG_PASSPHRASE``) for transfer over an untrusted channel.

Run (from ``backend/``, venv active, backend NOT writing):
    python -m scripts.package_knowledge
    python -m scripts.package_knowledge --encrypt         # AES-256 via openssl
    python -m scripts.package_knowledge --out /path/dir
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

# Allow-list: knowledge, structured vulnerability intelligence, the derived
# knowledge graph, and NIST/OSCAL controls. Everything NOT here is excluded.
KB_TABLES = [
    "knowledge_packs", "knowledge_chunks", "knowledge_pack_updates", "knowledge_import_jobs",
    "vulnerability_records", "vulnerability_cwe_links", "vulnerability_import_jobs",
    "vulnerability_sync_state", "cve_cvss_scores",
    "cwe_records", "capec_records", "capec_cwe_links",
    "osv_records", "osv_affected", "osv_aliases", "osv_cwe_links",
    "ghsa_advisories", "ghsa_affected", "ghsa_aliases", "ghsa_cwe_links", "ghsa_osv_sync_state",
    "vendor_advisories", "vendor_advisory_findings",
    "cisa_csaf_seen", "redhat_csaf_seen",
    "kg_nodes", "kg_edges", "kg_inconsistencies", "kg_build_runs",
    "control_records", "control_links", "control_sync_state",
]

# Explicitly operator-personal / operational — must NEVER appear in an export.
FORBIDDEN_TABLES = {
    "memories", "scan_results", "attack_surface", "user_memories", "user_memory_settings",
    "user_findings", "user_prefs", "user_profiles", "user_training_consent",
    "conversations", "conversation_messages", "projects", "project_events",
    "artifacts", "artifact_upload_quota",
    "execution_proposals", "policy_decisions", "approvals", "tool_executions",
    "execution_outputs", "exec_evidence", "exec_findings", "cleanup_records", "exec_audit",
    "tool_settings", "training_adapters", "training_consent", "training_datasets",
    "training_jobs", "installed_datasets", "dataset_chunks", "dataset_import_jobs",
    "eval_runs", "eval_results",
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def export_knowledge_db(src: Path, dst: Path) -> dict:
    """Copy ONLY the allow-listed KB tables from ``src`` into a fresh ``dst``.
    Returns {table: rowcount}. Regenerates the FTS lexical index from scratch."""
    if dst.exists():
        dst.unlink()
    con = sqlite3.connect(str(dst), uri=False)
    con.execute("PRAGMA journal_mode=OFF")
    con.execute("PRAGMA synchronous=OFF")
    con.execute(f"ATTACH 'file:{src}?mode=ro' AS src", ())
    counts: dict[str, int] = {}
    present = {r[0] for r in con.execute(
        "SELECT name FROM src.sqlite_master WHERE type='table'")}
    for t in KB_TABLES:
        if t not in present:
            continue
        create_sql = con.execute(
            "SELECT sql FROM src.sqlite_master WHERE type='table' AND name=?", (t,)
        ).fetchone()[0]
        con.execute(create_sql)
        # Explicit non-generated column list — PRAGMA table_info omits GENERATED
        # VIRTUAL/STORED columns, which cannot be inserted into (e.g. kg_nodes).
        cols = [r[1] for r in con.execute(f"PRAGMA main.table_info(\"{t}\")")]
        collist = ",".join(f'"{c}"' for c in cols)
        con.execute(f"INSERT INTO main.\"{t}\" ({collist}) SELECT {collist} FROM src.\"{t}\"")
        for (isql,) in con.execute(
            "SELECT sql FROM src.sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (t,)
        ):
            try:
                con.execute(isql)
            except sqlite3.OperationalError:
                pass
        counts[t] = con.execute(f"SELECT COUNT(*) FROM main.\"{t}\"").fetchone()[0]
    # regenerate the lexical index (never copied from src — always rebuilt clean)
    con.execute(
        "CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(chunk_id UNINDEXED, "
        "pack_id UNINDEXED, content, tokenize='porter unicode61')"
    )
    con.execute(
        "INSERT INTO knowledge_chunks_fts (chunk_id,pack_id,content) "
        "SELECT id, pack_id, COALESCE(content,'') FROM knowledge_chunks"
    )
    con.commit()
    con.execute("DETACH src")

    # privacy assertion — no forbidden table may exist in the export
    exported = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    leaked = exported & FORBIDDEN_TABLES
    con.close()
    if leaked:
        raise RuntimeError(f"REFUSING to package: personal tables leaked into export: {sorted(leaked)}")
    return counts


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(_BACKEND_DIR), stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return None


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# The Chroma collections a knowledge package is allowed to carry. Anything else
# in vector_db is operator data that must not travel with it.
KNOWLEDGE_COLLECTIONS = {"oyster_knowledge", "oyster_vulnerabilities"}


def _vector_collections(vector_db: Path) -> dict[str, int]:
    """Collection name -> embedding count for the store about to be archived."""
    chroma = vector_db / "chroma.sqlite3"
    if not chroma.exists():
        return {}
    con = sqlite3.connect(f"file:{chroma}?mode=ro", uri=True, timeout=30)
    try:
        return {name: int(n) for name, n in con.execute(
            "SELECT c.name, COUNT(e.id) FROM collections c "
            "LEFT JOIN segments s ON s.collection = c.id "
            "LEFT JOIN embeddings e ON e.segment_id = s.id GROUP BY c.name")}
    except sqlite3.Error:
        # Unreadable means unknown, and unknown must not pass a privacy gate.
        return {"<unreadable>": -1}
    finally:
        con.close()


def _assert_vector_db_is_knowledge_only(vector_db: Path, force: bool) -> dict[str, int]:
    """Check what this module used to merely assert.

    The docstring claimed the store held only the two knowledge collections, so
    `vector_db` could be tarred whole. That was never verified at runtime, and on
    the production store it is false: it holds oyster_knowledge,
    oyster_dataset_eval, oyster_user_memory and oyster_docs — and oyster_docs
    contains real uploaded document text, which would ship inside a package
    documented as privacy-safe.

    A wrong assumption in a privacy claim has to fail loudly, so this refuses
    rather than warns. --force still packages, but then the operator has chosen
    it knowing what travels.
    """
    found = _vector_collections(vector_db)
    extra = {k: v for k, v in found.items() if k not in KNOWLEDGE_COLLECTIONS}
    if not extra:
        return found

    print("\nvector_db holds collections outside the knowledge allow-list:")
    for name, n in sorted(extra.items()):
        print(f"  {name}: {n:,} embeddings")
    if not force:
        raise SystemExit(
            "REFUSING to package: the archive would carry the collections above.\n"
            "  package_knowledge tars vector_db whole, so every collection in it travels,\n"
            "  regardless of the SQLite table allow-list. oyster_docs in particular holds\n"
            "  uploaded document text.\n"
            "  Package from a store that holds only knowledge collections, or pass --force\n"
            "  and treat the result as sensitive: encrypt it, and never put it on a\n"
            "  presigned URL or any channel you would not send the source documents over."
        )
    print("  ! --force: packaging anyway — treat this archive as containing the above\n")
    return found


def build_package(out_dir: Path, encrypt: bool, force: bool) -> dict:
    memory_db = Path(config.MEMORY_DB)
    vector_db = Path(config.VECTOR_DB_DIR)

    print("Auditing active store before packaging…")
    audit = audit_knowledge.audit(floor=40, threshold=100_000)
    eligible = audit["eligible"]["eligible_unique_searchable_chunks"]
    if not audit["passed"] and not force:
        raise SystemExit(
            f"REFUSING to package: audit did not pass (eligible={eligible:,} < 100,000). "
            "Fix the store or pass --force to package an unverified snapshot.")

    # Before anything is staged: the whole vector_db is about to be archived, so
    # prove it holds only knowledge collections instead of assuming it.
    vector_collections = _assert_vector_db_is_knowledge_only(vector_db, force)

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    staging = Path(tempfile.mkdtemp(prefix="oyster_pkg_"))
    try:
        kb_db = staging / "oyster_knowledge.db"
        print("Exporting knowledge-only SQLite (allow-listed tables)…")
        table_counts = export_knowledge_db(memory_db, kb_db)

        # per-file checksums (exported db + every vector_db file)
        files: dict[str, dict] = {"oyster_knowledge.db": {
            "sha256": _sha256(kb_db), "bytes": kb_db.stat().st_size}}
        for p in sorted(vector_db.rglob("*")):
            if p.is_file():
                rel = "vector_db/" + str(p.relative_to(vector_db))
                files[rel] = {"sha256": _sha256(p), "bytes": p.stat().st_size}

        manifest = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "git_commit": _git_commit(),
            "embedding_model": audit["embedding"]["model"],
            "embedding_dimensions": audit["embedding"]["dimensions"],
            "eligible_unique_searchable_chunks": eligible,
            "total_records": audit["totals"]["total_records"],
            "source_count": audit["source_count"],
            "collections": audit["database"]["collections"],
            # What the tar actually carries, recorded so a recipient can see it
            # without unpacking and re-deriving it.
            "vector_collections_shipped": vector_collections,
            "table_row_counts": table_counts,
            "files": files,
            "restore_targets": ["memory.db (KB tables merged)", "vector_db (replaced)"],
        }
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2))

        # bundle the evidence reports if present
        ev_dir = staging / "evidence"
        ev_dir.mkdir()
        reports = Path(config.DATA_DIR) / "reports"
        for name in ("knowledge_audit_latest.json", "retrieval_eval_retrieval-100k-v1_latest.json"):
            src = reports / name
            if src.exists():
                shutil.copy2(src, ev_dir / name)

        archive = out_dir / f"oyster-kb-{stamp}.tar.zst"
        print(f"Creating archive {archive.name} (this moves ~2 GB; please wait)…")
        comp = "zstd -T0 -3" if _have("zstd") else None
        if comp:
            subprocess.check_call([
                "tar", "--use-compress-program", comp, "-cf", str(archive),
                "-C", str(staging), "oyster_knowledge.db", "manifest.json", "evidence",
                "-C", str(vector_db.parent), vector_db.name,
            ])
        else:
            archive = out_dir / f"oyster-kb-{stamp}.tar.gz"
            subprocess.check_call([
                "tar", "-czf", str(archive),
                "-C", str(staging), "oyster_knowledge.db", "manifest.json", "evidence",
                "-C", str(vector_db.parent), vector_db.name,
            ])

        archive_sha = _sha256(archive)
        (out_dir / (archive.name + ".sha256")).write_text(f"{archive_sha}  {archive.name}\n")

        final = archive
        if encrypt:
            passphrase = os.environ.get("OYSTER_PKG_PASSPHRASE")
            if not passphrase:
                raise SystemExit("--encrypt requires OYSTER_PKG_PASSPHRASE in the environment")
            if not _have("openssl"):
                raise SystemExit("openssl not found; cannot encrypt")
            enc = out_dir / (archive.name + ".enc")
            subprocess.run(
                ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt",
                 "-in", str(archive), "-out", str(enc), "-pass", "env:OYSTER_PKG_PASSPHRASE"],
                check=True,
            )
            archive.unlink()
            (out_dir / (archive.name + ".sha256")).unlink(missing_ok=True)
            (out_dir / (enc.name + ".sha256")).write_text(f"{_sha256(enc)}  {enc.name}\n")
            final = enc

        return {
            "archive": str(final),
            "archive_bytes": final.stat().st_size,
            "archive_sha256": _sha256(final),
            "manifest_files": len(files),
            "eligible_unique_searchable_chunks": eligible,
            "encrypted": encrypt,
        }
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Package the verified knowledge base for transfer.")
    ap.add_argument("--out", default=str(Path(config.DATA_DIR) / "packages"),
                    help="Output directory (gitignored). Default: data/packages/")
    ap.add_argument("--encrypt", action="store_true", help="AES-256 encrypt (needs OYSTER_PKG_PASSPHRASE).")
    ap.add_argument("--force", action="store_true", help="Package even if the audit gate fails.")
    args = ap.parse_args()

    result = build_package(Path(args.out), encrypt=args.encrypt, force=args.force)
    print("\n" + "=" * 66)
    print("PACKAGE COMPLETE")
    print("=" * 66)
    for k, v in result.items():
        if k == "archive_bytes":
            print(f"  {k:<34}: {v:,} bytes ({v / 1e9:.2f} GB)")
        else:
            print(f"  {k:<34}: {v}")
    print("=" * 66)
    print("  Transfer this file out-of-band (scp / S3 presigned / encrypted drive).")
    print("  Restore on the target with: python -m scripts.restore_knowledge --package <file>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
