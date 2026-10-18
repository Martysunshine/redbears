#!/usr/bin/env python3
"""Emit the reproducibility manifest for the knowledge base.

Records, for every installed pack, the exact upstream ref (git commit / version)
and content checksum that produced the current store — so the knowledge base can
be rebuilt from primary sources (see ``reingest_all.py``) on a machine that has
no snapshot archive. Written to ``deploy/pinned_sources.json`` (committed — it is
small, non-personal reproducibility metadata).

Run (from ``backend/``):
    python -m scripts.export_source_manifest
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402


def build() -> dict:
    con = sqlite3.connect(f"file:{config.MEMORY_DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    packs = []
    # last succeeded import ref per connector (full commit SHA where available)
    refs = {}
    for r in con.execute(
        "SELECT connector_id, ref FROM knowledge_import_jobs "
        "WHERE status='succeeded' AND ref IS NOT NULL ORDER BY started_at"):
        refs[r["connector_id"]] = r["ref"]
    for r in con.execute(
        "SELECT pack_id, version, licence, trust_level, pack_kind, content_checksum, "
        "doc_count, chunk_count FROM knowledge_packs ORDER BY pack_id"):
        packs.append({
            "pack_id": r["pack_id"],
            "version": r["version"],
            "upstream_ref": refs.get(r["pack_id"]),
            "licence": r["licence"],
            "trust_level": r["trust_level"],
            "pack_kind": r["pack_kind"],
            "content_checksum": r["content_checksum"],
            "doc_count": r["doc_count"],
            "chunk_count": r["chunk_count"],
        })
    vuln_state = [dict(r) for r in con.execute("SELECT * FROM vulnerability_sync_state")]
    con.close()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "embedding_model": getattr(config, "EMBED_MODEL", None),
        "note": ("Rebuild-from-source manifest. Snapshot restore (restore_knowledge.py) "
                 "is the exact, primary path; this reproducible rebuild depends on upstream "
                 "availability and may not reproduce byte-identical counts."),
        "pack_count": len(packs),
        "packs": packs,
        "vulnerability_sync_state": vuln_state,
    }


def main() -> int:
    out = _BACKEND_DIR / "deploy" / "pinned_sources.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(build(), indent=2))
    print(f"wrote {out} ({(build()['pack_count'])} packs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
