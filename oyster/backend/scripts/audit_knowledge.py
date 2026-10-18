#!/usr/bin/env python3
"""Authoritative audit of Oyster's active cybersecurity knowledge base.

This is the single source of truth for "how many real, unique, searchable,
source-attributed knowledge chunks does Oyster actually hold" — it inspects the
LIVE store (never README claims, memory files or old reports):

  * ``memory.db``            — the ``knowledge_chunks`` provenance table (SQLite)
  * ``vector_db/*.sqlite3``  — the Chroma persistent index (``oyster_knowledge``
                               + ``oyster_vulnerabilities`` collections)

A chunk is counted as an **eligible unique searchable knowledge chunk** only when
it satisfies every rule the definition requires:

  1. meaningful content         — trimmed length >= ``--floor`` chars (default 40),
                                  so chunker split-artifacts ("html", ")", "he
                                  program.") and empty rows never count;
  2. stored in the active store — a row in ``knowledge_chunks``;
  3. searchable representation  — its id is present as an embedding in the Chroma
                                  collection its pack routes to (so it is
                                  retrievable through Oyster's normal RAG path);
  4. source attribution         — a non-empty ``canonical_url``;
  5. stable unique id           — the row primary key (deterministic, so a
                                  re-ingest updates instead of multiplying);
  6. content hash               — a non-empty ``content_hash``;
  7. not an exact duplicate     — counted once per distinct ``content_hash``.

Structured ``vulnerability_records`` that are NOT embedded as knowledge chunks
(the ~370k NVD/OSV/GHSA rows reachable only by exact-id lookup) are deliberately
NOT counted here — counting them would be the artificial inflation the audit
exists to prevent.

Read-only. Produces a human-readable terminal summary AND a machine-readable
JSON report under ``data/reports/`` (gitignored). Exit code is non-zero when the
acceptance thresholds are not met, so it doubles as a CI / release gate.

Run (from ``backend/``):
    python -m scripts.audit_knowledge
    python -m scripts.audit_knowledge --json-only
    python -m scripts.audit_knowledge --floor 40 --threshold 100000
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Make ``config`` importable whether run as ``-m scripts.audit_knowledge`` or
# directly, without importing any heavy runtime module.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402  (pure-stdlib leaf per project architecture)

# Packs whose chunks live in the dedicated ``oyster_vulnerabilities`` collection
# (kept isolated from ``oyster_knowledge`` — see rag_service / knowledge.retrieval).
VULN_PACK_IDS = {"vulnerability-cve", "mitre-cwe", "mitre-capec"}

# all-MiniLM-L6-v2 is a 384-dim model; recorded for provenance in the report.
_KNOWN_EMBED_DIMS = {"all-MiniLM-L6-v2": 384, "all-mpnet-base-v2": 768}

DEFAULT_FLOOR = 40
DEFAULT_THRESHOLD = 100_000


def _ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def _norm_text(s: str) -> str:
    """Whitespace/case/markdown-punctuation-insensitive normalisation for a
    cheap, honest *near*-duplicate proxy (NOT semantic near-dup — that would be
    an O(n^2) embedding comparison we deliberately do not claim to do)."""
    s = (s or "").lower()
    s = re.sub(r"[`*_#>\-\[\]()!]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _chroma_indexed_ids(vector_db_dir: Path) -> dict[str, set[str]]:
    """Every embedding id present in the Chroma index, grouped by collection."""
    chroma_sqlite = vector_db_dir / "chroma.sqlite3"
    out: dict[str, set[str]] = {}
    if not chroma_sqlite.exists():
        return out
    con = _ro(chroma_sqlite)
    try:
        for (name,) in con.execute("SELECT name FROM collections"):
            out[name] = set()
        rows = con.execute(
            "SELECT c.name, e.embedding_id "
            "FROM collections c "
            "JOIN segments s ON s.collection = c.id "
            "JOIN embeddings e ON e.segment_id = s.id"
        )
        for name, eid in rows:
            out.setdefault(name, set()).add(eid)
    finally:
        con.close()
    return out


def audit(floor: int = DEFAULT_FLOOR, threshold: int = DEFAULT_THRESHOLD) -> dict:
    memory_db = Path(config.MEMORY_DB)
    vector_db_dir = Path(config.VECTOR_DB_DIR)
    know_collection = getattr(config, "KNOWLEDGE_COLLECTION", "oyster_knowledge")
    vuln_collection = getattr(config, "KNOWLEDGE_VULN_COLLECTION", "oyster_vulnerabilities")

    indexed = _chroma_indexed_ids(vector_db_dir)
    know_ids = indexed.get(know_collection, set())
    vuln_ids = indexed.get(vuln_collection, set())
    all_indexed = set().union(*indexed.values()) if indexed else set()

    con = _ro(memory_db)
    con.row_factory = sqlite3.Row

    # --- streaming pass over every chunk (no full-content load into memory) ---
    total = 0
    empty_trivial = 0
    missing_attr = 0
    missing_hash = 0
    missing_index = 0
    eligible_rows = 0
    eligible_hashes: set[str] = set()
    all_hashes: dict[str, int] = {}
    norm_groups: dict[str, set[str]] = {}
    per_source: dict[str, dict] = {}
    per_type: dict[str, int] = {}
    per_version: dict[str, int] = {}

    cur = con.execute(
        "SELECT id, pack_id, pack_version, source_type, content, content_hash, canonical_url "
        "FROM knowledge_chunks"
    )
    for row in cur:
        total += 1
        _id = row["id"]
        pack = row["pack_id"] or ""
        content = (row["content"] or "").strip()
        chash = row["content_hash"] or ""
        url = (row["canonical_url"] or "").strip()

        src = per_source.setdefault(
            pack, {"rows": 0, "unique_hashes": set(), "eligible": 0, "indexed": 0}
        )
        src["rows"] += 1
        if chash:
            src["unique_hashes"].add(chash)
            all_hashes[chash] = all_hashes.get(chash, 0) + 1
        per_type[row["source_type"] or "unknown"] = per_type.get(row["source_type"] or "unknown", 0) + 1
        pv = f"{pack}@{row['pack_version'] or ''}"
        per_version[pv] = per_version.get(pv, 0) + 1

        target = vuln_ids if pack in VULN_PACK_IDS else know_ids
        is_indexed = _id in target or _id in all_indexed
        if is_indexed:
            src["indexed"] += 1

        # eligibility gate
        if len(content) < floor:
            empty_trivial += 1
            continue
        if not chash:
            missing_hash += 1
            continue
        if not url:
            missing_attr += 1
            continue
        if not is_indexed:
            missing_index += 1
            continue

        eligible_rows += 1
        eligible_hashes.add(chash)
        src["eligible"] += 1
        norm_groups.setdefault(_norm_text(content), set()).add(chash)

    # latest ingestion + failed jobs
    latest_chunk = con.execute("SELECT MAX(created_at) FROM knowledge_chunks").fetchone()[0]

    def _table_exists(name: str) -> bool:
        return con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone() is not None

    failed_jobs = 0
    latest_job = None
    for jt in ("knowledge_import_jobs", "vulnerability_import_jobs"):
        if _table_exists(jt):
            failed_jobs += con.execute(
                f"SELECT COUNT(*) FROM {jt} WHERE status NOT IN ('succeeded','success','ok','complete','completed')"
            ).fetchone()[0]
            lj = con.execute(f"SELECT MAX(COALESCE(finished_at, started_at)) FROM {jt}").fetchone()[0]
            if lj and (latest_job is None or lj > latest_job):
                latest_job = lj

    fts_rows = None
    if _table_exists("knowledge_chunks_fts"):
        try:
            fts_rows = con.execute("SELECT COUNT(*) FROM knowledge_chunks_fts").fetchone()[0]
        except sqlite3.OperationalError:
            fts_rows = None

    structured = {}
    for t in ("vulnerability_records", "cwe_records", "capec_records"):
        if _table_exists(t):
            structured[t] = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]

    con.close()

    exact_dupe_rows = total - len(all_hashes)
    near_dupe_groups = sum(1 for hs in norm_groups.values() if len(hs) > 1)

    # orphan embeddings: indexed ids that have no knowledge_chunks row
    con2 = _ro(memory_db)
    kc_ids = set(r[0] for r in con2.execute("SELECT id FROM knowledge_chunks"))
    con2.close()
    # ``oyster_docs`` contains user-uploaded document embeddings and is not
    # represented in ``knowledge_chunks``.  Only the two authoritative
    # knowledge collections participate in this audit; counting document
    # embeddings as orphaned knowledge falsely fails a healthy corpus.
    knowledge_indexed_ids = know_ids | vuln_ids
    orphan_embeddings = len(knowledge_indexed_ids - kc_ids)

    eligible_unique = len(eligible_hashes)
    indexed_pct = round(100.0 * (eligible_rows / eligible_rows), 4) if eligible_rows else 0.0
    # index availability among eligible == 100% by construction (missing_index excluded),
    # so report it against the pre-index-filter eligible candidates instead:
    eligible_candidates = eligible_rows + missing_index
    index_availability_pct = round(
        100.0 * (eligible_rows / eligible_candidates), 4
    ) if eligible_candidates else 100.0

    sources = []
    for pack, s in sorted(per_source.items(), key=lambda kv: kv[1]["rows"], reverse=True):
        sources.append({
            "pack_id": pack,
            "rows": s["rows"],
            "unique_chunks": len(s["unique_hashes"]),
            "eligible_chunks": s["eligible"],
            "indexed": s["indexed"],
        })

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "knowledge_version": getattr(config, "KNOWLEDGE_VERSION", None) or "active-store",
        "floor_chars": floor,
        "threshold": threshold,
        "database": {
            "memory_db": str(memory_db),
            "memory_db_format": "sqlite3",
            "vector_db_dir": str(vector_db_dir),
            "vector_db_format": "chromadb (persistent, cosine)",
            "collections": {name: len(ids) for name, ids in indexed.items()},
        },
        "embedding": {
            "model": getattr(config, "EMBED_MODEL", None),
            "dimensions": _KNOWN_EMBED_DIMS.get(getattr(config, "EMBED_MODEL", ""), None),
        },
        "totals": {
            "total_records": total,
            "total_indexed_embeddings": len(all_indexed),
            "distinct_content_hashes": len(all_hashes),
            "exact_duplicate_rows": exact_dupe_rows,
            "near_duplicate_groups_normtext": near_dupe_groups,
            "empty_or_trivial_rows": empty_trivial,
            "missing_attribution_rows": missing_attr,
            "missing_content_hash_rows": missing_hash,
            "missing_index_rows": missing_index,
            "orphan_embeddings": orphan_embeddings,
            "fts_indexed_rows": fts_rows,
        },
        "eligible": {
            "eligible_rows": eligible_rows,
            "eligible_unique_searchable_chunks": eligible_unique,
            "exact_duplicate_rate_pct": round(100.0 * exact_dupe_rows / total, 4) if total else 0.0,
            "index_availability_pct": index_availability_pct,
            "attribution_coverage_pct": round(
                100.0 * (total - missing_attr) / total, 4
            ) if total else 0.0,
        },
        "source_count": len(per_source),
        "sources": sources,
        "source_types": per_type,
        "pack_versions": len(per_version),
        "structured_records_not_counted": structured,
        "latest_ingestion": {
            "latest_chunk_created_at": latest_chunk,
            "latest_import_job_at": latest_job,
            "failed_or_incomplete_import_jobs": failed_jobs,
        },
    }

    # acceptance gate
    report["acceptance"] = {
        "eligible_unique_ge_threshold": eligible_unique >= threshold,
        "attribution_100pct": missing_attr == 0,
        "index_availability_100pct": missing_index == 0,
        "no_orphan_embeddings": orphan_embeddings == 0,
    }
    report["passed"] = all(report["acceptance"].values())
    return report


def _print_summary(r: dict) -> None:
    t = r["totals"]
    e = r["eligible"]
    print("=" * 72)
    print("OYSTER KNOWLEDGE BASE AUDIT")
    print("=" * 72)
    print(f"  generated_at        : {r['generated_at']}")
    print(f"  memory_db           : {r['database']['memory_db']} ({r['database']['memory_db_format']})")
    print(f"  vector_db           : {r['database']['vector_db_dir']} ({r['database']['vector_db_format']})")
    print(f"  embedding model     : {r['embedding']['model']} (dims={r['embedding']['dimensions']})")
    print(f"  collections         : {r['database']['collections']}")
    print("-" * 72)
    print(f"  total records       : {t['total_records']:,}")
    print(f"  indexed embeddings  : {t['total_indexed_embeddings']:,}")
    print(f"  distinct hashes     : {t['distinct_content_hashes']:,}")
    print(f"  exact duplicate rows: {t['exact_duplicate_rows']:,}")
    print(f"  near-dup groups*    : {t['near_duplicate_groups_normtext']:,}  (*normalised-text proxy)")
    print(f"  empty/trivial rows  : {t['empty_or_trivial_rows']:,}  (< {r['floor_chars']} chars)")
    print(f"  missing attribution : {t['missing_attribution_rows']:,}")
    print(f"  missing index       : {t['missing_index_rows']:,}")
    print(f"  orphan embeddings   : {t['orphan_embeddings']:,}")
    print(f"  FTS lexical rows    : {t['fts_indexed_rows']}")
    print("-" * 72)
    print(f"  ELIGIBLE UNIQUE SEARCHABLE CHUNKS : {e['eligible_unique_searchable_chunks']:,}")
    print(f"  index availability  : {e['index_availability_pct']}%")
    print(f"  attribution coverage: {e['attribution_coverage_pct']}%")
    print(f"  source count        : {r['source_count']}   pack@versions: {r['pack_versions']}")
    print(f"  latest ingestion    : {r['latest_ingestion']['latest_chunk_created_at']}")
    print(f"  failed import jobs  : {r['latest_ingestion']['failed_or_incomplete_import_jobs']}")
    sr = r["structured_records_not_counted"]
    if sr:
        print(f"  structured records (NOT counted as chunks): {sr}")
    print("-" * 72)
    print("  top sources (rows / unique / eligible / indexed):")
    for s in r["sources"][:20]:
        print(f"    {s['pack_id']:<32} {s['rows']:>7,} {s['unique_chunks']:>7,} "
              f"{s['eligible_chunks']:>7,} {s['indexed']:>7,}")
    print("-" * 72)
    acc = r["acceptance"]
    for k, v in acc.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print("=" * 72)
    print(f"  RESULT: {'PASS' if r['passed'] else 'FAIL'} "
          f"(eligible {e['eligible_unique_searchable_chunks']:,} vs threshold {r['threshold']:,})")
    print("=" * 72)


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit Oyster's active knowledge base.")
    ap.add_argument("--floor", type=int, default=DEFAULT_FLOOR,
                    help="Minimum trimmed content length (chars) for eligibility.")
    ap.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                    help="Required eligible-unique-chunk count for a PASS.")
    ap.add_argument("--json-out", type=str, default=None,
                    help="Explicit path for the JSON report (default: data/reports/).")
    ap.add_argument("--json-only", action="store_true", help="Print only the JSON report.")
    args = ap.parse_args()

    r = audit(floor=args.floor, threshold=args.threshold)

    reports_dir = Path(config.DATA_DIR) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = Path(args.json_out) if args.json_out else reports_dir / f"knowledge_audit_{ts}.json"
    latest = reports_dir / "knowledge_audit_latest.json"
    payload = json.dumps(r, indent=2, sort_keys=False)
    out_path.write_text(payload)
    latest.write_text(payload)

    if args.json_only:
        print(payload)
    else:
        _print_summary(r)
        print(f"\nJSON report written to:\n  {out_path}\n  {latest}")

    return 0 if r["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
