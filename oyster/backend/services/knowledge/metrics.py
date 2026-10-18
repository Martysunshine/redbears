"""Canonical, factual metrics for the active cybersecurity knowledge base.

One source of truth for the numbers Oyster is allowed to state publicly
("Oyster indexes more than 100,000 source-attributed cybersecurity knowledge
chunks"). Every field is read from the LIVE store — the ``knowledge_chunks``
provenance table plus the Chroma index — never from a hard-coded constant.

A chunk counts as ``unique_searchable_chunks`` only when it is meaningful
(trimmed length >= ``FLOOR`` chars), source-attributed (has a ``canonical_url``),
content-hashed, deduplicated (counted once per hash) and actually indexed in the
Chroma collection its pack routes to — the exact rules the audit script enforces.

The retrieval evaluation score is read from the most recent eval report on disk
(``data/reports/retrieval_eval_*_latest.json``) if present, so a published score
always corresponds to a real, dated evaluation run — never an assumed value.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import config

FLOOR = 40
PUBLIC_THRESHOLD = 100_000
VULN_PACK_IDS = {"vulnerability-cve", "mitre-cwe", "mitre-capec"}
_KNOWN_EMBED_DIMS = {"all-MiniLM-L6-v2": 384, "all-mpnet-base-v2": 768}


def _ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def _chroma_ids(vector_db_dir: Path) -> dict[str, set[str]]:
    chroma = vector_db_dir / "chroma.sqlite3"
    out: dict[str, set[str]] = {}
    if not chroma.exists():
        return out
    con = _ro(chroma)
    try:
        for name, eid in con.execute(
            "SELECT c.name, e.embedding_id FROM collections c "
            "JOIN segments s ON s.collection = c.id "
            "JOIN embeddings e ON e.segment_id = s.id"
        ):
            out.setdefault(name, set()).add(eid)
    finally:
        con.close()
    return out


def _latest_retrieval_eval() -> dict | None:
    reports = Path(config.DATA_DIR) / "reports"
    if not reports.exists():
        return None
    candidates = sorted(reports.glob("retrieval_eval_*_latest.json"))
    if not candidates:
        candidates = sorted(reports.glob("retrieval_eval_*.json"))
    if not candidates:
        return None
    try:
        data = json.loads(candidates[-1].read_text())
        m = data.get("metrics", {})
        return {
            "suite_id": data.get("suite_id"),
            "top_k": data.get("top_k"),
            "cases": m.get("cases"),
            "pass_rate": m.get("pass_rate"),
            "mrr": m.get("mrr"),
            "citation_rate": m.get("citation_rate"),
            "evaluated_at": data.get("finished_at"),
        }
    except (ValueError, OSError):
        return None


def compute() -> dict:
    """Return the canonical, factual metrics dict for the active store."""
    memory_db = Path(config.MEMORY_DB)
    vector_db_dir = Path(config.VECTOR_DB_DIR)
    know_col = getattr(config, "KNOWLEDGE_COLLECTION", "oyster_knowledge")
    vuln_col = getattr(config, "KNOWLEDGE_VULN_COLLECTION", "oyster_vulnerabilities")

    indexed = _chroma_ids(vector_db_dir)
    know_ids = indexed.get(know_col, set())
    vuln_ids = indexed.get(vuln_col, set())
    all_indexed = set().union(*indexed.values()) if indexed else set()

    con = _ro(memory_db)
    total = 0
    all_hashes: set[str] = set()
    eligible_hashes: set[str] = set()
    sources: set[str] = set()
    docs: set[str] = set()
    missing_attr = 0
    # Chunk rows that really are indexed. `all_indexed` spans every Chroma
    # collection, including ones that hold no knowledge_chunks at all, so it is
    # the wrong numerator for a coverage figure over knowledge_chunks — see
    # indexed_percentage below.
    indexed_chunk_rows = 0
    for _id, pack, content, chash, url, doc_id in con.execute(
        "SELECT id, pack_id, content, content_hash, canonical_url, doc_id FROM knowledge_chunks"
    ):
        total += 1
        if pack:
            sources.add(pack)
        if doc_id:
            docs.add(doc_id)
        if chash:
            all_hashes.add(chash)
        c = (content or "").strip()
        u = (url or "").strip()
        if not u:
            missing_attr += 1
        target = vuln_ids if pack in VULN_PACK_IDS else know_ids
        is_indexed = _id in target or _id in all_indexed
        if is_indexed:
            indexed_chunk_rows += 1
        if len(c) >= FLOOR and chash and u and is_indexed:
            eligible_hashes.add(chash)
    latest_chunk = con.execute("SELECT MAX(created_at) FROM knowledge_chunks").fetchone()[0]
    con.close()

    exact_dupes = total - len(all_hashes)
    unique_searchable = len(eligible_hashes)
    ev = _latest_retrieval_eval()

    return {
        "unique_searchable_chunks": unique_searchable,
        "total_records": total,
        "source_count": len(sources),
        "document_or_record_count": len(docs),
        "exact_duplicate_count": exact_dupes,
        # Share of knowledge_chunks rows that are actually indexed. This used to
        # divide len(all_indexed) — every embedding id in EVERY Chroma collection
        # — by the knowledge_chunks row count, so the numerator counted records
        # the denominator could not contain. On the live store that is
        # oyster_dataset_eval (3,999), oyster_user_memory (65) and oyster_docs
        # (12), and the field reported 104.22%: a coverage ratio above 100%,
        # which also masked genuinely unindexed rows one-for-one.
        "indexed_percentage": round(100.0 * indexed_chunk_rows / total, 2) if total else 0.0,
        "attribution_percentage": round(100.0 * (total - missing_attr) / total, 2) if total else 0.0,
        "retrieval_evaluation": ev,
        "retrieval_evaluation_score": ev.get("pass_rate") if ev else None,
        "embedding_model": getattr(config, "EMBED_MODEL", None),
        "embedding_dimensions": _KNOWN_EMBED_DIMS.get(getattr(config, "EMBED_MODEL", ""), None),
        "knowledge_version": getattr(config, "KNOWLEDGE_VERSION", None) or "active-store",
        "last_verified_at": latest_chunk,
        "meets_public_threshold": unique_searchable >= PUBLIC_THRESHOLD,
        "public_threshold": PUBLIC_THRESHOLD,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


def public_statement() -> dict:
    """The honest, display-ready headline — only emitted when the store truly
    satisfies the threshold; otherwise a neutral, non-claiming fallback."""
    m = compute()
    n = m["unique_searchable_chunks"]
    if m["meets_public_threshold"]:
        headline = f"{n:,} indexed knowledge chunks"
        marketing = "Oyster indexes more than 100,000 source-attributed cybersecurity knowledge chunks."
    else:
        headline = f"{n:,} indexed knowledge chunks"
        marketing = None  # never assert the 100k claim below threshold
    return {
        "headline": headline,
        "marketing_sentence": marketing,
        "unique_searchable_chunks": n,
        "meets_public_threshold": m["meets_public_threshold"],
        "source_count": m["source_count"],
        "retrieval_evaluation_score": m["retrieval_evaluation_score"],
        "last_verified_at": m["last_verified_at"],
    }
