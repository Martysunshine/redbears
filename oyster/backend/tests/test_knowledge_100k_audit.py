"""Tests for the 100k knowledge-base audit, metrics, FTS repair and retrieval eval.

The eligibility rules (meaningful / attributed / hashed / deduped / indexed) are
tested deterministically against a *synthetic* store built in a temp dir — no
dependency on the real 1GB knowledge base, so these pass on a fresh clone. One
final test verifies the ACTUAL on-disk store exceeds 100k when it is present
(skipped otherwise), so the public claim is checked on the real machine too.
"""
from __future__ import annotations

import sqlite3
import os
from pathlib import Path

import pytest

import config
from scripts import audit_knowledge, rebuild_fts
from services.evaluation import harness
from services.knowledge import metrics

# Real store location (independent of conftest's temp redirect), for the live check.
_AUDIT_DATA_DIR = Path(
    os.getenv(
        "OYSTER_KNOWLEDGE_AUDIT_DATA_DIR",
        str(Path(__file__).resolve().parents[1] / "data"),
    )
)
_REAL_MEMORY_DB = Path(
    os.getenv("OYSTER_KNOWLEDGE_AUDIT_MEMORY_DB", str(_AUDIT_DATA_DIR / "memory.db"))
)
_REAL_VECTOR_DB = Path(
    os.getenv("OYSTER_KNOWLEDGE_AUDIT_VECTOR_DB", str(_AUDIT_DATA_DIR / "vector_db"))
)

_LONG = "This is a complete, meaningful cybersecurity knowledge fact about detecting and mitigating an attack technique." * 2


def _build_memory_db(path: Path, chunks: list[dict], with_fts_ids: list[str] | None = None) -> None:
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, pack_id TEXT, pack_version TEXT, "
        "doc_id TEXT, document TEXT, source_type TEXT, title TEXT, publisher TEXT, canonical_url TEXT, "
        "licence TEXT, trust_level TEXT, risk_level TEXT, domain TEXT, section TEXT, chunk_index INTEGER, "
        "content_hash TEXT, content TEXT, created_at TEXT, cve_id TEXT, cwe_id TEXT, capec_id TEXT)"
    )
    for c in chunks:
        con.execute(
            "INSERT INTO knowledge_chunks (id,pack_id,pack_version,doc_id,source_type,title,publisher,"
            "canonical_url,content_hash,content,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (c["id"], c["pack_id"], "v1", c.get("doc_id", "d1"), "built_in", c.get("title", "t"),
             c.get("publisher", "pub"), c.get("canonical_url", "https://example.com/x"),
             c.get("content_hash"), c.get("content"), "2026-01-01T00:00:00+00:00"),
        )
    # FTS table (optionally pre-populate a subset to test the additive rebuild)
    con.execute(
        "CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(chunk_id UNINDEXED, pack_id UNINDEXED, "
        "content, tokenize='porter unicode61')"
    )
    for cid in (with_fts_ids or []):
        row = next((c for c in chunks if c["id"] == cid), None)
        if row:
            con.execute("INSERT INTO knowledge_chunks_fts (chunk_id,pack_id,content) VALUES (?,?,?)",
                        (cid, row["pack_id"], row.get("content", "")))
    con.commit()
    con.close()


def _build_chroma(vector_dir: Path, ids_by_collection: dict[str, list[str]]) -> None:
    vector_dir.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(vector_dir / "chroma.sqlite3"))
    con.execute("CREATE TABLE collections (id TEXT PRIMARY KEY, name TEXT)")
    con.execute("CREATE TABLE segments (id TEXT PRIMARY KEY, collection TEXT, scope TEXT)")
    con.execute("CREATE TABLE embeddings (id INTEGER PRIMARY KEY AUTOINCREMENT, segment_id TEXT, "
                "embedding_id TEXT, seq_id BLOB, created_at TIMESTAMP)")
    for i, (name, ids) in enumerate(ids_by_collection.items()):
        col_id = f"col{i}"
        seg_id = f"seg{i}"
        con.execute("INSERT INTO collections (id,name) VALUES (?,?)", (col_id, name))
        con.execute("INSERT INTO segments (id,collection,scope) VALUES (?,?,?)", (seg_id, col_id, "VECTOR"))
        for eid in ids:
            con.execute("INSERT INTO embeddings (segment_id,embedding_id,seq_id) VALUES (?,?,?)",
                        (seg_id, eid, b""))
    con.commit()
    con.close()


@pytest.fixture
def synthetic_store(tmp_path, monkeypatch):
    """A tiny store exercising every eligibility rule."""
    chunks = [
        {"id": "c1", "pack_id": "owasp-x", "content": _LONG, "content_hash": "h1"},          # eligible
        {"id": "c2", "pack_id": "owasp-x", "content": "too short", "content_hash": "h2"},     # trivial (<40)
        {"id": "c3", "pack_id": "owasp-x", "content": _LONG, "content_hash": "h1"},           # exact dup of c1
        {"id": "c4", "pack_id": "owasp-x", "content": _LONG, "content_hash": "h4",
         "canonical_url": ""},                                                                 # missing attribution
        {"id": "c5", "pack_id": "owasp-x", "content": _LONG, "content_hash": "h5"},           # NOT indexed
        {"id": "c6", "pack_id": "vulnerability-cve", "content": _LONG, "content_hash": "h6"}, # eligible (vuln collection)
    ]
    mem = tmp_path / "memory.db"
    vec = tmp_path / "vector_db"
    _build_memory_db(mem, chunks)
    _build_chroma(vec, {
        "oyster_knowledge": ["c1", "c2", "c3", "c4", "c7orphan"],  # c5 absent; c7orphan has no row
        "oyster_vulnerabilities": ["c6"],
    })
    monkeypatch.setattr(config, "MEMORY_DB", mem)
    monkeypatch.setattr(config, "VECTOR_DB_DIR", vec)
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    return {"mem": mem, "vec": vec, "chunks": chunks}


# --- audit eligibility ------------------------------------------------------

def test_audit_counts_only_eligible_unique(synthetic_store):
    r = audit_knowledge.audit(floor=40, threshold=100_000)
    t = r["totals"]
    assert t["total_records"] == 6
    assert t["distinct_content_hashes"] == 5          # h1,h2,h4,h5,h6
    assert t["exact_duplicate_rows"] == 1             # c3 duplicates h1
    assert t["empty_or_trivial_rows"] == 1            # c2
    assert t["missing_attribution_rows"] == 1         # c4
    assert t["missing_index_rows"] == 1               # c5
    assert t["orphan_embeddings"] == 1                # c7orphan
    # eligible unique = distinct hashes among eligible rows = {h1 (c1/c3), h6 (c6)}
    assert r["eligible"]["eligible_unique_searchable_chunks"] == 2


def test_audit_gate_fails_below_threshold(synthetic_store):
    r = audit_knowledge.audit(floor=40, threshold=100_000)
    assert r["passed"] is False                       # only 2 eligible << 100k
    assert r["acceptance"]["attribution_100pct"] is False


def test_trivial_and_dup_never_counted(synthetic_store):
    # A duplicate row and a trivial row must never inflate the unique count.
    r = audit_knowledge.audit(floor=40, threshold=1)
    assert r["eligible"]["eligible_unique_searchable_chunks"] == 2
    # attribution coverage reflects the one missing-url row (5/6).
    assert 83.0 < r["eligible"]["attribution_coverage_pct"] < 84.0


# --- metrics ----------------------------------------------------------------

def test_metrics_match_audit(synthetic_store):
    m = metrics.compute()
    assert m["unique_searchable_chunks"] == 2
    assert m["total_records"] == 6
    assert m["exact_duplicate_count"] == 1
    assert m["meets_public_threshold"] is False
    assert m["public_threshold"] == 100_000


def test_public_statement_withholds_claim_below_threshold(synthetic_store):
    p = metrics.public_statement()
    assert p["meets_public_threshold"] is False
    assert p["marketing_sentence"] is None            # never assert 100k below threshold


# --- FTS additive rebuild + idempotency -------------------------------------

def test_fts_rebuild_is_additive_and_idempotent(tmp_path, monkeypatch):
    chunks = [{"id": f"k{i}", "pack_id": "p", "content": _LONG, "content_hash": f"h{i}"} for i in range(10)]
    mem = tmp_path / "memory.db"
    _build_memory_db(mem, chunks, with_fts_ids=["k0", "k1"])  # only 2 of 10 in FTS
    monkeypatch.setattr(config, "MEMORY_DB", mem)

    dry = rebuild_fts.rebuild(dry_run=True)
    assert dry["missing_from_fts"] == 8

    first = rebuild_fts.rebuild()
    assert first["inserted"] == 8
    assert first["fts_after"] == 10

    second = rebuild_fts.rebuild()                     # idempotent
    assert second["inserted"] == 0
    assert second["fts_after"] == 10


# --- retrieval eval scoring (deterministic, no embeddings) -------------------

def test_score_case_requires_pack_and_source_hit():
    case = {"id": "x", "query": "q", "expect_any_pack": ["p1"],
            "expect_source_substring": ["foo"], "min_results": 1}
    # right pack + substring present → pass at rank 1
    good = [{"pack_id": "p1", "content": "something about foo here", "source_url": "https://s/1"}]
    s = harness.score_case(case, good)
    assert s["passed"] and s["pack_hit"] and s["source_hit"] and s["first_hit_rank"] == 1

    # right pack, no substring → fail on source_hit
    s2 = harness.score_case(case, [{"pack_id": "p1", "content": "unrelated", "source_url": "https://s/2"}])
    assert s2["pack_hit"] and not s2["source_hit"] and not s2["passed"]

    # substring present but wrong pack → fail on pack_hit
    s3 = harness.score_case(case, [{"pack_id": "other", "content": "foo", "source_url": "https://s/3"}])
    assert s3["source_hit"] and not s3["pack_hit"] and not s3["passed"]


@pytest.mark.asyncio
async def test_run_suite_with_injected_retriever_is_deterministic():
    # inject a fake retriever so scoring is exercised without embeddings/network
    async def fake(query, top_k):
        return [{"pack_id": "mitre-cwe", "content": "CWE-79 cross-site scripting",
                 "source_url": "https://cwe.mitre.org/79"}]
    run = await harness.run_suite("retrieval-100k-v1", top_k=5, retriever=fake, persist=False)
    assert run["metrics"]["cases"] >= 100          # the suite has >=100 cases
    assert run["top_k"] == 5


def test_suite_has_at_least_100_cases():
    suite = harness.load_suite("retrieval-100k-v1")
    assert suite is not None
    assert len(suite["cases"]) >= 100
    assert suite["default_top_k"] == 5
    # every case is well-formed
    for c in suite["cases"]:
        assert c.get("query") and c.get("id")
        assert c.get("expect_any_pack") or c.get("expect_source_substring")


# --- live store (real machine) ----------------------------------------------

@pytest.mark.skipif(
    not (_REAL_MEMORY_DB.exists() and (_REAL_VECTOR_DB / "chroma.sqlite3").exists()),
    reason="real knowledge store not present (fresh clone) — deterministic tests cover the logic",
)
def test_live_store_exceeds_100k(monkeypatch):
    monkeypatch.setattr(config, "MEMORY_DB", _REAL_MEMORY_DB)
    monkeypatch.setattr(config, "VECTOR_DB_DIR", _REAL_VECTOR_DB)
    r = audit_knowledge.audit(floor=40, threshold=100_000)
    assert r["eligible"]["eligible_unique_searchable_chunks"] >= 100_000
    assert r["totals"]["missing_attribution_rows"] == 0
    assert r["totals"]["missing_index_rows"] == 0
    assert r["totals"]["orphan_embeddings"] == 0
    assert r["passed"] is True
