"""Test harness for the Knowledge Service.

Redirects the SQLite memory DB and the Chroma vector dir to a throwaway temp
location **before** anything imports ``config`` — so no user data (memory.db,
vector_db, uploaded evidence) is ever touched. The real on-disk Knowledge Packs
and registries are used for validation, but all *writes* go to temp.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# --- redirect writable state to temp BEFORE importing config -----------------
_TMP = Path(tempfile.mkdtemp(prefix="oyster_ktest_"))
os.environ["OYSTER_DATA_DIR"] = str(_TMP / "data")
os.environ["OYSTER_LOGS_DIR"] = str(_TMP / "logs")
os.environ["OYSTER_MEMORY_DB"] = str(_TMP / "data" / "memory.db")
os.environ["OYSTER_VECTOR_DB_DIR"] = str(_TMP / "data" / "vector_db")
(_TMP / "data").mkdir(parents=True, exist_ok=True)
(_TMP / "logs").mkdir(parents=True, exist_ok=True)

import pytest  # noqa: E402

from services.knowledge import store  # noqa: E402


@pytest.fixture(autouse=True)
def _exec_db():
    """Ensure the Execution Engine schema exists on the temp DB for every test.
    Idempotent; execution tables are project-scoped so cross-test rows never
    collide (each test uses a unique project id)."""
    from services.execution import store as exec_store
    exec_store.init_db()
    yield


@pytest.fixture(autouse=True)
def _fresh_db():
    """Give every test a clean knowledge schema on the temp DB."""
    # Drop knowledge tables so each test starts from migrations.
    con = store.conn()
    for t in ("knowledge_packs", "knowledge_chunks", "knowledge_pack_updates"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    if store.fts_available():
        con.execute("DROP TABLE IF EXISTS knowledge_chunks_fts")
    con.commit()
    con.close()
    store.init_db()
    yield


@pytest.fixture(autouse=True)
def _fresh_vuln_db():
    """Give every test a clean vulnerability-knowledge schema on the temp DB —
    same pattern as ``_fresh_db``, one level down (per-source, not per-pack)."""
    from services.knowledge.vulnerabilities import store as vuln_store

    con = vuln_store.conn()
    for t in ("vulnerability_records", "vulnerability_cwe_links", "cwe_records",
              "capec_records", "capec_cwe_links", "vulnerability_sync_state",
              "vulnerability_import_jobs", "vendor_advisories", "vendor_advisory_findings",
              "cisa_csaf_seen", "redhat_csaf_seen", "cve_cvss_scores"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    con.commit()
    con.close()
    vuln_store.init_db()
    yield


@pytest.fixture(autouse=True)
def _fresh_osv_db():
    """Give every test a clean GHSA/OSV schema on the temp DB."""
    from services.knowledge.vulnerabilities import osv_store

    con = osv_store.conn()
    for t in ("ghsa_advisories", "ghsa_aliases", "ghsa_cwe_links", "ghsa_affected",
              "osv_records", "osv_aliases", "osv_cwe_links", "osv_affected",
              "ghsa_osv_sync_state"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    con.commit()
    con.close()
    osv_store.init_db()
    yield


@pytest.fixture(autouse=True)
def _fresh_controls_db():
    """Give every test a clean NIST-control schema on the temp DB."""
    from services.knowledge.controls import store as controls_store

    con = controls_store.conn()
    for t in ("control_records", "control_links", "control_sync_state"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    con.commit()
    con.close()
    controls_store.init_db()
    yield


@pytest.fixture
def fake_embedding(monkeypatch):
    """Replace the vector side so tests never load the embedding model / Chroma.

    Returns a controllable in-memory vector index keyed by chunk id.
    """
    from services import rag_service

    async def _ingest(pack_id, version, doc_name, text, source_url=None,
                      source_title=None, domain=None, risk_level=None):
        # Real chunking (pure text-splitting, no model/network) so a chunk's
        # content and hash match exactly what production would compute —
        # pack_service.install()'s unchanged-doc detection calls the real
        # rag_service._chunk_text() directly to decide whether to re-embed,
        # and it must agree with what this fake "embedded" here.
        doc_id = f"kp::{pack_id}::{doc_name}"
        chunks = rag_service._chunk_text(text)
        return [{"id": f"{doc_id}::{i}", "content": c, "chunk_index": i}
                for i, c in enumerate(chunks)]

    async def _delete(pack_id):
        return None

    async def _delete_ids(chunk_ids):
        return None

    async def _vector(query, top_k, pack_ids=None):
        return []  # lexical-only unless a test overrides

    async def _vuln_upsert(chunk_id, text, metadata):
        return None

    async def _vuln_delete(chunk_id):
        return None

    async def _vuln_vector(query, top_k=10):
        return []

    monkeypatch.setattr(rag_service, "ingest_knowledge_async", _ingest)
    monkeypatch.setattr(rag_service, "delete_pack_async", _delete)
    monkeypatch.setattr(rag_service, "delete_knowledge_chunk_ids_async", _delete_ids)
    monkeypatch.setattr(rag_service, "vector_search_knowledge_async", _vector)
    monkeypatch.setattr(rag_service, "upsert_vulnerability_chunk_async", _vuln_upsert)
    monkeypatch.setattr(rag_service, "delete_vulnerability_chunk_async", _vuln_delete)
    monkeypatch.setattr(rag_service, "vector_search_vulnerabilities_async", _vuln_vector)
    return rag_service
