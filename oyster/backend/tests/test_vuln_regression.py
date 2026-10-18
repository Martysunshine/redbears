"""Regression: the vulnerability subsystem's migrations and writes never touch
existing Knowledge Pack data. Offline, deterministic, on the same temp DB the
rest of the suite uses."""

from __future__ import annotations

from services.knowledge import store as kb_store
from services.knowledge.vulnerabilities import store as vuln_store


def _seed_existing_pack_chunk():
    kb_store.replace_chunks("owasp-wstg-src", [{
        "id": "kp::owasp-wstg-src::intro.md::0",
        "pack_version": "abc123",
        "doc_id": "kp::owasp-wstg-src::intro.md",
        "document": "intro.md",
        "source_type": "built_in",
        "title": "WSTG Introduction",
        "publisher": "OWASP",
        "canonical_url": "https://github.com/OWASP/wstg",
        "licence": "CC-BY-SA-4.0",
        "trust_level": "official",
        "risk_level": "informational",
        "domain": "offensive",
        "section": "Introduction",
        "chunk_index": 0,
        "content_hash": "deadbeef",
        "content": "Existing pack content that must survive vuln migrations untouched.",
    }])
    con = kb_store.conn()
    con.execute(
        "INSERT OR REPLACE INTO knowledge_packs (pack_id,version,title,domain,doc_count,chunk_count,"
        "installed_at,updated_at) VALUES ('owasp-wstg-src','abc123','WSTG','offensive',1,1,'t','t')"
    )
    con.commit()
    con.close()


def test_vuln_migrations_never_touch_an_existing_packs_chunks():
    _seed_existing_pack_chunk()
    before = kb_store.get_chunk("kp::owasp-wstg-src::intro.md::0")
    assert before is not None

    vuln_store.init_db()
    vuln_store.init_db()  # idempotent re-run

    after = kb_store.get_chunk("kp::owasp-wstg-src::intro.md::0")
    assert after == before  # byte-identical — nothing in it changed


def test_vuln_migrations_never_change_existing_pack_row_counts():
    _seed_existing_pack_chunk()
    con = kb_store.conn()
    before = con.execute("SELECT COUNT(*) c FROM knowledge_packs").fetchone()["c"]
    before_chunks = con.execute("SELECT COUNT(*) c FROM knowledge_chunks").fetchone()["c"]
    con.close()

    vuln_store.init_db()

    con = kb_store.conn()
    after = con.execute("SELECT COUNT(*) c FROM knowledge_packs").fetchone()["c"]
    after_chunks = con.execute("SELECT COUNT(*) c FROM knowledge_chunks").fetchone()["c"]
    con.close()
    assert before == after
    assert before_chunks == after_chunks


def test_new_nullable_id_columns_default_to_null_on_pre_existing_rows():
    _seed_existing_pack_chunk()
    vuln_store.init_db()
    chunk = kb_store.get_chunk("kp::owasp-wstg-src::intro.md::0")
    assert chunk["cve_id"] is None
    assert chunk["cwe_id"] is None
    assert chunk["capec_id"] is None


def test_new_pack_kind_column_defaults_to_markdown_for_existing_packs():
    _seed_existing_pack_chunk()
    vuln_store.init_db()
    packs = kb_store.pack_meta_map()
    assert packs["owasp-wstg-src"]["pack_kind"] == "markdown"


def test_upsert_chunk_does_not_disturb_other_packs_rows():
    _seed_existing_pack_chunk()
    kb_store.upsert_chunk({
        "id": "vuln::cve::CVE-2024-30001", "pack_id": "vulnerability-cve",
        "content": "vuln text", "cve_id": "CVE-2024-30001",
    })
    still_there = kb_store.get_chunk("kp::owasp-wstg-src::intro.md::0")
    assert still_there is not None
    assert still_there["content"] == "Existing pack content that must survive vuln migrations untouched."
