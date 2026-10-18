"""MCP gateway — source-backed retrieval.

Exercises the real knowledge path (lexical FTS with the vector side faked) so a
tool answer carries genuine provenance, an absent answer is honest, and global
vs project scope is labelled. Uses the same pack-install harness as the
knowledge-service tests.
"""

from __future__ import annotations

import json

import pytest

from mcp_gateway.core import protocol
from mcp_gateway.core.identity import Identity


@pytest.fixture
def app_schema():
    from services import project_service, user_prefs
    from services.artifacts import store as art_store
    project_service.init_db()
    user_prefs.init_db()
    art_store.init_db()
    yield


def operator(sub="ret-op"):
    return Identity(oyster={"tier": "admin", "email": "op@x", "sub": sub},
                    transport="stdio", auth_method="local")


async def call_tool(identity, name, arguments=None):
    r = await protocol.handle_rpc(identity, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                            "params": {"name": name, "arguments": arguments or {}}})
    return json.loads(r["result"]["content"][0]["text"])


async def test_search_returns_source_backed_citations(fake_embedding):
    from services.knowledge import pack_service
    await pack_service.install("mitre-attack")
    data = await call_tool(operator(), "search_security_knowledge", {"query": "technique", "top_k": 5})
    assert data["scope"] == "global_security_knowledge"
    assert data["insufficient_evidence"] is False
    assert data["results"], "expected at least one citation"
    top = data["results"][0]
    # Full provenance on every citation.
    assert top["chunk_id"]
    assert top["knowledge_pack"] == "mitre-attack"
    assert top["source_url"]
    assert "retrieved_at" in data


async def test_get_source_evidence_resolves_and_missing_is_honest(fake_embedding):
    from services.knowledge import pack_service, store
    await pack_service.install("mitre-attack")
    row = store.conn().execute(
        "SELECT id FROM knowledge_chunks WHERE pack_id='mitre-attack' LIMIT 1").fetchone()
    got = await call_tool(operator(), "get_source_evidence", {"chunk_id": row["id"]})
    assert got["found"] is True
    assert got["evidence"]["passage"]
    assert got["evidence"]["canonical_url"]

    # A source that does not exist / is not accessible is reported honestly, not faked.
    missing = await call_tool(operator(), "get_source_evidence", {"chunk_id": "kp::nope::x::0"})
    assert missing["found"] is False


async def test_insufficient_evidence_when_nothing_matches(fake_embedding):
    # No packs installed at all → an honest empty answer, never a fabricated one.
    data = await call_tool(operator(), "search_security_knowledge",
                           {"query": "zzxxqq nonexistent gibberish token"})
    assert data["insufficient_evidence"] is True
    assert data["results"] == []


async def test_global_vs_project_scope_is_labelled(fake_embedding, app_schema):
    from services.knowledge import pack_service
    from services import project_service
    from services.artifacts import store as art_store
    await pack_service.install("mitre-attack")

    project_service.ensure_project("u_ret-op", "ws")
    project_service.set_owner("u_ret-op", "ret-op")
    art = art_store.create("u_ret-op", "app.py")
    art_store.update(art["id"], text="def login(): pass", index_status="indexed")

    g = await call_tool(operator(), "search_security_knowledge", {"query": "technique"})
    p = await call_tool(operator(), "search_project_files", {"query": "login"})
    assert g["scope"] == "global_security_knowledge"
    assert p["scope"] == "project_files"
    assert any("app.py" in (h.get("filename") or "") for h in p["results"])


async def test_citations_are_stable(fake_embedding):
    from services.knowledge import pack_service
    await pack_service.install("mitre-attack")
    a = await call_tool(operator(), "search_security_knowledge", {"query": "technique", "top_k": 3})
    b = await call_tool(operator(), "search_security_knowledge", {"query": "technique", "top_k": 3})
    assert [c["chunk_id"] for c in a["results"]] == [c["chunk_id"] for c in b["results"]]
