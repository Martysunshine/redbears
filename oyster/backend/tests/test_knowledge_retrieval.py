"""Hybrid retrieval, filters, dedup, budget, citation resolution, isolation."""

from __future__ import annotations

import pytest

from services.knowledge import pack_service, retrieval, store


async def _installed(fake_embedding, *pack_ids):
    for pid in pack_ids:
        await pack_service.install(pid)


async def test_lexical_only_when_vector_offline(fake_embedding):
    # fake_embedding.vector returns [] → simulates offline/unavailable vector index
    await _installed(fake_embedding, "kali-linux")
    hits = await pack_service.search("metapackages headless apt", top_k=5)
    assert hits, "lexical (FTS5) search should return results with vector offline"
    assert all(h["source_type"] == "built_in" for h in hits)
    assert hits[0]["chunk_id"].startswith("kp::kali-linux::")


async def test_hybrid_fusion_merges_both_retrievers(fake_embedding, monkeypatch):
    from services import rag_service
    await _installed(fake_embedding, "gtfobins")
    ids = [r["id"] for r in store.conn().execute(
        "SELECT id FROM knowledge_chunks WHERE pack_id='gtfobins'").fetchall()]
    assert ids

    async def _vec(query, top_k, pack_ids=None):
        return [{"id": ids[-1], "content": "vector-only-hit", "score": 0.9,
                 "pack_id": "gtfobins"}]
    monkeypatch.setattr(rag_service, "vector_search_knowledge_async", _vec)

    hits = await pack_service.search("find suid exec shell", top_k=8)
    hit_ids = {h["chunk_id"] for h in hits}
    assert ids[-1] in hit_ids  # vector candidate present
    assert len(hits) >= 1


async def test_citation_resolution(fake_embedding):
    await _installed(fake_embedding, "mitre-attack")
    row = store.conn().execute(
        "SELECT id FROM knowledge_chunks WHERE pack_id='mitre-attack' LIMIT 1").fetchone()
    payload = pack_service.resolve_citation(row["id"])
    assert payload is not None
    assert payload["passage"]
    assert payload["canonical_url"]
    assert payload["knowledge_pack"] == "mitre-attack"
    assert payload["source_type"] == "built_in"


async def test_missing_citation_returns_none(fake_embedding):
    assert pack_service.resolve_citation("kp::nope::x::0") is None


# --- exact-identifier title boost (2026-09-15) ------------------------------

def test_query_title_boost_ids_extracts_attack_and_owasp_llm_ids():
    ids = retrieval._query_title_boost_ids("Compare T1055 process injection with T1218.011 and LLM06 risk")
    assert ids == {"T1055", "T1218.011", "LLM06"}


def test_query_title_boost_ids_empty_when_no_identifier_named():
    assert retrieval._query_title_boost_ids("how does process injection generally work") == set()


def test_title_boost_favors_the_canonical_page_over_an_incidental_mention():
    """Diagnostic finding: mitre-d3fend-src's cross-reference tables mention an
    ATT&CK id in body text without being about it, and were outranking the
    actual mitre-attack-src technique page. The boost must key off the
    document/title PREFIX (the canonical page), not mere body containment —
    this test constructs exactly that contrast."""
    canonical = {"id": "a", "document": "T1055 — Process Injection", "title": "T1055 — Process Injection",
                 "_score": 0.02}
    incidental = {"id": "b", "document": "D3FEND — Content Filtering", "title": "D3FEND — Content Filtering",
                  "_score": 0.021}  # starts slightly ahead before the boost
    scored = [canonical, incidental]
    retrieval._apply_title_boost(scored, {"T1055"})
    assert canonical["_score"] > incidental["_score"], "canonical page must outrank the incidental mention after boosting"
    assert incidental["_score"] == 0.021, "a chunk that only mentions the id must not be boosted"


def test_title_boost_is_noop_when_query_names_no_identifier():
    scored = [{"id": "a", "document": "T1055 — Process Injection", "_score": 0.02}]
    retrieval._apply_title_boost(scored, set())
    assert scored[0]["_score"] == 0.02


def test_title_boost_base_id_does_not_wrongly_match_a_sub_technique_page():
    """Regression: a naive header.startswith(id) check let a query about the
    base technique "T1055" incorrectly match a chunk titled "T1055.001 — ..."
    (a distinct sub-technique), because "T1055.001" does start with "T1055"."""
    base = {"id": "a", "document": "T1055 — Process Injection", "_score": 0.02}
    sub = {"id": "b", "document": "T1055.001 — Dynamic-link Library Injection", "_score": 0.021}
    scored = [base, sub]
    retrieval._apply_title_boost(scored, {"T1055"})
    assert base["_score"] > 0.02, "the base technique page must be boosted"
    assert sub["_score"] == 0.021, "a distinct sub-technique page must NOT be boosted by the base id"


def test_title_boost_sub_technique_id_matches_its_own_page_only():
    base = {"id": "a", "document": "T1055 — Process Injection", "_score": 0.02}
    sub = {"id": "b", "document": "T1055.001 — Dynamic-link Library Injection", "_score": 0.02}
    scored = [base, sub]
    retrieval._apply_title_boost(scored, {"T1055.001"})
    assert sub["_score"] > base["_score"]


# --- exact-binary-name title boost (2026-09-16, accuracy pass 2) -----------

def test_query_binary_names_extracts_exe_mentions():
    names = retrieval._query_binary_names("execute code with rundll32.exe as a living off the land binary")
    assert names == {"rundll32"}


def test_query_binary_names_empty_when_no_exe_named():
    assert retrieval._query_binary_names("how to enumerate and escalate privileges on a Linux host") == set()


def test_query_binary_names_extracts_multiple():
    names = retrieval._query_binary_names("compare certutil.exe and rundll32.exe as LOLBins")
    assert names == {"certutil", "rundll32"}


def test_binary_name_boost_favors_the_canonical_filename_page():
    """Diagnosed cause of lolbas-rundll32: LOLBAS titles its canonical page
    "Rundll32.yml" (a filename, dot-delimited) rather than a space-delimited
    id like the ATT&CK boost handles -- a chunk that merely mentions the
    binary in a broader technique writeup must not out-rank it."""
    canonical = {"id": "a", "document": "Rundll32.yml", "title": "Rundll32.yml", "_score": 0.02}
    incidental = {"id": "b", "document": "T1218.011 — Rundll32", "title": "T1218.011 — Rundll32", "_score": 0.021}
    scored = [canonical, incidental]
    retrieval._apply_binary_name_boost(scored, {"rundll32"})
    assert canonical["_score"] > incidental["_score"]
    assert incidental["_score"] == 0.021, "a chunk that only mentions the binary must not be boosted"


def test_binary_name_boost_is_case_insensitive():
    canonical = {"id": "a", "document": "Rundll32.yml", "_score": 0.02}
    retrieval._apply_binary_name_boost([canonical], {"RUNDLL32"})
    assert canonical["_score"] > 0.02


def test_binary_name_boost_does_not_match_an_unrelated_document_with_the_name_as_a_substring():
    """A bare 'LIKE prefix%' would also match "Rundll32Extractor.md" -- the
    dot boundary is what distinguishes a genuine filename-title match."""
    unrelated = {"id": "a", "document": "Rundll32Extractor.md", "_score": 0.02}
    retrieval._apply_binary_name_boost([unrelated], {"rundll32"})
    assert unrelated["_score"] == 0.02, "a document whose title merely starts with the name must not be boosted"


def test_binary_name_boost_is_noop_when_no_exe_named():
    scored = [{"id": "a", "document": "Rundll32.yml", "_score": 0.02}]
    retrieval._apply_binary_name_boost(scored, set())
    assert scored[0]["_score"] == 0.02


async def test_domain_filter(fake_embedding):
    await _installed(fake_embedding, "kali-linux", "mitre-attack")
    # mitre-attack is 'defensive'; kali is 'offensive'
    defensive = await pack_service.search("detection telemetry technique", top_k=8,
                                          filters={"domain": "defensive"})
    assert defensive
    assert all(h["domain"] == "defensive" for h in defensive)


async def test_dedup_and_budget(fake_embedding, monkeypatch):
    from services import rag_service
    await _installed(fake_embedding, "kali-linux")
    rows = store.conn().execute(
        "SELECT id, content FROM knowledge_chunks WHERE pack_id='kali-linux'").fetchall()
    dup_id = rows[0]["id"]

    async def _vec(query, top_k, pack_ids=None):
        # return the same chunk twice → must be deduped to one
        return [{"id": dup_id, "content": rows[0]["content"], "score": 0.9, "pack_id": "kali-linux"},
                {"id": dup_id, "content": rows[0]["content"], "score": 0.8, "pack_id": "kali-linux"}]
    monkeypatch.setattr(rag_service, "vector_search_knowledge_async", _vec)
    hits = await pack_service.search("kali", top_k=8)
    ids = [h["chunk_id"] for h in hits]
    assert ids.count(dup_id) <= 1


async def test_no_packs_no_results(fake_embedding):
    hits = await pack_service.search("anything", top_k=5)
    assert hits == []


async def test_specific_pack_scope(fake_embedding):
    await _installed(fake_embedding, "kali-linux", "gtfobins")
    hits = await pack_service.search("shell", top_k=8, pack_id="gtfobins")
    assert hits
    assert all(h["knowledge_pack"] == "gtfobins" for h in hits)


async def test_exact_cve_id_named_in_query_is_never_shadowed_by_a_closer_embedding_hit(fake_embedding, monkeypatch):
    """Regression test for a real bug found during live verification: a chat
    question naming an explicit id ("Is CVE-2021-44228 in CISA KEV?") was
    observed to retrieve a DIFFERENT CVE's record, because a short
    alphanumeric id does not embed distinctively enough for similarity search
    to reliably find its own record. The exact-id path must always win."""
    from services.knowledge.vulnerabilities import store as vuln_store
    from services.knowledge.vulnerabilities.models import NvdCveEntry

    vuln_store.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2030-11111", description="the RIGHT record",
                                           vuln_status="Analyzed", cvss_v3_score=9.0)])
    right_chunk_id = "vuln::cve::CVE-2030-11111"
    store.upsert_chunk({
        "id": right_chunk_id, "pack_id": "vulnerability-cve", "pack_version": "2024-01-01",
        "doc_id": right_chunk_id, "document": "CVE-2030-11111", "source_type": "vulnerability_feed",
        "title": "CVE-2030-11111", "publisher": "NVD",
        "canonical_url": "https://nvd.nist.gov/vuln/detail/CVE-2030-11111",
        "licence": "nist-nvd-public", "trust_level": "official", "risk_level": "informational",
        "domain": "vulnerability", "section": None, "chunk_index": 0,
        "content_hash": "h1", "content": "the RIGHT record", "cve_id": "CVE-2030-11111",
    })
    vuln_store.set_vuln_chunk("CVE-2030-11111", right_chunk_id, "h1")

    con = store.conn()
    now = "2024-01-01T00:00:00+00:00"
    con.execute(
        "INSERT INTO knowledge_packs (pack_id,version,title,domain,doc_count,chunk_count,"
        "installed_at,updated_at,enabled) VALUES ('vulnerability-cve','2024-01-01',"
        "'Vulnerabilities','defensive',1,1,?,?,1)", (now, now),
    )
    con.commit()
    con.close()

    # A DIFFERENT record the fake vector search claims is the closest semantic
    # match — proves the exact-id path overrides pure embedding similarity.
    async def _wrong_vec(query, top_k):
        return [{"id": "vuln::cve::CVE-2030-22222", "content": "the WRONG record",
                 "metadata": {"knowledge_pack": "vulnerability-cve"}}]
    monkeypatch.setattr(fake_embedding, "vector_search_vulnerabilities_async", _wrong_vec)

    results = await retrieval.retrieve("Is CVE-2030-11111 in CISA KEV?", top_k=6)
    assert results
    assert results[0]["chunk"] == "the RIGHT record"
    assert results[0]["chunk_id"] == right_chunk_id


# --- surrounding-document context expansion (2026-10-06) --------------------

def _seed_doc(pack_id="expand-pack", doc_id="doc::a", n=5, per=60):
    """Insert n sequential chunks of one document so neighbour lookup has a
    real window to walk."""
    chunks = [
        {"id": f"kp::{pack_id}::{doc_id}::{i}", "pack_id": pack_id, "doc_id": doc_id,
         "document": "Doc A", "title": "Doc A", "chunk_index": i,
         "canonical_url": "https://example/a", "trust_level": "official",
         "content": f"part{i} " + ("x" * per)}
        for i in range(n)
    ]
    store.replace_chunks(pack_id, chunks)
    return pack_id, doc_id


def test_neighbor_chunks_window_excludes_center_and_respects_radius():
    pack_id, doc_id = _seed_doc(n=5)
    got = store.neighbor_chunks(pack_id, doc_id, 2, radius=1)
    idx = [c["chunk_index"] for c in got]
    assert idx == [1, 3]                      # center (2) excluded, radius 1 each side
    assert store.neighbor_chunks(pack_id, doc_id, 2, radius=0) == []
    # document boundary: index 0 has no left neighbour
    assert [c["chunk_index"] for c in store.neighbor_chunks(pack_id, doc_id, 0, radius=2)] == [1, 2]


def test_neighbor_chunks_isolated_to_same_document():
    _seed_doc(pack_id="p1", doc_id="d1", n=3)
    _seed_doc(pack_id="p1", doc_id="d2", n=3)
    got = store.neighbor_chunks("p1", "d1", 1, radius=2)
    assert all(c["doc_id"] == "d1" for c in got)


def test_expand_context_stitches_in_reading_order_and_preserves_attribution():
    pack_id, doc_id = _seed_doc(n=5, per=50)
    cite = {"chunk_id": f"kp::{pack_id}::{doc_id}::2", "chunk": "part2 " + "x" * 50,
            "source_url": "https://example/a", "knowledge_pack": pack_id}
    before = cite["chunk"]
    out = retrieval._expand_context([dict(cite)], radius=1, budget=100000)[0]
    assert out["expanded_chunks"] == 3                 # center + 2 neighbours
    assert out["chunk"].index("part1") < out["chunk"].index("part2") < out["chunk"].index("part3")
    assert len(out["chunk"]) > len(before)
    assert out["source_url"] == "https://example/a"    # attribution untouched
    assert out["knowledge_pack"] == pack_id


def test_expand_context_respects_budget_and_is_noop_when_disabled():
    pack_id, doc_id = _seed_doc(n=9, per=100)
    cite = {"chunk_id": f"kp::{pack_id}::{doc_id}::4", "chunk": "part4 " + "x" * 100}
    disabled = retrieval._expand_context([dict(cite)], radius=0, budget=100000)[0]
    assert "expanded_chunks" not in disabled           # radius 0 → untouched
    tight = retrieval._expand_context([dict(cite)], radius=4, budget=len(cite["chunk"]) + 10)[0]
    assert len(tight["chunk"]) <= len(cite["chunk"]) + 10  # budget enforced


# --- second-stage lexical reranker ------------------------------------------

def test_rerank_prefers_higher_query_term_coverage():
    broad = {"content": "nmap is a network scanner", "title": "nmap", "_score": 1.0}
    precise = {"content": "the nmap -sS syn scan sends syn packets", "title": "nmap syn scan", "_score": 1.0}
    retrieval._rerank([broad, precise], "nmap -sS syn scan", weight=0.35)
    assert precise["_score"] > broad["_score"]         # more query terms covered → ranked up
    assert precise["_score"] <= 1.35                   # bounded by 1+weight


def test_rerank_is_noop_at_zero_weight():
    cand = {"content": "nmap syn scan", "title": "", "_score": 1.0}
    retrieval._rerank([cand], "nmap syn scan", weight=0.0)
    assert cand["_score"] == 1.0
