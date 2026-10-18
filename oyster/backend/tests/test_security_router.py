"""Deterministic pre-LLM security question routing (Part 3) + grounded answer
formatting (Part 5) — offline, synthetic fixtures, no network/LLM.
"""

from __future__ import annotations

import sqlite3

import config
import pytest

from services.knowledge import security_answer, security_router
from services.knowledge.graph import builder, store as gstore
from services.knowledge.vulnerabilities import store as vstore


@pytest.fixture
def graph_ready():
    gstore.init_db()
    gstore.replace_graph([], [], [], {})
    yield


def _seed_chunks(rows: list[dict]) -> None:
    con = sqlite3.connect(str(config.MEMORY_DB))
    for i, r in enumerate(rows):
        con.execute(
            "INSERT INTO knowledge_chunks (id,pack_id,title,canonical_url,content,chunk_index) "
            "VALUES (?,?,?,?,?,?)",
            (f"c{i}", r["pack_id"], r.get("title"), r.get("url"), r.get("content", ""), i),
        )
    con.commit()
    con.close()


def _mitre(tid):
    base = tid.split(".")[0]
    sub = tid.split(".")[1] if "." in tid else None
    url = f"https://attack.mitre.org/techniques/{base}" + (f"/{sub}" if sub else "")
    return {"pack_id": "mitre-attack-src", "title": f"{tid} — Example Technique",
            "url": url, "content": f"{tid} description."}


def _d3fend(label, tids):
    body = "\n".join(f"- **{t}** — countered" for t in tids)
    return {"pack_id": "mitre-d3fend-src", "title": f"D3FEND — {label}",
            "url": f"https://d3fend.mitre.org/technique/d3f:{label.replace(' ', '')}/",
            "content": body}


# ---------------------------------------------------------------------------
# classify() — pure, deterministic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("question,expected_route", [
    ("Tell me about CVE-2021-44228", security_router.ROUTE_EXACT_LOOKUP),
    ("What is CWE-79?", security_router.ROUTE_EXACT_LOOKUP),
    ("CAPEC-66", security_router.ROUTE_EXACT_LOOKUP),
    ("T1134.002", security_router.ROUTE_EXACT_LOOKUP),
    ("d3f:TokenBinding", security_router.ROUTE_EXACT_LOOKUP),
    ("list known exploited vulnerabilities with high EPSS", security_router.ROUTE_VULN_FILTER),
    ("how do I detect process injection", security_router.ROUTE_DETECTION),
    ("how do I harden a Kubernetes cluster", security_router.ROUTE_MITIGATION),
    ("what is our incident response containment procedure", security_router.ROUTE_IR),
    ("what is prompt injection", security_router.ROUTE_GENERAL),
])
def test_classify_routes(question, expected_route):
    assert security_router.classify(question)["route"] == expected_route


def test_exact_identifier_wins_over_topic_keywords():
    # Contains both an identifier and a "detect" keyword — identifier wins.
    decision = security_router.classify("how do I detect CVE-2021-44228")
    assert decision["route"] == security_router.ROUTE_EXACT_LOOKUP
    assert decision["identifiers"]["cve"] == ["CVE-2021-44228"]


def test_extract_identifiers_all_five_kinds():
    text = "CVE-2021-44228 CWE-79 CAPEC-66 T1134.002 d3f:TokenBinding"
    ids = security_router.extract_identifiers(text)
    assert ids["cve"] == ["CVE-2021-44228"]
    assert ids["cwe"] == ["CWE-79"]
    assert ids["capec"] == ["CAPEC-66"]
    assert ids["attack"] == ["T1134.002"]
    assert ids["d3fend"] == ["TokenBinding"]


# ---------------------------------------------------------------------------
# resolve_exact() — real-or-explicitly-absent, never fabricated
# ---------------------------------------------------------------------------

def test_resolve_exact_fake_cve_is_absent_not_fabricated():
    resolved = security_router.resolve_exact({"cve": ["CVE-2099-99999"], "cwe": [], "capec": [], "attack": [], "d3fend": []})
    assert resolved["cve"] == [{"cve_id": "CVE-2099-99999", "found": False}]


def _insert_cwe_row(cwe_id, name, description):
    vstore.init_db()
    con = vstore.conn()
    con.execute(
        "INSERT INTO cwe_records (cwe_id, name, description, created_at, updated_at) "
        "VALUES (?,?,?,'now','now')", (cwe_id, name, description),
    )
    con.commit()
    con.close()


def test_resolve_exact_real_cwe_found():
    _insert_cwe_row("CWE-79", "XSS", "desc")
    resolved = security_router.resolve_exact({"cve": [], "cwe": ["CWE-79"], "capec": [], "attack": [], "d3fend": []})
    assert resolved["cwe"][0]["cwe_id"] == "CWE-79"
    assert resolved["cwe"][0].get("found") is not False


def test_d3fend_graph_edges_and_exact_lookup(graph_ready):
    _seed_chunks([
        _mitre("T1134.002"),
        _d3fend("Token Binding", ["T1134.002"]),
    ])
    stats = builder.build()
    assert stats["countermeasures"] == 1

    resolved = security_router.resolve_exact(
        {"cve": [], "cwe": [], "capec": [], "attack": [], "d3fend": ["TokenBinding"]})
    assert resolved["d3fend"][0]["found"] is True
    assert resolved["d3fend"][0]["label"] == "Token Binding"
    assert "T1134.002" in resolved["d3fend"][0]["counters_techniques"]

    # And the ATT&CK-side lookup shows the D3FEND countermeasure via coverage.
    attack_resolved = security_router.resolve_exact(
        {"cve": [], "cwe": [], "capec": [], "attack": ["T1134.002"], "d3fend": []})
    assert attack_resolved["attack"][0].get("found") is not False
    assert attack_resolved["attack"][0]["coverage"]["mitigation"]


def test_d3fend_dangling_reference_when_technique_unmapped(graph_ready):
    """A D3FEND doc that counters a technique id absent from the imported
    ATT&CK set is a real, honest dangling reference — not silently dropped."""
    _seed_chunks([_d3fend("Decoy Environment", ["T9999"])])
    stats = builder.build()
    assert stats["inconsistencies"]["dangling_reference"] == 1


# ---------------------------------------------------------------------------
# answer() — Part 5's 7-part grounded format
# ---------------------------------------------------------------------------

async def test_answer_fake_cve_is_never_fabricated():
    result = await security_answer.answer("CVE-2099-99999", model=None)
    assert result["route"] == security_router.ROUTE_EXACT_LOOKUP
    assert result["items"] == []
    assert result["confidence"]["level"] == "none"
    assert "not found" in result["confidence"]["data_gap_warning"]


async def test_answer_general_route_degrades_without_llm():
    result = await security_answer.answer("what is prompt injection", model=None)
    assert result["route"] == security_router.ROUTE_GENERAL
    assert result["llm_available"] is False
    assert isinstance(result["direct_answer"], str) and result["direct_answer"]
