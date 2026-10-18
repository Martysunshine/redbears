"""Cycle V5 graph-scale hardening: generated-column indexes populate from
attrs, dangling edges are structurally impossible to persist (dropped +
recorded, not silently stored), and the read-only post-hoc check agrees."""

from __future__ import annotations

import sqlite3

import config
import pytest

from services.knowledge.graph import builder
from services.knowledge.graph import store as gstore


@pytest.fixture
def graph_ready():
    gstore.init_db()
    gstore.replace_graph([], [], [], {})
    yield


def test_kg_nodes_generated_columns_populate_from_attrs(graph_ready):
    gstore.replace_graph(
        [{"node_id": "package:npm:left-pad", "node_type": "package", "label": "left-pad",
          "attrs": {"ecosystem": "npm", "package": "left-pad", "source": "osv"}}],
        [], [], {},
    )
    con = sqlite3.connect(str(config.MEMORY_DB))
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT source, ecosystem, package FROM kg_nodes WHERE node_id=?",
        ("package:npm:left-pad",),
    ).fetchone()
    con.close()
    assert row["source"] == "osv"
    assert row["ecosystem"] == "npm"
    assert row["package"] == "left-pad"


def test_kg_nodes_generated_columns_are_indexed(graph_ready):
    con = sqlite3.connect(str(config.MEMORY_DB))
    idx_names = {r[1] for r in con.execute("PRAGMA index_list(kg_nodes)")}
    con.close()
    assert "idx_kg_nodes_ecosystem" in idx_names
    assert "idx_kg_nodes_package" in idx_names
    assert "idx_kg_nodes_source" in idx_names


def test_kg_edges_type_indexes_exist(graph_ready):
    con = sqlite3.connect(str(config.MEMORY_DB))
    idx_names = {r[1] for r in con.execute("PRAGMA index_list(kg_edges)")}
    con.close()
    assert "idx_kg_edges_type" in idx_names
    assert "idx_kg_edges_src_type" in idx_names
    assert "idx_kg_edges_dst_type" in idx_names


def test_dangling_edge_is_dropped_and_recorded(monkeypatch, graph_ready):
    """A relationship builder that (hypothetically) emitted an edge to a node
    absent from the same build must never have that edge land in storage —
    build() itself is the last line of defence, independent of whether the
    individual builder function stayed disciplined."""

    def _fake_vuln_relationships():
        nodes = [{"node_id": "cve:CVE-2099-00001", "node_type": "cve", "label": "x", "attrs": {}}]
        edges = [
            {"src": "cve:CVE-2099-00001", "dst": "cwe:CWE-DOES-NOT-EXIST",
             "edge_type": "classified_as", "attrs": {}},
        ]
        return nodes, edges

    def _empty():
        return [], []

    monkeypatch.setattr(builder, "_vuln_relationships", _fake_vuln_relationships)
    monkeypatch.setattr(builder, "_platform_relationships", _empty)
    monkeypatch.setattr(builder, "_control_relationships", _empty)
    monkeypatch.setattr(builder, "_ghsa_osv_relationships", _empty)

    stats = builder.build()
    assert stats["inconsistencies"]["dangling_edge_dropped"] == 1

    dangling = gstore.dangling_edges()
    assert dangling == []  # the bad edge was dropped, not stored

    incons = gstore.list_inconsistencies(kind="dangling_edge_dropped")
    assert len(incons) == 1
    assert incons[0]["attrs"]["dst"] == "cwe:CWE-DOES-NOT-EXIST"


def test_real_build_has_zero_dangling_edges(graph_ready):
    """End-to-end: whatever is actually installed right now, a real build()
    call must leave zero dangling edges in storage."""
    builder.build()
    assert gstore.dangling_edges() == []


# ---------------------------------------------------------------------------
# Splunk Security Content / Falco rules -> ATT&CK technique detection edges.
# Both packs embed real, source-supplied technique ids in their own YAML
# (`mitre_attack_id:\n  - T1190`, `tags: [..., T1555]`) — a bare-token
# extraction is safe here because these two packs are curated detection-rule
# content, never general prose.
# ---------------------------------------------------------------------------

def _seed_chunks(rows: list[dict]) -> None:
    con = sqlite3.connect(str(config.MEMORY_DB))
    for i, r in enumerate(rows):
        con.execute(
            "INSERT INTO knowledge_chunks (id,pack_id,title,canonical_url,content,chunk_index) "
            "VALUES (?,?,?,?,?,?)",
            (f"tid{i}", r["pack_id"], r.get("title"), r.get("url"), r.get("content", ""), i),
        )
    con.commit()
    con.close()


def test_splunk_detection_content_yields_technique_edge(graph_ready):
    _seed_chunks([{
        "pack_id": "splunk-security-content-src", "title": "citrix_sharefile_exploitation.yml",
        "url": "https://github.com/splunk/security_content/blob/x/detections/web/x.yml",
        "content": "name: Citrix ShareFile Exploitation\nmitre_attack_id:\n    - T1190\ncve:\n    - CVE-2023-24489\n",
    }])
    builder.build()
    node = gstore.get_node("technique:T1190")
    assert node is not None
    edges = [e for e in gstore.edges_from("technique:T1190") if e["edge_type"] == "detected_by"]
    assert any(e["dst"] == "pack:splunk-security-content-src" for e in edges)


def test_falco_rule_content_yields_technique_edge(graph_ready):
    _seed_chunks([{
        "pack_id": "falco-rules-src", "title": "rules.yaml",
        "url": "https://github.com/falcosecurity/rules/blob/x/rules.yaml",
        "content": "  tags: [maturity_stable, host, container, filesystem, mitre_credential_access, T1555]\n",
    }])
    builder.build()
    node = gstore.get_node("technique:T1555")
    assert node is not None
    edges = [e for e in gstore.edges_from("technique:T1555") if e["edge_type"] == "detected_by"]
    assert any(e["dst"] == "pack:falco-rules-src" for e in edges)
