"""GHSA/OSV -> CVE/CWE knowledge-graph edges — real identifiers only, never
a dangling/fabricated edge when the target CVE/CWE was never actually synced."""

from __future__ import annotations

import pytest

from services.knowledge.graph import builder as graph_builder
from services.knowledge.graph import store as gstore
from services.knowledge.vulnerabilities import osv_store, store as vstore
from services.knowledge.vulnerabilities.models import NvdCveEntry
from services.knowledge.vulnerabilities.sources.osv_schema import OsvRecord


@pytest.fixture
def graph_ready():
    gstore.init_db()
    gstore.replace_graph([], [], [], {})
    yield


def test_ghsa_to_cve_edge_only_when_cve_actually_synced():
    vstore.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-77001", description="real cve")])
    osv_store.upsert_ghsa(OsvRecord(record_id="GHSA-2345-6789-CFGH", summary="s",
                                    aliases=["CVE-2024-77001", "CVE-2024-99999"]))
    nodes, edges = graph_builder._ghsa_osv_relationships()
    node_ids = {n["node_id"] for n in nodes}
    assert "ghsa:GHSA-2345-6789-CFGH" in node_ids
    assert "cve:CVE-2024-77001" in node_ids
    assert "cve:CVE-2024-99999" not in node_ids  # never synced -> no dangling node

    doc_edges = [e for e in edges if e["edge_type"] == "documents"]
    assert doc_edges == [{"src": "ghsa:GHSA-2345-6789-CFGH", "dst": "cve:CVE-2024-77001",
                          "edge_type": "documents", "attrs": {}}]


def test_osv_to_cwe_edge_only_when_cwe_actually_synced():
    from services.knowledge.vulnerabilities.models import CweRecord
    vstore.sync_cwe_records([CweRecord(cwe_id="CWE-79", name="XSS")])
    osv_store.upsert_osv(OsvRecord(record_id="PYSEC-2024-1", summary="s",
                                   cwe_ids=["CWE-79", "CWE-99999"]),
                         ecosystem_source="PyPI")
    nodes, edges = graph_builder._ghsa_osv_relationships()
    class_edges = [e for e in edges if e["edge_type"] == "classified_as" and e["src"] == "osv:PYSEC-2024-1"]
    assert class_edges == [{"src": "osv:PYSEC-2024-1", "dst": "cwe:CWE-79",
                            "edge_type": "classified_as", "attrs": {}}]


def test_no_ghsa_osv_data_returns_empty_without_error():
    nodes, edges = graph_builder._ghsa_osv_relationships()
    assert nodes == []
    assert edges == []


def test_build_integrates_ghsa_osv_nodes_into_full_graph(graph_ready):
    vstore.sync_nvd_batch([NvdCveEntry(cve_id="CVE-2024-77002", description="d")])
    osv_store.upsert_ghsa(OsvRecord(record_id="GHSA-2345-6789-CFGJ", summary="s",
                                    aliases=["CVE-2024-77002"]))
    stats = graph_builder.build()
    assert stats["nodes_by_type"].get("ghsa", 0) >= 1
