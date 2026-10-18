"""Cross-source knowledge graph (Phase 9) — offline, synthetic knowledge_chunks.

Seeds the ``knowledge_chunks`` provenance table with a tiny hand-built set that
mimics the three ATT&CK-bearing sources (ATT&CK STIX / Atomic Red Team / Sigma),
then asserts the builder joins them on technique id and detects the intended
coverage gaps + dangling references. No network, no LLM, no Chroma.
"""

from __future__ import annotations

import sqlite3

import config
import pytest

from services.knowledge.graph import builder, query
from services.knowledge.graph import store as gstore


def _seed(rows: list[dict]) -> None:
    con = sqlite3.connect(str(config.MEMORY_DB))
    for i, r in enumerate(rows):
        con.execute(
            "INSERT INTO knowledge_chunks (id,pack_id,title,canonical_url,content,chunk_index) "
            "VALUES (?,?,?,?,?,?)",
            (f"c{i}", r["pack_id"], r.get("title"), r.get("url"), r.get("content", ""), i),
        )
    con.commit()
    con.close()


@pytest.fixture
def graph_ready():
    gstore.init_db()
    # clear any prior graph rows
    gstore.replace_graph([], [], [], {})
    yield


def _mitre(tid):
    base = tid.split(".")[0]
    sub = tid.split(".")[1] if "." in tid else None
    url = f"https://attack.mitre.org/techniques/{base}" + (f"/{sub}" if sub else "")
    return {"pack_id": "mitre-attack-src", "title": f"{tid} — Example Technique",
            "url": url, "content": f"{tid} description."}


def _atomic(tid):
    return {"pack_id": "atomic-red-team-src", "title": f"{tid} - Emulation Test",
            "url": f"https://github.com/redcanaryco/atomic-red-team/blob/x/atomics/{tid}/{tid}.md",
            "content": f"Atomic test for {tid}."}


def _sigma(tids):
    tagblock = "\n".join(f"    - attack.{t.lower()}" for t in tids)
    return {"pack_id": "sigma-src", "title": "some_detection_rule.yml",
            "url": "https://github.com/SigmaHQ/sigma/blob/x/rules/windows/some_detection_rule.yml",
            "content": f"title: Some Rule\ntags:\n{tagblock}\ndetection:\n  condition: all"}


def test_graph_joins_sources_and_finds_gaps(graph_ready):
    _seed([
        _mitre("T1003.001"), _atomic("T1003.001"), _sigma(["T1003.001"]),  # full
        _mitre("T1566"),                                                    # mapping only
        _mitre("T1490"), _sigma(["T1490"]),                                 # detection, no emulation
        _mitre("T1053"), _atomic("T1053"),                                  # emulation, no detection
        _sigma(["T9999"]),                                                  # dangling (unmapped)
    ])
    stats = builder.build()

    assert stats["techniques_mapped"] == 4          # 1003.001, 1566, 1490, 1053
    assert stats["inconsistencies"]["dangling_reference"] == 1
    assert stats["inconsistencies"]["detection_without_emulation"] == 1
    assert stats["inconsistencies"]["emulation_without_detection"] == 1
    assert stats["coverage"]["detection_and_emulation"] == 1  # only T1003.001


def test_technique_coverage_full(graph_ready):
    _seed([_mitre("T1003.001"), _atomic("T1003.001"), _sigma(["T1003.001"])])
    builder.build()
    cov = query.technique_coverage("T1003.001")
    assert cov is not None
    assert cov["mapped"] is True
    assert cov["is_subtechnique"] is True
    assert cov["parent"] == "T1003"
    assert cov["coverage"]["mapping"] and cov["coverage"]["mapping"][0]["pack_id"] == "mitre-attack-src"
    assert cov["coverage"]["emulation"][0]["pack_id"] == "atomic-red-team-src"
    assert cov["coverage"]["detection"][0]["pack_id"] == "sigma-src"
    assert cov["gap"].startswith("full")
    # citation carried through
    assert "attack.mitre.org/techniques/T1003/001" in (cov["source_url"] or "")


def test_technique_coverage_lowercase_and_missing(graph_ready):
    _seed([_mitre("T1059"), _sigma(["T1059"])])
    builder.build()
    # case-insensitive lookup
    cov = query.technique_coverage("t1059")
    assert cov and cov["gap"] == "detection without emulation"
    # a technique absent from the graph → None (router turns this into 404)
    assert query.technique_coverage("T4242") is None


def test_dangling_reference_recorded(graph_ready):
    _seed([_sigma(["T9999"])])
    builder.build()
    dangling = query.inconsistencies(kind="dangling_reference")
    assert len(dangling) == 1
    assert dangling[0]["subject"] == "T9999"
    cov = query.technique_coverage("T9999")
    assert cov["mapped"] is False
    assert "dangling" in cov["gap"]


def test_rebuild_is_idempotent(graph_ready):
    _seed([_mitre("T1003.001"), _atomic("T1003.001")])
    s1 = builder.build()
    s2 = builder.build()
    assert s1 == s2
    st = query.stats()
    assert st["built"] is True
    assert st["nodes_by_type"].get("technique", 0) >= 1
