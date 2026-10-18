"""Project-artifact retrieval must disambiguate near-identical documents that
differ only by an identifier (IP/CVE/version) the query names. Reproduces the
multi-document miss (vector-only ranking returned the wrong near-identical doc)
and proves the exact-token boost fixes it. No live stack: the Chroma collection
is stubbed, so this is deterministic.
"""
from __future__ import annotations

import config
from services import rag_service


class _FakeCol:
    def __init__(self, docs):
        self._docs = docs

    def count(self):
        return len(self._docs)

    def query(self, query_texts=None, n_results=10, where=None):
        # Return docs in a DELIBERATELY WRONG vector order (the doc that matches
        # the queried IP is NOT first), with near-identical cosine distances —
        # exactly the near-duplicate situation embeddings can't separate.
        items = self._docs[:n_results]
        return {
            "documents": [[d["doc"] for d in items]],
            "metadatas": [[{"filename": d["file"]} for d in items]],
            "distances": [[d["dist"] for d in items]],
        }


def _fixtures():
    # Five near-identical notes differing only by IP; vector order puts the
    # wanted one (.40) in the middle with a slightly worse distance.
    return [
        {"file": "n41.pdf", "doc": "The host runs vsftpd 2.3.4 on 10.20.30.41 and is in scope.", "dist": 0.20},
        {"file": "n42.pdf", "doc": "The host runs vsftpd 2.3.4 on 10.20.30.42 and is in scope.", "dist": 0.21},
        {"file": "n40.pdf", "doc": "The host runs vsftpd 2.3.4 on 10.20.30.40 and is in scope.", "dist": 0.22},
        {"file": "n43.pdf", "doc": "The host runs vsftpd 2.3.4 on 10.20.30.43 and is in scope.", "dist": 0.23},
        {"file": "n44.pdf", "doc": "The host runs vsftpd 2.3.4 on 10.20.30.44 and is in scope.", "dist": 0.24},
    ]


def test_distinctive_tokens_picks_ids_not_common_words():
    t = rag_service._distinctive_tokens("what service runs at 10.20.30.40 per CVE-2021-44228 version 2.3.4 and nmap")
    assert "10.20.30.40" in t and "cve-2021-44228" in t and "2.3.4" in t
    assert "service" not in t and "what" not in t  # common words excluded


def test_exact_ip_doc_is_surfaced_top_despite_worse_vector_rank(monkeypatch):
    monkeypatch.setattr(rag_service, "_get_collection", lambda: _FakeCol(_fixtures()))
    hits = rag_service._search("what service and version run at 10.20.30.40?", top_k=1, project_id="p1")
    assert hits, "should return a hit"
    assert hits[0]["document"] == "n40.pdf"  # the exact-IP doc, not the vector-rank-1 n41


def test_no_distinctive_token_preserves_vector_order(monkeypatch):
    monkeypatch.setattr(rag_service, "_get_collection", lambda: _FakeCol(_fixtures()))
    # a query with no id token must not be reordered by the boost
    hits = rag_service._search("what service is running on the host?", top_k=5, project_id="p1")
    assert [h["document"] for h in hits] == ["n41.pdf", "n42.pdf", "n40.pdf", "n43.pdf", "n44.pdf"]
