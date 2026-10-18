"""Evaluation harness (Phase 8) — offline, deterministic, governance-gated."""

from __future__ import annotations

import pytest

from services.evaluation import datasets_gate, harness
from services.evaluation import store as estore


@pytest.fixture(autouse=True)
def _eval_db():
    estore.init_db()
    yield


# --- governance gate --------------------------------------------------------

def test_training_is_always_forbidden():
    with pytest.raises(datasets_gate.TrainingForbidden):
        datasets_gate.assert_training_forbidden()


def test_unknown_dataset_not_eval_eligible():
    d = datasets_gate.evaluate_dataset("does-not-exist")
    assert d["found"] is False
    assert d["eval_allowed"] is False
    assert d["training_allowed"] is False


def test_real_datasets_are_governed_and_never_training():
    from services.knowledge import registries
    items = registries.datasets().get("items", [])
    assert items, "expected governed datasets in the registry"
    for it in items:
        dec = datasets_gate.evaluate_dataset(it["id"])
        assert dec["training_allowed"] is False        # global disable
        assert dec["stored_as_knowledge"] is False      # eval never ingests


# --- suite loading ----------------------------------------------------------

def test_bundled_suite_loads():
    suites = harness.list_suites()
    ids = {s["suite_id"] for s in suites}
    assert "retrieval-grounding-v1" in ids
    suite = harness.load_suite("retrieval-grounding-v1")
    assert suite and len(suite["cases"]) >= 8
    assert suite["governance"]["training"] == "disabled"


# --- scoring ----------------------------------------------------------------

def test_score_case_pack_and_source_hit():
    case = {"id": "x", "query": "q", "expect_any_pack": ["mitre-attack-src"],
            "expect_source_substring": ["T1003.001"], "min_results": 1}
    results = [
        {"pack_id": "sigma-src", "title": "unrelated", "content": "noise"},
        {"pack_id": "mitre-attack-src", "title": "T1003.001 — LSASS Memory",
         "source_url": "https://attack.mitre.org/techniques/T1003/001", "content": "..."},
    ]
    s = harness.score_case(case, results)
    assert s["pack_hit"] and s["source_hit"] and s["passed"]
    assert s["first_hit_rank"] == 2       # first satisfying result is at rank 2
    assert s["citation_present"] is True


def test_score_case_miss_fails():
    case = {"id": "y", "query": "q", "expect_any_pack": ["gtfobins-src"],
            "expect_source_substring": ["certutil"], "min_results": 1}
    results = [{"pack_id": "sigma-src", "title": "nope", "content": "nothing here"}]
    s = harness.score_case(case, results)
    assert s["passed"] is False
    assert s["pack_hit"] is False
    assert s["source_hit"] is False


def test_score_case_reads_real_citation_schema_not_just_test_mocks():
    """2026-09-15 regression: retrieval.retrieve()'s real _citation() dicts use
    "chunk" for body text and "document" for the filename/title — never
    "content" or "title" (those are only what unit-test mocks happened to use).
    _result_pack already handled both key spellings (pack_id/knowledge_pack);
    _result_text did not, so it silently never saw a live citation's actual
    chunk body — only source_title/source_url — and any case whose expected
    substring lived only in the body text failed source_hit even when the
    correct evidence was right there at rank 1."""
    case = {"id": "z", "query": "q", "expect_any_pack": ["sigma-src"],
            "expect_source_substring": ["t1021"], "min_results": 1}
    real_shaped_citation = {
        "n": 1, "chunk_id": "abc", "document": "lateral_movement_rule.yml",
        "chunk": "tags:\n  - attack.lateral-movement\n  - attack.t1021.001",
        "score": 0.9, "knowledge_pack": "sigma-src",
        "source_title": "Generic Lateral Movement Rule",  # deliberately doesn't contain "t1021"
        "source_url": "https://example.invalid/rule", "publisher": "SigmaHQ",
    }
    s = harness.score_case(case, [real_shaped_citation])
    assert s["source_hit"] is True, "must find the expected substring in the chunk body, not just title/URL"
    assert s["passed"] is True
    assert s["first_hit_rank"] == 1


@pytest.mark.asyncio
async def test_run_suite_with_fake_retriever_persists_and_aggregates():
    # A retriever that always returns a grounded LSASS-style hit → every case
    # gets a result, but only cases expecting mitre/T1003 fully pass.
    async def fake(query, top_k):
        return [{"pack_id": "mitre-attack-src", "title": "T1003.001 — LSASS Memory",
                 "source_url": "https://attack.mitre.org/techniques/T1003/001",
                 "content": "lsass credentials T1003.001"}]

    run = await harness.run_suite("retrieval-grounding-v1", retriever=fake, top_k=5)
    assert run["case_count"] >= 8
    m = run["metrics"]
    assert 0.0 <= m["pass_rate"] <= 1.0
    assert m["citation_rate"] == 1.0        # fake always cites
    assert m["mean_results"] == 1.0
    # persisted
    fetched = estore.get_run(run["id"])
    assert fetched is not None
    assert fetched["case_count"] == run["case_count"]
    assert len(fetched["results"]) == run["case_count"]


@pytest.mark.asyncio
async def test_run_suite_unknown_raises():
    with pytest.raises(ValueError):
        await harness.run_suite("no-such-suite")
