"""Evaluation harness: load suites, run each case through retrieval, score.

The retriever is injectable so the harness is testable offline. In production it
defaults to the Knowledge Service hybrid retrieval (``retrieval.retrieve``).

Scoring per case (deterministic, string-level — no LLM judge):

* **pack_hit**   — a result comes from one of ``expect_any_pack`` (if declared).
* **source_hit** — any of ``expect_source_substring`` appears in a result's
  title / source_url / content (case-insensitive). This is the grounding check.
* **first_hit_rank** — 1-based rank of the first result satisfying the case →
  reciprocal-rank contribution to MRR.
* **citation_present** — at least one result carries a source_url.
* **passed** — min_results met AND (pack_hit if packs declared) AND source_hit.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import store

_SUITES_DIR = Path(__file__).parent / "suites"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- suite loading ----------------------------------------------------------

def list_suites() -> list[dict]:
    out = []
    for fp in sorted(_SUITES_DIR.glob("*.json")):
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        out.append({
            "suite_id": d.get("suite_id", fp.stem),
            "title": d.get("title"),
            "description": d.get("description"),
            "case_count": len(d.get("cases", [])),
            "default_top_k": d.get("default_top_k", 8),
            "governance": d.get("governance", {}),
        })
    return out


def load_suite(suite_id: str) -> dict | None:
    for fp in _SUITES_DIR.glob("*.json"):
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if d.get("suite_id", fp.stem) == suite_id:
            return d
    return None


# --- scoring ----------------------------------------------------------------

def _result_pack(r: dict) -> str | None:
    return r.get("pack_id") or r.get("knowledge_pack")


def _result_text(r: dict) -> str:
    # 2026-09-15: real citations from retrieval.retrieve()/_citation() use
    # "chunk" (body text) and "document" (filename/title) — not "content" and
    # "title". _result_pack already handled both schemas (pack_id/knowledge_pack);
    # this one didn't, so the source_hit substring check silently never saw a
    # live citation's actual chunk body — only source_title/source_url — since
    # r.get("content") and r.get("title") are always None on a real result.
    # Existing unit-test mocks that build dicts with "content"/"title" keep
    # working unchanged; this only adds the keys real retrieval actually uses.
    parts = [r.get("source_title"), r.get("title"), r.get("source_url"),
             r.get("canonical_url"), r.get("content"), r.get("chunk"), r.get("document")]
    return " ".join(p for p in parts if p).lower()


def score_case(case: dict, results: list[dict]) -> dict:
    # Optional, additive: a case that asserts the corpus honestly has NOTHING
    # relevant (out-of-scope query) rather than fabricating a match. Every
    # existing case omits this field, so its behavior is completely
    # unchanged; only a case that opts in with `"expect_insufficient": true`
    # takes this branch.
    if case.get("expect_insufficient"):
        passed = len(results) == 0
        return {
            "case_id": case["id"],
            "query": case.get("query"),
            "passed": passed,
            "pack_hit": True,
            "source_hit": True,
            "first_hit_rank": None,
            "result_count": len(results),
            "citation_present": False,
            "detail": {
                "expect_insufficient": True,
                "top_packs": [_result_pack(r) for r in results[:5]],
            },
        }

    expect_packs = [p.lower() for p in case.get("expect_any_pack", [])]
    expect_subs = [s.lower() for s in case.get("expect_source_substring", [])]
    min_results = case.get("min_results", 1)

    pack_hit = False
    source_hit = False
    first_hit_rank = None
    citation_present = any((r.get("source_url") or r.get("canonical_url")) for r in results)

    for i, r in enumerate(results, start=1):
        pack = (_result_pack(r) or "").lower()
        text = _result_text(r)
        p_ok = (not expect_packs) or (pack in expect_packs)
        s_ok = (not expect_subs) or any(sub in text for sub in expect_subs)
        if p_ok and pack in expect_packs:
            pack_hit = True
        if s_ok and expect_subs and any(sub in text for sub in expect_subs):
            source_hit = True
        if (p_ok and s_ok) and first_hit_rank is None:
            first_hit_rank = i

    if not expect_packs:
        pack_hit = True  # no pack expectation → not a failure dimension
    if not expect_subs:
        source_hit = True

    passed = (len(results) >= min_results) and pack_hit and source_hit
    return {
        "case_id": case["id"],
        "query": case.get("query"),
        "passed": passed,
        "pack_hit": pack_hit,
        "source_hit": source_hit,
        "first_hit_rank": first_hit_rank,
        "result_count": len(results),
        "citation_present": citation_present,
        "detail": {
            "expect_any_pack": case.get("expect_any_pack", []),
            "expect_source_substring": case.get("expect_source_substring", []),
            "top_packs": [_result_pack(r) for r in results[:5]],
        },
    }


def _aggregate(scored: list[dict]) -> dict:
    n = len(scored) or 1
    mrr = sum((1.0 / s["first_hit_rank"]) for s in scored if s["first_hit_rank"]) / n
    return {
        "cases": len(scored),
        "passed": sum(1 for s in scored if s["passed"]),
        "pass_rate": round(sum(1 for s in scored if s["passed"]) / n, 4),
        "pack_hit_rate": round(sum(1 for s in scored if s["pack_hit"]) / n, 4),
        "source_hit_rate": round(sum(1 for s in scored if s["source_hit"]) / n, 4),
        "citation_rate": round(sum(1 for s in scored if s["citation_present"]) / n, 4),
        "mrr": round(mrr, 4),
        "mean_results": round(sum(s["result_count"] for s in scored) / n, 2),
    }


# --- run --------------------------------------------------------------------

async def _default_retriever(query: str, top_k: int) -> list[dict]:
    from services.knowledge import retrieval
    return await retrieval.retrieve(query, top_k=top_k)


async def run_suite(suite_id: str, *, top_k: int | None = None, retriever=None,
                    persist: bool = True) -> dict:
    suite = load_suite(suite_id)
    if suite is None:
        raise ValueError(f"eval suite '{suite_id}' not found")
    retriever = retriever or _default_retriever
    k = top_k or suite.get("default_top_k", 8)

    started = _ts()
    scored: list[dict] = []
    for case in suite.get("cases", []):
        results = await retriever(case["query"], k)
        scored.append(score_case(case, results or []))

    metrics = _aggregate(scored)
    run = {
        "id": f"eval-{suite_id}-{uuid.uuid4().hex[:8]}",
        "suite_id": suite_id,
        "title": suite.get("title"),
        "top_k": k,
        "case_count": len(scored),
        "passed": metrics["passed"],
        "metrics": metrics,
        "status": "completed",
        "started_at": started,
        "finished_at": _ts(),
    }
    if persist:
        store.save_run(run, scored)
    run["results"] = scored
    run["governance"] = suite.get("governance", {})
    return run
