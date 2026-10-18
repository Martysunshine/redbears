#!/usr/bin/env python3
"""Phase 1 diagnostic (2026-09-15 accuracy improvement cycle).

Runs a suite against the LIVE store the same way scripts/run_retrieval_eval.py
does, but captures far more than pass/fail: for every case, the top-10 fused
results are cross-referenced back to their raw per-channel scores (BM25 rank
from FTS5, cosine-similarity score from Chroma, RRF contribution, final
trust/freshness-weighted score), plus duplicate/near-duplicate detection and
an identifier scan of the query. Failing or low-MRR cases get a best-effort
cause classification against the taxonomy the task specified; anything the
heuristics can't confidently place is left for manual review rather than
guessed at.

Read-only: never writes to the knowledge store. Writes a JSON report under
data/reports/ (gitignored) and prints a compact per-case table to stdout.

Run (from backend/):
    python -m scripts.diagnostic_retrieval_accuracy --suite retrieval-100k-v1
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402
from services.evaluation import harness  # noqa: E402
from services.knowledge import retrieval, store  # noqa: E402
from services.knowledge.vulnerabilities import identity as vuln_identity  # noqa: E402
from services import rag_service  # noqa: E402

# Rough identifier shapes for the diagnostic's query-classification pass only —
# NOT the retrieval-time boost logic (that lives in retrieval.py / Phase 3).
_ATTACK_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b", re.IGNORECASE)
_OWASP_LLM_RE = re.compile(r"\bLLM0?\d{1,2}\b", re.IGNORECASE)
_WIN_EVENT_RE = re.compile(r"\b(?:event\s*id\s*)?4\d{3}\b", re.IGNORECASE)


def _query_identifiers(query: str) -> dict:
    vuln_ids = vuln_identity.find_identifiers(query)
    return {
        **{k: v for k, v in vuln_ids.items() if v},
        "attack": sorted(set(m.group(0).upper() for m in _ATTACK_RE.finditer(query))),
        "owasp_llm": sorted(set(m.group(0).upper() for m in _OWASP_LLM_RE.finditer(query))),
    }


def _near_dup_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:400], b[:400]).ratio()


async def _channel_snapshot(query: str, pack_ids: list[str] | None, pool: int):
    """Independently re-run each retrieval channel so we can attribute the
    fused top-10 back to its raw BM25/vector scores. Mirrors retrieval.retrieve's
    own channel calls exactly, so ids line up."""
    allowed_vuln = retrieval._VULN_PACK_IDS if pack_ids is None else (retrieval._VULN_PACK_IDS & set(pack_ids))
    vec, lex, vuln_vec = await asyncio.gather(
        rag_service.vector_search_knowledge_async(query, pool, pack_ids),
        asyncio.to_thread(store.lexical_search, query, pack_ids, pool),
        rag_service.vector_search_vulnerabilities_async(query, pool) if allowed_vuln else retrieval._empty_list(),
    )
    vuln_vec = [
        {"id": h["id"], "content": h.get("content", ""), "pack_id": (h.get("metadata") or {}).get("knowledge_pack"),
         "score": h.get("score")}
        for h in vuln_vec if (h.get("metadata") or {}).get("knowledge_pack") in allowed_vuln
    ]
    vec_by_id = {c["id"]: {"rank": i + 1, "score": c.get("score")} for i, c in enumerate(vec)}
    for i, c in enumerate(vuln_vec):
        vec_by_id.setdefault(c["id"], {"rank": i + 1, "score": c.get("score")})
    lex_by_id = {c["id"]: {"rank": i + 1, "bm25": c.get("rank")} for i, c in enumerate(lex)}
    return vec_by_id, lex_by_id


TAXONOMY = [
    "missing_knowledge", "incorrect_or_incomplete_expectation", "query_understanding_failure",
    "exact_identifier_failure", "acronym_or_alias_failure", "bm25_idf_corpus_drift",
    "vector_semantic_mismatch", "fusion_weight_problem", "chunk_boundary_problem",
    "duplicate_or_near_duplicate_competition", "weak_metadata", "wrong_source_priority",
    "followup_context_failure", "answer_synthesis_failure", "genuine_insufficient_evidence",
    "ranked_outside_official_cutoff", "needs_manual_review",
]


def _classify(case: dict, score: dict, top10: list[dict], vec_by_id: dict, lex_by_id: dict) -> tuple[str, str]:
    """Best-effort heuristic cause classification. Returns (cause, rationale).
    Conservative on purpose: falls back to needs_manual_review rather than
    guessing a specific mechanism the evidence doesn't actually support."""
    expect_packs = set(p.lower() for p in case.get("expect_any_pack", []))
    result_count = score["result_count"]

    if case.get("expect_insufficient"):
        if score["passed"]:
            return "genuine_insufficient_evidence", "correctly returned nothing for an out-of-scope query"
        return "answer_synthesis_failure", "corpus returned results for a query meant to have none — check retrieve()'s no-cutoff behavior, not a knowledge gap"

    if score["passed"] and (score["first_hit_rank"] or 99) <= 2:
        return "none", "passing at rank <=2, no diagnostic needed"

    if result_count == 0:
        return "missing_knowledge", "zero candidates returned from any channel for this query"

    packs_seen = {(r.get("pack_id") or "").lower() for r in top10}
    if expect_packs and not (expect_packs & packs_seen):
        # Expected pack never appears anywhere in top10 at all (not just outranked).
        vec_present = any((c.get("pack_id") or "").lower() in expect_packs for c in [])  # placeholder, filled by caller if needed
        return "missing_knowledge", f"expected pack(s) {sorted(expect_packs)} do not appear anywhere in top-10; likely absent from the corpus or never surfaced by either channel for this phrasing"

    if not score["passed"] and expect_packs and (expect_packs & packs_seen):
        # Expected pack IS present in top10 but scoring still failed -> source-substring mismatch most likely.
        return "incorrect_or_incomplete_expectation", "expected pack appears in top-10 but expect_source_substring never matched — check the expectation string against actual stored text"

    # Passed, but ranked low (first_hit_rank > 2): investigate why.
    rank = score.get("first_hit_rank")
    if rank and rank > 2:
        hit = top10[rank - 1] if rank - 1 < len(top10) else None
        if hit:
            cid = hit.get("chunk_id") or hit.get("id")
            in_vec = cid in vec_by_id
            in_lex = cid in lex_by_id
            # near-duplicate competition: an earlier-ranked entry is near-identical text
            # from a different chunk, occupying a slot the same evidence could have used.
            for earlier in top10[:rank - 1]:
                if _near_dup_ratio(earlier.get("chunk") or "", hit.get("chunk") or "") > 0.85 and \
                   (earlier.get("chunk_id") != hit.get("chunk_id")):
                    return "duplicate_or_near_duplicate_competition", \
                        f"near-duplicate chunk ({earlier.get('chunk_id')}) occupies an earlier slot with >85% text overlap"
            ids = _query_identifiers(case.get("query", ""))
            has_id = any(ids.get(k) for k in ("cve", "cwe", "capec", "attack", "owasp_llm"))
            if has_id and not (in_vec and vec_by_id[cid]["rank"] <= 3):
                return "exact_identifier_failure", \
                    f"query names an identifier {ids}; correct chunk not in vector top-3 (vec_rank={vec_by_id.get(cid, {}).get('rank')}) — needs identifier-aware boosting"
            if in_lex and not in_vec:
                return "vector_semantic_mismatch", "chunk found only by the lexical/BM25 channel, not by vector — embedding did not consider it semantically close"
            if in_vec and not in_lex:
                return "bm25_idf_corpus_drift", "chunk found only by the vector channel; lexical channel never surfaced it (consistent with corpus-wide term-frequency drift, not a missing term)"
            if in_vec and in_lex:
                return "fusion_weight_problem", f"chunk present in both channels (vec_rank={vec_by_id[cid]['rank']}, lex_rank={lex_by_id[cid]['rank']}) but fused rank is {rank} — RRF weighting pushed it down"
        return "needs_manual_review", "passed but ranked low; no single heuristic matched confidently"

    return "needs_manual_review", "did not match any heuristic bucket"


async def run(suite_id: str, top_k: int, pool: int) -> dict:
    rag_service._get_knowledge_collection()
    rag_service._get_vuln_collection()

    suite = harness.load_suite(suite_id)
    if suite is None:
        raise SystemExit(f"suite '{suite_id}' not found")

    pack_ids = store.enabled_pack_ids() or None
    case_reports = []

    for case in suite.get("cases", []):
        query = case["query"]
        # Fetch 10 for diagnostic visibility, but score pass/fail against the
        # OFFICIAL top_k cutoff (matches run_retrieval_eval.py's gate) — scoring
        # against the full 10 would silently inflate the pass rate relative to
        # what actually ships, and hide "evidence exists but ranked outside the
        # real cutoff" as a distinct, actionable finding.
        results = await retrieval.retrieve(query, top_k=max(top_k, 10))
        score = harness.score_case(case, results[:top_k])
        score_ext = harness.score_case(case, results[:10])
        top10 = results[:10]

        vec_by_id, lex_by_id = await _channel_snapshot(query, pack_ids, pool)

        enriched_top10 = []
        seen_hashes = {}
        for r in top10:
            cid = r.get("chunk_id")
            vinfo = vec_by_id.get(cid, {})
            linfo = lex_by_id.get(cid, {})
            channels = []
            if vinfo:
                channels.append("vector")
            if linfo:
                channels.append("lexical")
            snippet = (r.get("chunk") or "")[:300]
            dup_of = None
            for prev_cid, prev_snip in seen_hashes.items():
                if _near_dup_ratio(snippet, prev_snip) > 0.85:
                    dup_of = prev_cid
                    break
            seen_hashes[cid] = snippet
            enriched_top10.append({
                "chunk_id": cid,
                "chunk": snippet,
                "pack_id": r.get("knowledge_pack"),
                "source_title": r.get("source_title"),
                "source_url": r.get("source_url"),
                "trust_level": r.get("trust_level"),
                "final_score": r.get("score"),
                "channels": channels or ["exact_id_boost_or_unattributed"],
                "vector_rank": vinfo.get("rank"),
                "vector_score": vinfo.get("score"),
                "lexical_rank": linfo.get("rank"),
                "lexical_bm25": linfo.get("bm25"),
                "near_duplicate_of": dup_of,
            })

        cause, rationale = _classify(case, score, enriched_top10, vec_by_id, lex_by_id)
        if not score["passed"] and score_ext["passed"]:
            cause = "ranked_outside_official_cutoff"
            rationale = f"evidence found at extended rank {score_ext['first_hit_rank']} (>official top_k={top_k}) — ranking problem, not missing knowledge"
        case_reports.append({
            "case_id": case["id"],
            "query": query,
            "expect_any_pack": case.get("expect_any_pack", []),
            "expect_source_substring": case.get("expect_source_substring", []),
            "expect_insufficient": case.get("expect_insufficient", False),
            "passed": score["passed"],
            "passed_extended_top10": score_ext["passed"],
            "first_hit_rank": score["first_hit_rank"],
            "first_hit_rank_extended": score_ext["first_hit_rank"],
            "result_count": score["result_count"],
            "citation_present": score["citation_present"],
            "query_identifiers": _query_identifiers(query),
            "cause": cause,
            "cause_rationale": rationale,
            "top10": enriched_top10,
        })

    n = len(case_reports) or 1
    summary = {
        "suite_id": suite_id,
        "cases": len(case_reports),
        "passed": sum(1 for c in case_reports if c["passed"]),
        "pass_rate": round(sum(1 for c in case_reports if c["passed"]) / n, 4),
        "mrr": round(sum((1.0 / c["first_hit_rank"]) for c in case_reports if c["first_hit_rank"]) / n, 4),
        "cause_histogram": {},
    }
    for c in case_reports:
        if c["cause"] != "none":
            summary["cause_histogram"][c["cause"]] = summary["cause_histogram"].get(c["cause"], 0) + 1

    return {"summary": summary, "cases": case_reports}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="retrieval-100k-v1")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--pool", type=int, default=config.KNOWLEDGE_CANDIDATE_POOL)
    args = ap.parse_args()

    report = asyncio.run(run(args.suite, args.top_k, args.pool))

    print("=" * 72)
    print(f"DIAGNOSTIC — {args.suite}")
    print("=" * 72)
    print(json.dumps(report["summary"], indent=2))
    print("-" * 72)
    for c in report["cases"]:
        if not c["passed"] or (c["first_hit_rank"] or 99) > 2:
            print(f"  [{c['cause']}] {c['case_id']}: passed={c['passed']} rank={c['first_hit_rank']} — {c['cause_rationale'][:100]}")
    print("=" * 72)

    reports_dir = Path(config.DATA_DIR) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = reports_dir / f"diagnostic_{args.suite}_{ts}.json"
    latest = reports_dir / f"diagnostic_{args.suite}_latest.json"
    payload = json.dumps(report, indent=2)
    out.write_text(payload)
    latest.write_text(payload)
    print(f"\nJSON report:\n  {out}\n  {latest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
