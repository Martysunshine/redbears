#!/usr/bin/env python3
"""Measure the RAG follow-up fix against the LIVE knowledge store.

Each case is a two-turn exchange: a ``prior_user`` question and an anaphoric
``followup`` ("how is it exploited?"). For every case this runs the real hybrid
retriever (``services.knowledge.retrieval.retrieve`` — the same path the eval
gate and the RAG Analyst use) twice:

* **bare**     — retrieve on the follow-up text alone (old behaviour).
* **anchored** — retrieve on ``prompt_utils.build_followup_query(followup,
                 history)``, which prepends the prior user turn when the question
                 looks like a follow-up (new behaviour).

Scoring reuses ``services.evaluation.harness.score_case`` so the numbers are
comparable to the retrieval-100k gate. Read-only: it never writes to the store.
Writes a JSON report under ``data/reports/`` (gitignored).

Run (from ``backend/``):
    python -m scripts.run_followup_eval
    python -m scripts.run_followup_eval --top-k 5
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402
import prompt_utils  # noqa: E402
from services.evaluation import harness  # noqa: E402

_SUITES_DIR = _BACKEND_DIR / "services" / "evaluation" / "suites"


def _load(suite_id: str) -> dict:
    for fp in _SUITES_DIR.glob("*.json"):
        d = json.loads(fp.read_text(encoding="utf-8"))
        if d.get("suite_id", fp.stem) == suite_id:
            return d
    raise ValueError(f"suite '{suite_id}' not found")


async def _run(suite_id: str, top_k: int) -> dict:
    from services import rag_service
    from services.knowledge import retrieval

    # Warm the shared Chroma singletons in the MAIN thread first. retrieval.retrieve
    # fans out three retrievers via asyncio.gather; if the client + collections were
    # created for the first time concurrently in worker threads, chromadb 1.5.9's
    # SharedSystemClient hits an init race. The live server warms these at startup,
    # so this priming only matters for the standalone script (no behaviour change).
    rag_service._get_knowledge_collection()
    rag_service._get_vuln_collection()

    suite = _load(suite_id)
    bare_scored: list[dict] = []
    enriched_scored: list[dict] = []
    per_case: list[dict] = []

    for case in suite.get("cases", []):
        history = [{"role": "user", "content": case["prior_user"]}]
        bare_q = case["followup"]
        anchored_q = prompt_utils.build_followup_query(case["followup"], history)
        scoring = {
            "id": case["id"],
            "expect_any_pack": case.get("expect_any_pack", []),
            "expect_source_substring": case.get("expect_source_substring", []),
            "min_results": case.get("min_results", 1),
        }

        res_bare = await retrieval.retrieve(bare_q, top_k=top_k)
        res_anch = await retrieval.retrieve(anchored_q, top_k=top_k)
        sb = harness.score_case({**scoring, "query": bare_q}, res_bare or [])
        sa = harness.score_case({**scoring, "query": anchored_q}, res_anch or [])
        bare_scored.append(sb)
        enriched_scored.append(sa)
        per_case.append({
            "case_id": case["id"],
            "rewritten": anchored_q != bare_q,
            "bare_query": bare_q,
            "anchored_query": anchored_q,
            "bare_passed": sb["passed"],
            "anchored_passed": sa["passed"],
            "bare_rank": sb["first_hit_rank"],
            "anchored_rank": sa["first_hit_rank"],
        })

    return {
        "suite_id": suite_id,
        "top_k": top_k,
        "bare": harness._aggregate(bare_scored),
        "anchored": harness._aggregate(enriched_scored),
        "cases": per_case,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure the follow-up retrieval fix on the live store.")
    ap.add_argument("--suite", default="retrieval-followup-v1")
    ap.add_argument("--top-k", type=int, default=5)
    args = ap.parse_args()

    run = asyncio.run(_run(args.suite, args.top_k))
    b, a = run["bare"], run["anchored"]
    rewritten = sum(1 for c in run["cases"] if c["rewritten"])

    print("=" * 76)
    print(f"FOLLOW-UP RETRIEVAL EVAL — {run['suite_id']}  (top_k={run['top_k']})")
    print("=" * 76)
    print(f"  cases              : {b['cases']}")
    print(f"  detector fired on  : {rewritten}/{b['cases']} follow-ups (rest left unchanged)")
    print("-" * 76)
    print(f"  {'metric':<18}{'bare':>12}{'anchored':>12}{'delta':>12}")
    for key in ("pass_rate", "source_hit_rate", "pack_hit_rate", "mrr"):
        bv, av = b[key], a[key]
        print(f"  {key:<18}{bv:>12.4f}{av:>12.4f}{av - bv:>+12.4f}")
    print("-" * 76)
    print("  per-case (rank: lower is better, None = not found):")
    for c in run["cases"]:
        flag = "→rewritten" if c["rewritten"] else "  unchanged"
        print(f"    {c['case_id']:<26} {flag}  bare={str(c['bare_passed']):<5} "
              f"anchored={str(c['anchored_passed']):<5}  rank {c['bare_rank']} → {c['anchored_rank']}")
    print("=" * 76)

    reports_dir = Path(config.DATA_DIR) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = reports_dir / f"retrieval_followup_eval_{ts}.json"
    latest = reports_dir / "retrieval_followup_eval_latest.json"
    payload = json.dumps(run, indent=2)
    out.write_text(payload)
    latest.write_text(payload)
    print(f"\nJSON report:\n  {out}\n  {latest}")
    # Informational gate: the fix should not REDUCE the pass rate.
    return 0 if a["pass_rate"] >= b["pass_rate"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
