#!/usr/bin/env python3
"""Run a knowledge-retrieval evaluation suite against the LIVE store.

Drives Oyster's real hybrid retrieval path (``services.knowledge.retrieval.
retrieve`` — vector over ``oyster_knowledge`` + ``oyster_vulnerabilities`` fused
with the FTS5 lexical half, exactly what ``/rag/security-chat`` and the Knowledge
Service use) for every case in a suite, at ``--top-k`` (default 5), and reports
the top-k retrieval success rate + MRR + per-case detail.

This is the Phase-4 acceptance gate: at least 90% of cases must retrieve an
expected relevant source within the top 5, with a grounding citation, and with
no cross-source attribution corruption.

Writes a JSON report under ``data/reports/`` (gitignored). Exit code is non-zero
when the pass rate is below ``--min-pass-rate`` (default 0.90).

Run (from ``backend/``):
    python -m scripts.run_retrieval_eval
    python -m scripts.run_retrieval_eval --suite retrieval-100k-v1 --top-k 5
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
from services.evaluation import harness  # noqa: E402


async def _run(suite_id: str, top_k: int) -> dict:
    from services import rag_service

    # Warm the shared Chroma singletons in the MAIN thread first. retrieval.retrieve
    # (invoked per-case inside harness.run_suite) fans out three retrievers via
    # asyncio.gather; if the client + collections were created for the first time
    # concurrently in worker threads, chromadb 1.5.9's SharedSystemClient hits an
    # init race. The live server warms these at startup, so this priming only
    # matters for this standalone script (no behaviour change) — same fix as
    # scripts/run_followup_eval.py.
    rag_service._get_knowledge_collection()
    rag_service._get_vuln_collection()

    # persist=False: the eval never writes into the knowledge store, only reads it.
    return await harness.run_suite(suite_id, top_k=top_k, persist=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run a retrieval eval suite against the live store.")
    ap.add_argument("--suite", default="retrieval-100k-v1")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--min-pass-rate", type=float, default=0.90)
    ap.add_argument("--show-failures", action="store_true", default=True)
    args = ap.parse_args()

    run = asyncio.run(_run(args.suite, args.top_k))
    m = run["metrics"]

    failures = [r for r in run["results"] if not r["passed"]]
    # cross-source attribution corruption check: every retrieved result that
    # satisfied a case must carry a citation (source_url/canonical_url).
    citation_rate = m["citation_rate"]

    print("=" * 72)
    print(f"RETRIEVAL EVAL — {run['suite_id']}  (top_k={run['top_k']})")
    print("=" * 72)
    print(f"  cases            : {m['cases']}")
    print(f"  passed           : {m['passed']}")
    print(f"  pass_rate (top{run['top_k']}) : {m['pass_rate']*100:.2f}%")
    print(f"  pack_hit_rate    : {m['pack_hit_rate']*100:.2f}%")
    print(f"  source_hit_rate  : {m['source_hit_rate']*100:.2f}%")
    print(f"  citation_rate    : {citation_rate*100:.2f}%")
    print(f"  MRR              : {m['mrr']}")
    print(f"  mean_results     : {m['mean_results']}")
    if failures and args.show_failures:
        print("-" * 72)
        print(f"  FAILURES ({len(failures)}):")
        for f in failures:
            print(f"    - {f['case_id']}: pack_hit={f['pack_hit']} source_hit={f['source_hit']} "
                  f"results={f['result_count']} top_packs={f['detail']['top_packs']}")
    print("=" * 72)
    passed_gate = m["pass_rate"] >= args.min_pass_rate
    print(f"  GATE: {'PASS' if passed_gate else 'FAIL'} "
          f"(pass_rate {m['pass_rate']*100:.2f}% vs required {args.min_pass_rate*100:.0f}%)")
    print("=" * 72)

    reports_dir = Path(config.DATA_DIR) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = reports_dir / f"retrieval_eval_{args.suite}_{ts}.json"
    latest = reports_dir / f"retrieval_eval_{args.suite}_latest.json"
    payload = json.dumps(run, indent=2)
    out.write_text(payload)
    latest.write_text(payload)
    print(f"\nJSON report:\n  {out}\n  {latest}")

    return 0 if passed_gate else 1


if __name__ == "__main__":
    raise SystemExit(main())
