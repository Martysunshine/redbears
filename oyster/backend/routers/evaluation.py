"""Evaluation harness API (Phase 8).

Runs locally-authored retrieval-grounding suites against the installed Knowledge
Service and records the metrics. Also surfaces the dataset-governance gate:
training is globally disabled; registry datasets are eval-gated and never stored.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import log_config
from services.evaluation import datasets_gate, harness, security_harness, store

router = APIRouter(tags=["evaluation"])


class EvalRunRequest(BaseModel):
    suite_id: str
    top_k: int | None = None


class SecurityEvalRunRequest(BaseModel):
    suite_id: str = "security-intelligence-v1"
    model: str | None = None


@router.get("/evaluation/suites")
async def list_suites():
    return {"suites": harness.list_suites()}


@router.post("/evaluation/run")
async def run_eval(request: EvalRunRequest):
    try:
        run = await harness.run_suite(request.suite_id, top_k=request.top_k)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    log_config.audit("evaluation_run", {
        "suite_id": request.suite_id, "run_id": run["id"],
        "passed": run["passed"], "cases": run["case_count"],
        "pass_rate": run["metrics"].get("pass_rate"),
    })
    return run


@router.post("/evaluation/security/run")
async def run_security_eval(request: SecurityEvalRunRequest):
    """Runs the security-router/grounded-answer eval suite (Part 6): route
    accuracy, exact-identifier accuracy, non-fabrication on fake ids, citation
    resolution, prompt-injection safety, and structured-lookup latency."""
    try:
        run = await security_harness.run_suite(request.suite_id, model=request.model)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    log_config.audit("security_evaluation_run", {
        "suite_id": request.suite_id, "run_id": run["id"],
        "passed": run["passed"], "cases": run["case_count"],
        "metrics": run["metrics"],
    })
    return run


@router.get("/evaluation/runs")
async def list_runs(limit: int = 50):
    return {"runs": store.list_runs(limit)}


@router.get("/evaluation/runs/{run_id}")
async def get_run(run_id: str):
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="eval run not found")
    return run


@router.get("/evaluation/datasets")
async def dataset_governance():
    """Governance view of the datasets registry as it applies to evaluation."""
    from services.knowledge import registries
    items = registries.datasets().get("items", [])
    return {
        "training_disabled_globally": True,
        "note": "Datasets are scored against for evaluation only; content is never "
                "stored as retrievable knowledge and never used for training.",
        "datasets": [datasets_gate.evaluate_dataset(it.get("id")) for it in items],
    }


@router.post("/evaluation/datasets/{dataset_id}/check")
async def check_dataset(dataset_id: str):
    return datasets_gate.evaluate_dataset(dataset_id)
