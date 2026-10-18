"""Dataset RAG API — approved, licence-gated cybersecurity Q&A/instruction
datasets, searchable/askable through their own clearly-labeled surface.

Kept structurally separate from ``/knowledge/*`` (curated Knowledge Packs):
different Chroma collection, different governance gate, different citation
shape. Nothing here is ever used for training (see ``services/training/``,
which never reads this registry)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from models.schemas import DatasetAskRequest, DatasetSearchRequest, ToolEnableRequest
from services.knowledge.datasets import service as dataset_service

router = APIRouter(tags=["datasets"])


@router.get("/datasets")
async def list_datasets():
    items = dataset_service.list_with_status()
    return {
        "datasets": items, "total": len(items),
        "installed": sum(1 for d in items if d["installed"]),
        "rag_eligible": sum(1 for d in items if d["allowed"]),
    }


@router.get("/datasets/{dataset_id}")
async def get_dataset(dataset_id: str):
    items = dataset_service.list_with_status()
    for d in items:
        if d["dataset_id"] == dataset_id:
            return d
    raise HTTPException(status_code=404, detail=f"Unknown dataset '{dataset_id}'")


@router.post("/datasets/{dataset_id}/preview")
async def preview_dataset(dataset_id: str):
    return await dataset_service.preview(dataset_id)


@router.post("/datasets/{dataset_id}/install")
async def install_dataset(dataset_id: str):
    result = await dataset_service.install(dataset_id)
    if not result.get("ok") and not result.get("blocked"):
        raise HTTPException(status_code=400, detail=result.get("error", "Install failed"))
    return result


@router.delete("/datasets/{dataset_id}")
async def uninstall_dataset(dataset_id: str):
    ok = await dataset_service.uninstall(dataset_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Dataset not installed")
    return {"ok": True, "dataset_id": dataset_id, "uninstalled": True}


@router.post("/datasets/{dataset_id}/enabled")
async def set_dataset_enabled(dataset_id: str, request: ToolEnableRequest):
    ok = dataset_service.set_enabled(dataset_id, request.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Dataset not installed")
    return {"ok": True, "dataset_id": dataset_id, "enabled": request.enabled}


@router.get("/datasets/{dataset_id}/jobs")
async def dataset_jobs(dataset_id: str):
    return {"dataset_id": dataset_id, "jobs": dataset_service.import_jobs(dataset_id)}


@router.post("/datasets/search")
async def search_datasets(request: DatasetSearchRequest):
    results = await dataset_service.search(request.query, top_k=request.top_k,
                                           dataset_ids=request.dataset_ids)
    return {"results": results, "total": len(results), "query": request.query}


@router.post("/datasets/ask")
async def ask_datasets(request: DatasetAskRequest):
    return await dataset_service.ask(request.question, model=request.model,
                                     top_k=request.top_k, dataset_ids=request.dataset_ids)


@router.get("/datasets/citation/{chunk_id:path}")
async def resolve_dataset_citation(chunk_id: str):
    payload = dataset_service.resolve_citation(chunk_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Citation not found")
    return payload
