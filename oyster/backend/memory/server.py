from __future__ import annotations

from fastapi import APIRouter, Query
from pydantic import BaseModel

from . import service, store

router = APIRouter(tags=["memory"])


class StoreMemoryRequest(BaseModel):
    type: str = "note"
    key: str
    value: str
    tags: list[str] = []
    session_id: str | None = None


class StoreScanRequest(BaseModel):
    target: str
    tool: str
    result: dict
    session_id: str | None = None


class AttackSurfaceRequest(BaseModel):
    target: str
    component_type: str
    detail: str
    severity: str = "info"
    session_id: str | None = None


@router.post("/store")
async def store_memory(request: StoreMemoryRequest) -> dict:
    return store.store_memory(
        request.type, request.key, request.value, request.tags, request.session_id
    )


@router.get("/recall")
async def recall_memories(
    query: str | None = Query(default=None),
    type: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict:
    results = service.recall(query=query, type=type, session_id=session_id, limit=limit)
    return {"memories": results, "total": len(results)}


@router.post("/scan")
async def store_scan(request: StoreScanRequest) -> dict:
    return service.log_scan(request.target, request.tool, request.result, request.session_id)


@router.get("/scan-history/{target}")
async def scan_history(target: str, limit: int = Query(default=10, ge=1, le=50)) -> dict:
    results = service.get_scan_history(target, limit)
    return {"target": target, "scans": results, "total": len(results)}


@router.post("/attack-surface")
async def add_attack_surface(request: AttackSurfaceRequest) -> dict:
    return service.add_to_attack_surface(
        request.target, request.component_type, request.detail,
        request.severity, request.session_id,
    )


@router.get("/attack-surface")
async def get_attack_surface(target: str | None = Query(default=None)) -> dict:
    results = service.get_attack_surface(target)
    return {"attack_surface": results, "total": len(results)}


@router.delete("/session/{session_id}")
async def clear_session(session_id: str) -> dict:
    deleted = service.clear_session(session_id)
    return {"session_id": session_id, "deleted_entries": deleted}


@router.get("/context")
async def get_context(target: str | None = Query(default=None)) -> dict:
    summary = service.summarize_context(target)
    return {"target": target, "summary": summary, "stats": service.stats()}


@router.get("/stats")
async def get_stats() -> dict:
    return service.stats()
