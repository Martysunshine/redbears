"""Long-term memory API — project-scoped (the tenant-isolation boundary).

Every route resolves its project through ``project_context.workspace_for_path``:
operators address projects by the id in the URL, every other account is
redirected into its own workspace no matter what it asks for. A memory created
under project A is stored, embedded and retrieved only within project A — there
is no cross-project query path anywhere in this module.

The routes that act on a ``{memory_id}`` additionally re-check that the memory
actually belongs to the resolved project. Without that check, listing would be
correctly isolated while update/approve/reject/delete would not be: memory ids
are addressable independently of the project in the path, so an account could
mutate another's memory by id alone. As everywhere else in Oyster, a memory in
someone else's project answers 404, not 403 — a wrong owner and a non-existent
id must be indistinguishable.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from models.schemas import (ConflictResolveRequest, MemoryAddRequest, MemorySearchRequest,
                            MemorySettingsRequest, MemoryUpdateRequest)
from services import project_context, project_service
from services.auth_service import require_account
from services.user_memory import service as memory_service
from services.user_memory import store as memory_store

router = APIRouter(tags=["memory"])


def resolved_project(project_id: str, identity: dict = Depends(require_account)) -> str:
    """The project this caller may actually touch (FastAPI reads {project_id}
    from the path here, so route bodies keep using `project_id` unchanged)."""
    pid = project_context.workspace_for_path(identity, project_id)
    if project_service.get_project(pid) is None:
        raise HTTPException(status_code=404, detail=f"Project '{pid}' not found.")
    return pid


def _owned(memory_id: str, project_id: str) -> dict:
    """Fetch a memory that belongs to this project, or 404."""
    mem = memory_store.get_memory(memory_id)
    if mem is None or mem.get("project_id") != project_id:
        raise HTTPException(status_code=404, detail="Memory not found.")
    return mem


@router.get("/projects/{project_id}/memory")
async def list_memory(status: str = "active", type: str | None = None,
                      project_id: str = Depends(resolved_project)):
    statuses = status.split(",") if "," in status else status
    items = memory_service.list_memories(project_id, status=statuses, type_=type)
    return {"memories": items, "total": len(items)}


@router.get("/projects/{project_id}/memory/pending")
async def list_pending(project_id: str = Depends(resolved_project)):
    items = memory_service.list_pending(project_id)
    return {"pending": items, "total": len(items)}


@router.get("/projects/{project_id}/memory/conflicts")
async def list_conflicts(project_id: str = Depends(resolved_project)):
    groups = memory_service.list_conflicts(project_id)
    return {"conflicts": groups, "total": len(groups)}


@router.post("/projects/{project_id}/memory/conflicts/{conflict_group}/resolve")
async def resolve_conflict(conflict_group: str, request: ConflictResolveRequest,
                           project_id: str = Depends(resolved_project)):
    result = await memory_service.resolve_conflict(project_id, conflict_group, request.keep_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Conflict group or memory id not found.")
    return {"ok": True, "members": result}


@router.get("/projects/{project_id}/memory/stats")
async def memory_stats(project_id: str = Depends(resolved_project)):
    return {"project_id": project_id, "stats": memory_service.stats(project_id)}


@router.get("/projects/{project_id}/memory/export")
async def export_memory(project_id: str = Depends(resolved_project)):
    return memory_service.export_all(project_id)


@router.get("/projects/{project_id}/memory/settings")
async def get_memory_settings(project_id: str = Depends(resolved_project)):
    return memory_service.get_settings(project_id)


@router.put("/projects/{project_id}/memory/settings")
async def put_memory_settings(request: MemorySettingsRequest,
                              project_id: str = Depends(resolved_project)):
    return memory_service.set_settings(
        project_id, memory_enabled=request.memory_enabled, auto_save=request.auto_save,
        ask_before_saving=request.ask_before_saving,
    )


@router.post("/projects/{project_id}/memory/search")
async def search_memory(request: MemorySearchRequest,
                        project_id: str = Depends(resolved_project)):
    results = await memory_service.retrieve_relevant(project_id, request.query, top_k=request.top_k)
    return {"results": results, "total": len(results)}


@router.post("/projects/{project_id}/memory")
async def add_memory(request: MemoryAddRequest,
                     project_id: str = Depends(resolved_project)):
    if request.type not in ("fact", "preference", "decision", "instruction", "project_detail"):
        raise HTTPException(status_code=400, detail="Invalid memory type.")
    result = await memory_service.manual_add(project_id, request.type, request.subject,
                                             request.content, confidence=request.confidence)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.patch("/projects/{project_id}/memory/{memory_id}")
async def update_memory(memory_id: str, request: MemoryUpdateRequest,
                        project_id: str = Depends(resolved_project)):
    _owned(memory_id, project_id)
    result = await memory_service.update(memory_id, content=request.content,
                                         subject=request.subject, type_=request.type)
    if result is None:
        raise HTTPException(status_code=404, detail="Memory not found.")
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/projects/{project_id}/memory/{memory_id}/approve")
async def approve_memory(memory_id: str, project_id: str = Depends(resolved_project)):
    _owned(memory_id, project_id)
    result = memory_service.approve(memory_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Pending memory not found.")
    return {"ok": True, "memory": result}


@router.post("/projects/{project_id}/memory/{memory_id}/reject")
async def reject_memory(memory_id: str, project_id: str = Depends(resolved_project)):
    _owned(memory_id, project_id)
    result = memory_service.reject(memory_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Pending memory not found.")
    return {"ok": True, "memory": result}


@router.delete("/projects/{project_id}/memory/{memory_id}")
async def delete_memory(memory_id: str, project_id: str = Depends(resolved_project)):
    _owned(memory_id, project_id)
    ok = await memory_service.delete(memory_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Memory not found.")
    return {"ok": True, "memory_id": memory_id, "deleted": True}


@router.delete("/projects/{project_id}/memory")
async def delete_all_memory(project_id: str = Depends(resolved_project)):
    """'Delete all personal data' — hard-deletes every memory + its vector. Irreversible."""
    n = await memory_service.delete_all_personal_data(project_id)
    return {"ok": True, "project_id": project_id, "deleted": n}
