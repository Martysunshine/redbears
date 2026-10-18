"""Aggregated settings — one endpoint for the Settings panel.

Each toggle is backed by exactly one source of truth (no duplicated state):
memory_enabled / auto_save / ask_before_saving live in
``services.user_memory.store`` (project-scoped); allow_training_data lives in
``services.training.consent`` (project-scoped, off by default). This router
only aggregates reads/writes — it owns no state of its own.

Open to every signed-in account. The ``{project_id}`` in the path is
authoritative only for operators: ``project_context.workspace_for_path``
redirects everyone else into their own workspace, so asking for another
account's project settings silently returns your own rather than theirs.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services import project_context, project_service
from services.auth_service import require_account
from services.training import service as training_service
from services.user_memory import service as memory_service

router = APIRouter(tags=["settings"])


class SettingsUpdateRequest(BaseModel):
    memory_enabled: bool | None = None
    auto_save: bool | None = None
    ask_before_saving: bool | None = None
    allow_training_data: bool | None = None


def _resolve(identity: dict, project_id: str) -> str:
    """The project this caller may actually configure."""
    pid = project_context.workspace_for_path(identity, project_id)
    if project_service.get_project(pid) is None:
        raise HTTPException(status_code=404, detail=f"Project '{pid}' not found.")
    return pid


def _aggregate(project_id: str) -> dict:
    mem = memory_service.get_settings(project_id)
    return {
        "project_id": project_id,
        "memory_enabled": mem["memory_enabled"],
        "auto_save": mem["auto_save"],
        "ask_before_saving": mem["ask_before_saving"],
        "allow_training_data": training_service.get_consent(project_id),
    }


@router.get("/projects/{project_id}/settings")
async def get_settings(project_id: str, identity: dict = Depends(require_account)):
    return _aggregate(_resolve(identity, project_id))


@router.patch("/projects/{project_id}/settings")
async def update_settings(project_id: str, request: SettingsUpdateRequest,
                          identity: dict = Depends(require_account)):
    project_id = _resolve(identity, project_id)
    if any(v is not None for v in (request.memory_enabled, request.auto_save, request.ask_before_saving)):
        memory_service.set_settings(
            project_id, memory_enabled=request.memory_enabled, auto_save=request.auto_save,
            ask_before_saving=request.ask_before_saving,
        )
    if request.allow_training_data is not None:
        training_service.set_consent(project_id, request.allow_training_data)
    return _aggregate(project_id)


@router.delete("/projects/{project_id}/settings/personal-data")
async def delete_all_personal_data(project_id: str,
                                   identity: dict = Depends(require_account)):
    """'Delete all personal data' — the nuclear option. Hard-deletes every
    long-term memory + its vector for this project. Does not touch project
    artifacts/documents or conversation history (deleted separately) or
    already-trained adapters (those are model weights, not personal data
    records — revoke consent and delete the project's training datasets/
    adapters separately if desired)."""
    project_id = _resolve(identity, project_id)
    n = await memory_service.delete_all_personal_data(project_id)
    return {"ok": True, "project_id": project_id, "memories_deleted": n}
