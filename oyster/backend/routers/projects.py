"""Project System HTTP surface — the aggregate root for Oyster.

Everything a caller does happens *inside a project*. Local Alpha keeps this
backed by SQLite; the API here is stable so later slices (MCP resources, skills,
artifacts, workspace) can hang off ``project_id`` without changing shape.

**Every signed-in account** can create, rename, delete and switch between its
own private projects. Ownership is explicit (``projects.owner_id``): a caller
only ever sees or manages projects they own — admins additionally see the
shared "operator bucket" (the ``default`` engagement + legacy projects), but
never another account's workspace. This closed a real leak: the old
``list_projects`` returned every row to any operator, exposing every user's
private workspace and their email in its name.

**The active project is per-account** (``services/user_prefs``). Switching moves
only the caller. The single global ``is_active`` pointer still exists — the
admin-only shared surfaces (documents/rag/execution) read it — so an admin's
``activate`` writes BOTH pointers to keep those coherent; a user's ``activate``
writes only their own.

Handlers are plain ``def`` on purpose: synchronous SQLite work belongs in
FastAPI's threadpool, not on the event loop (see routers/user_findings.py).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

import log_config
from models.schemas import ProjectCreateRequest, ProjectScopeRequest, ProjectUpdateRequest
from services import project_context, project_service, user_prefs
from services.auth_service import require_account


router = APIRouter(tags=["projects"])


def _sub(identity: dict) -> str:
    return identity.get("sub") or identity.get("email") or ""


def _is_admin(identity: dict) -> bool:
    return identity.get("tier") == "admin"


def _not_found(project_id: str) -> HTTPException:
    # 404 (never 403) for a project the caller may not touch: a wrong-owner id
    # and a non-existent id must be indistinguishable, so ids can't be probed.
    return HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")


def resolved_project(project_id: str, identity: dict = Depends(require_account)) -> str:
    """The project this caller may actually READ from a path (owned → itself;
    otherwise their own active workspace). Used by scope/timeline reads."""
    return project_context.workspace_for_path(identity, project_id)


@router.get("/projects")
def list_projects(identity: dict = Depends(require_account)):
    projects = project_service.list_projects_for(identity)
    return {
        "projects": projects,
        "total": len(projects),
        "active_id": project_context.workspace_id(identity),
    }


@router.post("/projects")
def create_project(request: ProjectCreateRequest,
                   identity: dict = Depends(require_account)):
    sub = _sub(identity)
    # A user's project must never flip the global operator pointer; an admin's
    # keeps today's behaviour (activate the global pointer too).
    project = project_service.create_project(
        name=request.name,
        description=request.description,
        scope=request.scope,
        activate=bool(request.activate) and _is_admin(identity),
        owner_id=sub,
    )
    # Land the creator in their new project (per-account pointer, all tiers).
    user_prefs.set_active_project_id(sub, project["id"])
    log_config.audit("project_created",
                     {"project_id": project["id"], "name": request.name, "owner": sub})
    return {"status": "ok", "project": project}


@router.get("/projects/active")
def get_active_project(identity: dict = Depends(require_account)):
    # Resolving provisions the home workspace on first call, so a new account
    # always has a project to land in rather than a 404.
    project = project_service.get_project(project_context.workspace_id(identity))
    if project is None:
        raise HTTPException(status_code=404, detail="No active project.")
    return {"project": project}


@router.get("/projects/{project_id}")
def get_project(project_id: str, identity: dict = Depends(require_account)):
    if not project_service.is_visible_to(identity, project_id):
        raise _not_found(project_id)
    project = project_service.get_project(project_id)
    if project is None:
        raise _not_found(project_id)
    return {"project": project}


@router.patch("/projects/{project_id}")
def update_project(project_id: str, request: ProjectUpdateRequest,
                   identity: dict = Depends(require_account)):
    if not project_service.can_manage(identity, project_id):
        raise _not_found(project_id)
    project = project_service.update_project(
        project_id, name=request.name, description=request.description, status=request.status
    )
    if project is None:
        raise _not_found(project_id)
    return {"status": "ok", "project": project}


@router.delete("/projects/{project_id}")
def delete_project(project_id: str, identity: dict = Depends(require_account)):
    if not project_service.can_manage(identity, project_id):
        raise _not_found(project_id)
    try:
        deleted = project_service.delete_project(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not deleted:
        raise _not_found(project_id)
    # If this was the caller's active project, drop the pointer so they fall
    # back to their home workspace rather than a dangling id.
    if user_prefs.get_active_project_id(_sub(identity)) == project_id:
        user_prefs.clear_active_project(_sub(identity))
    log_config.audit("project_deleted", {"project_id": project_id, "by": _sub(identity)})
    return {"status": "ok", "deleted": project_id}


@router.post("/projects/{project_id}/activate")
def activate_project(project_id: str, identity: dict = Depends(require_account)):
    if not project_service.is_visible_to(identity, project_id):
        raise _not_found(project_id)
    # Per-account pointer for everyone; admins ALSO flip the global pointer so
    # the shared operator surfaces (documents/rag/execution) stay coherent with
    # what the admin picked.
    user_prefs.set_active_project_id(_sub(identity), project_id)
    if _is_admin(identity):
        project_service.set_active_project(project_id)
    project = project_service.get_project(project_id)
    if project is None:
        raise _not_found(project_id)
    log_config.audit("project_activated", {"project_id": project_id, "by": _sub(identity)})
    return {"status": "ok", "project": project}


@router.put("/projects/{project_id}/scope")
def set_project_scope(request: ProjectScopeRequest,
                      project_id: str = Depends(resolved_project)):
    project = project_service.set_scope(project_id, request.scope)
    if project is None:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    return {"status": "ok", "project": project}


@router.get("/projects/{project_id}/timeline")
def get_timeline(limit: int = 100, project_id: str = Depends(resolved_project)):
    if project_service.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    events = project_service.get_timeline(project_id, limit=limit)
    return {"project_id": project_id, "events": events, "total": len(events)}
