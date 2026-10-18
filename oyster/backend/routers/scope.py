"""Engagement scope — per account.

Scope used to be one global file, which was correct when the only callers were
the two operators sharing a workspace. Now every signed-in account has the
red-team surface, so each account's scope lives in its OWN project and one
account can neither read nor overwrite another's.

Operators are unchanged: their resolved project IS the globally active one, and
``project_service.set_scope`` still mirrors it to the legacy global file, so
every existing scope-gated code path keeps reading exactly what it did before.
Non-operators never touch that file.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

import log_config
from models.schemas import ScopeSetRequest
from services import project_context, project_service, scope_service
from services.auth_service import require_account

router = APIRouter(tags=["scope"])


@router.post("/scope/set")
async def set_scope(request: ScopeSetRequest, identity: dict = Depends(require_account)):
    data = request.model_dump()
    # Derive engagement_name from project when using new format
    if not data.get("engagement_name") and data.get("project"):
        data["engagement_name"] = data["project"]

    project_id = project_context.workspace_id(identity)
    # For an operator this writes through to the global scope file via
    # project_service's active-project bridge. For a user it does not: their
    # project is never the active one, so the operators' file stays untouched.
    project_service.set_scope(project_id, data)

    name = data.get("project") or data.get("engagement_name", "unknown")
    log_config.audit(
        "scope_set",
        {
            "engagement_name": name,
            "authorized_by": data.get("authorized_by", "local-user"),
            "project_id": project_id,
        },
    )
    return {
        "status": "ok",
        "scope": data,
        "project_id": project_id,
        "message": f"Scope set for: {name}",
    }


@router.get("/scope")
async def get_scope(identity: dict = Depends(require_account)):
    project_id = project_context.workspace_id(identity)
    project = project_service.get_project(project_id) or {}
    scope = project.get("scope") or {}
    return {
        "scope": scope,
        "active": scope_service.is_scope_active(scope),
        "project_id": project_id,
    }
