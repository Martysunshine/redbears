"""HTTP surface for the Execution Engine.

Every route is project-scoped: the active project is used unless a body carries
an explicit ``project_id``, and cross-project access is refused inside the
service layer (a proposal/execution/evidence id from another project 404s).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

import config
from models.schemas import (
    ApprovalRequest,
    CleanupRequest,
    EvidenceCreateRequest,
    FindingCreateRequest,
    ProposalCreateRequest,
    RejectRequest,
    ToolEnableRequest,
)
from services import project_service
from services.execution import service as ex_service
from services.execution import store, tool_registry


def require_execution_enabled() -> None:
    """Kill-switch for the whole Execution Engine (config.EXECUTION_ENGINE_ENABLED).

    Recommended off for a public deployment: it's the boundary that lets a
    logged-in user make this server actually probe network targets. Flip
    OYSTER_EXECUTION_ENGINE_ENABLED=true once you're ready to operate it
    deliberately.
    """
    if not config.EXECUTION_ENGINE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Execution engine is disabled in this environment.",
        )


router = APIRouter(tags=["execution"], dependencies=[Depends(require_execution_enabled)])


def _pid(explicit: str | None = None) -> str:
    return explicit or project_service.get_active_project_id()


# ---- Tools ---------------------------------------------------------------

@router.get("/execution/tools")
async def list_tools():
    pid = _pid()
    tools = tool_registry.describe()
    for t in tools:
        t["enabled"] = store.is_tool_enabled(pid, t["id"])
    return {"tools": tools, "project_id": pid}


@router.get("/execution/tools/{tool_id}")
async def get_tool(tool_id: str):
    prof = tool_registry.get_profile(tool_id)
    if not prof:
        raise HTTPException(404, f"Unknown tool '{tool_id}'.")
    data = next((t for t in tool_registry.describe() if t["id"] == tool_id), None)
    data["enabled"] = store.is_tool_enabled(_pid(), tool_id)
    return data


@router.post("/execution/tools/{tool_id}/enabled")
async def set_tool_enabled(tool_id: str, req: ToolEnableRequest):
    if not tool_registry.get_profile(tool_id):
        raise HTTPException(404, f"Unknown tool '{tool_id}'.")
    pid = _pid()
    store.set_tool_enabled(pid, tool_id, req.enabled)
    store.audit(pid, "tool_enabled_changed", detail={"tool": tool_id, "enabled": req.enabled})
    return {"ok": True, "tool_id": tool_id, "enabled": req.enabled}


# ---- Proposals -----------------------------------------------------------

@router.post("/execution/proposals")
async def create_proposal(req: ProposalCreateRequest):
    result = ex_service.create_proposal(
        tool_id=req.tool_id, action_id=req.action_id, targets=req.targets,
        parameters=req.parameters, objective=req.objective,
        conversation_id=req.conversation_id, project_id=req.project_id,
    )
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "Could not create proposal."))
    return result


@router.get("/execution/proposals")
async def list_proposals(project_id: str | None = None):
    pid = _pid(project_id)
    return {"proposals": store.list_proposals(pid), "project_id": pid}


@router.get("/execution/proposals/{proposal_id}")
async def get_proposal(proposal_id: str, project_id: str | None = None):
    res = ex_service.validate_proposal(proposal_id, project_id=project_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("error", "Not found."))
    return res


@router.post("/execution/proposals/{proposal_id}/validate")
async def validate_proposal(proposal_id: str, project_id: str | None = None):
    res = ex_service.validate_proposal(proposal_id, project_id=project_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("error", "Not found."))
    return res


@router.post("/execution/proposals/{proposal_id}/approve")
async def approve_proposal(proposal_id: str, req: ApprovalRequest):
    res = ex_service.approve_proposal(proposal_id, approved_by=req.approved_by, note=req.note)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "Approval failed."))
    return res


@router.post("/execution/proposals/{proposal_id}/reject")
async def reject_proposal(proposal_id: str, req: RejectRequest):
    res = ex_service.reject_proposal(proposal_id, note=req.note)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "Reject failed."))
    return res


@router.post("/execution/proposals/{proposal_id}/execute")
async def execute_proposal(proposal_id: str):
    res = await ex_service.start_execution(proposal_id)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "Execution refused."))
    return res


# ---- Executions ----------------------------------------------------------

@router.get("/execution/executions")
async def list_executions(project_id: str | None = None):
    pid = _pid(project_id)
    return {"executions": store.list_executions(pid), "project_id": pid}


@router.get("/execution/executions/{execution_id}")
async def get_execution(execution_id: str, project_id: str | None = None):
    view = ex_service.execution_view(execution_id, project_id=project_id)
    if view is None:
        raise HTTPException(404, "Execution not found in this project.")
    return view


@router.post("/execution/executions/{execution_id}/cancel")
async def cancel_execution(execution_id: str):
    res = ex_service.cancel_execution(execution_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("error", "Not found."))
    return res


@router.post("/execution/executions/{execution_id}/cleanup")
async def record_cleanup(execution_id: str, req: CleanupRequest):
    res = ex_service.record_cleanup(execution_id, detail=req.detail)
    if not res.get("ok"):
        raise HTTPException(404, res.get("error", "Not found."))
    return res


@router.post("/execution/executions/{execution_id}/evidence")
async def create_evidence(execution_id: str, req: EvidenceCreateRequest):
    res = ex_service.create_evidence(execution_id, req.title, req.observation)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "Could not create evidence."))
    return res


# ---- Evidence + findings -------------------------------------------------

@router.get("/execution/evidence")
async def list_evidence(project_id: str | None = None):
    pid = _pid(project_id)
    return {"evidence": store.list_evidence(pid), "project_id": pid}


@router.get("/execution/findings")
async def list_findings(project_id: str | None = None):
    pid = _pid(project_id)
    return {"findings": store.list_findings(pid), "project_id": pid}


@router.post("/execution/findings")
async def create_finding(req: FindingCreateRequest):
    res = ex_service.create_finding(req.title, req.severity, req.summary, req.evidence_ids,
                                    recommendation=req.recommendation)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error", "Could not create finding."))
    return res


# ---- Audit ---------------------------------------------------------------

@router.get("/execution/audit")
async def list_audit(project_id: str | None = None, limit: int = 200):
    pid = _pid(project_id)
    return {"audit": store.list_audit(pid, limit=limit), "project_id": pid}
