"""Findings HTTP surface — a user's own saved chat messages.

Reachable by any signed-in account; anonymous is refused (require_account).
Every single-finding route re-checks ownership and returns 404 (never 403) for
someone else's row, so ids can't be probed — the same model conversations use.

Distinct from ``routers/findings.py`` (admin-only, instance-global pentest
evidence). No path collides: that router owns ``/findings/report`` and
``/redteam/evidence``; this one owns ``/findings`` collection + ``/findings/{id}``.

Handlers here are deliberately plain ``def``, not ``async def``. Every one of
them does synchronous SQLite work and awaits nothing; declaring them ``async``
would run that work directly on the event loop, so one slow write would stall
every other request in flight — including someone else's chat stream. As plain
``def`` FastAPI runs them in its threadpool, where blocking is harmless.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

import log_config
from models.schemas import UserFindingCreateRequest, UserFindingUpdateRequest
from services import project_context, user_findings_service
from services.auth_service import require_account

router = APIRouter(tags=["findings"])


def _sub(identity: dict) -> str:
    return identity.get("sub") or identity.get("email") or ""


def _not_found(finding_id: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")


@router.get("/findings")
def list_findings(project_id: str | None = None, in_report: bool | None = None,
                  identity: dict = Depends(require_account)):
    findings = user_findings_service.list_by(_sub(identity), project_id, in_report)
    return {"findings": findings, "total": len(findings)}


@router.get("/findings/report/export", response_class=PlainTextResponse)
def export_report(identity: dict = Depends(require_account)):
    """Export the caller's curated findings as a readable Markdown report.

    The active project is resolved from the authenticated identity; callers
    cannot choose another project through a query parameter. Share tokens and
    internal ownership fields are deliberately omitted from the export.
    """
    project_id = project_context.workspace_id(identity)
    findings = user_findings_service.list_by(_sub(identity), project_id, True)
    return user_findings_service.format_report(findings, project_id)


# NOTE: declared BEFORE /findings/{finding_id} — FastAPI matches in order, so
# the literal path must win over the parameterised one.
@router.get("/findings/public")
def list_public_findings(limit: int = 100, offset: int = 0,
                         identity: dict = Depends(require_account)):
    """The community feed — every finding anyone chose to publish.

    Signed-in only (a product decision): individual share LINKS remain open to
    anyone, but the browsable index is not. Rows carry a public handle, never
    an email, and no project/conversation/owner ids.
    """
    findings, total = user_findings_service.list_public(_sub(identity), limit=limit, offset=offset)
    return {"findings": findings, "total": total}


@router.post("/findings")
def create_finding(request: UserFindingCreateRequest,
                   identity: dict = Depends(require_account)):
    if not (request.content or "").strip():
        raise HTTPException(status_code=400, detail="A finding needs content to save.")
    finding = user_findings_service.create(
        _sub(identity),
        project_context.workspace_id(identity),
        request.content,
        title=request.title,
        conversation_id=request.conversation_id,
        conv_mode=request.conv_mode,
        message_id=request.message_id,
        citations=request.citations,
        in_report=request.in_report,
        severity=request.severity,
        endpoint=request.endpoint,
        method=request.method,
        notes=request.notes,
        recommended_fix=request.recommended_fix,
        affected_asset=request.affected_asset,
        unresolved_questions=request.unresolved_questions,
    )
    log_config.audit("finding_created", {"finding_id": finding["id"], "by": _sub(identity)})
    return {"status": "ok", "finding": finding}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, identity: dict = Depends(require_account)):
    if not user_findings_service.can_access(finding_id, _sub(identity)):
        raise _not_found(finding_id)
    finding = user_findings_service.get(finding_id)
    if finding is None:
        raise _not_found(finding_id)
    return {"finding": finding}


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: str, request: UserFindingUpdateRequest,
                   identity: dict = Depends(require_account)):
    if not user_findings_service.can_access(finding_id, _sub(identity)):
        raise _not_found(finding_id)
    finding = user_findings_service.update(
        finding_id, title=request.title, content=request.content,
        in_report=request.in_report, severity=request.severity,
        endpoint=request.endpoint, method=request.method,
        notes=request.notes, recommended_fix=request.recommended_fix,
        affected_asset=request.affected_asset,
        unresolved_questions=request.unresolved_questions,
    )
    if finding is None:
        raise HTTPException(status_code=400, detail="Nothing to update, or the title was empty.")
    return {"status": "ok", "finding": finding}


@router.delete("/findings/{finding_id}")
def delete_finding(finding_id: str, identity: dict = Depends(require_account)):
    if not user_findings_service.can_access(finding_id, _sub(identity)):
        raise _not_found(finding_id)
    if not user_findings_service.delete(finding_id):
        raise _not_found(finding_id)
    return {"status": "ok", "deleted": finding_id}


@router.post("/findings/{finding_id}/share")
def share_finding(finding_id: str, identity: dict = Depends(require_account)):
    if not user_findings_service.can_access(finding_id, _sub(identity)):
        raise _not_found(finding_id)
    token = user_findings_service.set_share(finding_id)
    if token is None:
        raise _not_found(finding_id)
    log_config.audit("finding_shared", {"finding_id": finding_id, "by": _sub(identity)})
    # The bare token only — the frontend builds the deploy-correct public URL
    # (basePath-aware) around it, so the backend stays host-agnostic.
    return {"status": "ok", "token": token}


@router.delete("/findings/{finding_id}/share")
def unshare_finding(finding_id: str, identity: dict = Depends(require_account)):
    if not user_findings_service.can_access(finding_id, _sub(identity)):
        raise _not_found(finding_id)
    user_findings_service.revoke_share(finding_id)
    log_config.audit("finding_unshared", {"finding_id": finding_id, "by": _sub(identity)})
    return {"status": "ok", "revoked": finding_id}
