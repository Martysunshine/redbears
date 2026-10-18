"""Red-team planning — per account.

Two things make this router safe to open beyond the operator allow-list:

  * **Scope is the caller's own.** Every check reads the scope stored on the
    project ``project_context`` resolved from the caller's identity, not the
    shared global scope file. One account cannot authorise itself against
    another's targets, or see what those targets are.
  * **Retrieval is the caller's own.** The citation searches below are
    project-scoped. Left unscoped they search the global document collection,
    which holds the operators' uploaded engagement material (rules of
    engagement, client source, findings) — a stranger's plan would quote it
    back at them.

Operators are unchanged: their resolved project is the active one, whose scope
is mirrored to the legacy file, and passing that project id to the retrieval
call matches what their documents are already tagged with.

This router generates GUIDANCE only. Real tool execution stays behind the
Execution Engine's separate scope/approval/audit gate.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

import config
import log_config
from models.schemas import CodeReviewRequest, FixRequest, ReconRequest, RedTeamPlanRequest
from models.schemas import Citation
from prompt_utils import disclaimer_instruction, load_prompt
from services import ollama_service, project_context, project_service, rag_service, scope_service
from services.auth_service import require_account

router = APIRouter(tags=["redteam"])


def _footer() -> str:
    """Operator-responsibility disclaimer instruction (blank when disabled)."""
    f = disclaimer_instruction()
    return f"\n\n{f}" if f else ""


def _workspace(identity: dict) -> tuple[str, dict]:
    """The caller's project id and its engagement scope."""
    project_id = project_context.workspace_id(identity)
    project = project_service.get_project(project_id) or {}
    return project_id, (project.get("scope") or {})


@router.post("/redteam/plan")
async def redteam_plan(request: RedTeamPlanRequest, identity: dict = Depends(require_account)):
    project_id, scope = _workspace(identity)

    authorized, reason = scope_service.validate_target(request.target, scope)
    if not authorized:
        log_config.audit("scope_violation",
                         {"target": request.target, "reason": reason, "project_id": project_id})
        raise HTTPException(status_code=403, detail=reason)

    log_config.audit(
        "redteam_plan",
        {"target": request.target, "objective": request.objective[:200], "project_id": project_id},
    )

    system_prompt = load_prompt("redteam_system_prompt.txt")

    citations_raw = await rag_service.search_async(
        f"{request.target} {request.objective}", top_k=4, project_id=project_id
    )
    context_section = ""
    if citations_raw:
        parts = [
            f"[{i}] From '{c['document']}':\n{c['chunk']}"
            for i, c in enumerate(citations_raw, 1)
        ]
        context_section = "\nKNOWLEDGE BASE CONTEXT:\n" + "\n\n".join(parts) + "\n"

    prompt = (
        f"{system_prompt}\n\n"
        f"ENGAGEMENT SCOPE:\n"
        f"  Name: {scope.get('engagement_name', 'N/A')}\n"
        f"  Authorized by: {scope.get('authorized_by', 'N/A')}\n"
        f"  Target: {request.target}\n"
        f"  Authorized domains: {', '.join(scope.get('domains', [])) or 'see scope file'}\n"
        f"  Authorized IPs: {', '.join(scope.get('ip_ranges', [])) or 'see scope file'}\n"
        f"{context_section}\n"
        f"OBJECTIVE: {request.objective}\n"
        f"METHODOLOGY: {request.methodology or 'PTES / OWASP Testing Guide'}\n\n"
        f"Generate a professional penetration test plan for the above target. "
        f"Include: attack surface overview, test phases, structured checklist, risk areas, "
        f"evidence collection guidance, and safe lab-level PoC descriptions where appropriate."
        f"{_footer()}"
    )

    answer = await ollama_service.generate(prompt, request.model)

    return {
        "target": request.target,
        "in_scope": True,
        "scope_reason": reason,
        "plan": answer,
        "citations": [Citation(**c) for c in citations_raw],
        "model": request.model,
    }


@router.post("/code/review")
async def code_review(request: CodeReviewRequest, identity: dict = Depends(require_account)):
    project_id, scope = _workspace(identity)

    authorized, reason = scope_service.validate_target(request.target_repo, scope)
    if not authorized:
        log_config.audit("scope_violation",
                         {"target": request.target_repo, "reason": reason, "project_id": project_id})
        raise HTTPException(status_code=403, detail=reason)

    log_config.audit(
        "code_review",
        {"target": request.target_repo, "language": request.language,
         "focus": request.focus, "project_id": project_id},
    )

    review_prompt = load_prompt("code_review_prompt.txt")

    code_section = ""
    if request.code_snippet:
        lang = request.language or "text"
        code_section = f"\nCODE TO REVIEW ({lang}):\n```{lang}\n{request.code_snippet}\n```\n"

    focus_section = f"\nFOCUS AREAS: {request.focus}\n" if request.focus else ""

    citations_raw = await rag_service.search_async(
        f"security {request.language} {request.focus} vulnerability {request.target_repo}",
        top_k=3,
        project_id=project_id,
    )
    context_section = ""
    if citations_raw:
        parts = [
            f"[{i}] From '{c['document']}':\n{c['chunk']}"
            for i, c in enumerate(citations_raw, 1)
        ]
        context_section = "\nKNOWLEDGE BASE CONTEXT:\n" + "\n\n".join(parts) + "\n"

    prompt = (
        f"{review_prompt}\n\n"
        f"REPOSITORY: {request.target_repo}\n"
        f"{code_section}"
        f"{focus_section}"
        f"{context_section}\n"
        f"Perform a thorough security review."
        f"{_footer()}"
    )

    answer = await ollama_service.generate(prompt, request.model)

    return {
        "target_repo": request.target_repo,
        "in_scope": True,
        "review": answer,
        "citations": [Citation(**c) for c in citations_raw],
        "model": request.model,
    }


@router.post("/redteam/recon")
async def redteam_recon(request: ReconRequest, identity: dict = Depends(require_account)):
    project_id, scope = _workspace(identity)

    if not scope_service.is_scope_active(scope):
        raise HTTPException(
            status_code=403,
            detail="No active scope. Set scope first via POST /scope/set.",
        )

    authorized, reason = scope_service.validate_target(request.target, scope)
    if not authorized:
        log_config.audit("scope_violation",
                         {"target": request.target, "reason": reason, "project_id": project_id})
        raise HTTPException(status_code=403, detail=reason)

    log_config.audit("recon", {"target": request.target, "project_id": project_id})

    recon_prompt_text = load_prompt("recon_prompt.txt")
    allowed_tests = ", ".join(scope.get("allowed_tests", [])) or "all authorized test types"

    prompt = (
        f"{recon_prompt_text}\n\n"
        f"PROJECT: {scope.get('project') or scope.get('engagement_name', 'N/A')}\n"
        f"TARGET: {request.target}\n"
        f"AUTHORIZED TESTS: {allowed_tests}\n"
        + (f"DESCRIPTION: {request.description}\n" if request.description else "")
        + "\nGenerate a comprehensive attack surface map for this target."
        + _footer()
    )

    ollama_model = config.resolve_model(request.model)
    result = await ollama_service.generate(prompt, ollama_model)

    return {"target": request.target, "recon": result, "model": request.model}


@router.post("/redteam/fix")
async def redteam_fix(request: FixRequest, identity: dict = Depends(require_account)):
    # Remediation advice is not target-bound (it describes a fix for a
    # vulnerability the caller already has), so there is no scope check here —
    # unchanged from before. The account gate still applies.
    fix_prompt_text = load_prompt("fix_prompt.txt")

    prompt = (
        f"{fix_prompt_text}\n\n"
        f"VULNERABILITY: {request.title}\n"
        f"AFFECTED ENDPOINT: {request.endpoint}\n"
        f"STACK: {request.stack or 'FastAPI + Next.js (Oyster)'}\n"
        f"DESCRIPTION:\n{request.description}\n"
        + (f"\nSTEPS TO REPRODUCE:\n{request.steps}\n" if request.steps else "")
        + "\nProvide the full remediation analysis following the format in your instructions."
        + _footer()
    )

    ollama_model = config.resolve_model(request.model)
    advice = await ollama_service.generate(prompt, ollama_model)

    return {"title": request.title, "endpoint": request.endpoint, "advice": advice, "model": request.model}
