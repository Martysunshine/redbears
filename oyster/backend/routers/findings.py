from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

import log_config
from models.schemas import EvidenceLogRequest, FindingsReportRequest
from prompt_utils import load_prompt
from services import evidence_service, ollama_service, scope_service

router = APIRouter(tags=["findings"])


@router.post("/findings/report")
async def findings_report(request: FindingsReportRequest):
    if not scope_service.is_scope_active():
        raise HTTPException(
            status_code=403,
            detail="No active engagement scope. Set scope via POST /scope/set first.",
        )

    scope = scope_service.load_scope()
    log_config.audit(
        "report_generated",
        {"engagement_name": request.engagement_name, "finding_count": len(request.findings)},
    )

    report_prompt_text = load_prompt("report_prompt.txt")
    findings_json = json.dumps(request.findings, indent=2)

    prompt = (
        f"{report_prompt_text}\n\n"
        f"ENGAGEMENT: {request.engagement_name}\n"
        f"AUTHORIZED BY: {scope.get('authorized_by', 'N/A')}\n"
        f"DATE RANGE: {scope.get('start_date', 'N/A')} to {scope.get('end_date', 'N/A')}\n\n"
        f"FINDINGS INPUT:\n{findings_json}\n\n"
        f"Generate the full professional penetration testing report."
    )

    report = await ollama_service.generate(prompt, request.model)

    return {
        "engagement_name": request.engagement_name,
        "report": report,
        "finding_count": len(request.findings),
        "model": request.model,
    }


@router.post("/redteam/evidence")
async def log_evidence(request: EvidenceLogRequest):
    entry = evidence_service.log_finding(request.model_dump())
    log_config.audit(
        "evidence_logged",
        {"severity": request.severity, "title": request.title, "endpoint": request.endpoint},
    )
    return {"status": "ok", "finding": entry}


@router.get("/redteam/evidence")
async def get_evidence():
    findings = evidence_service.list_findings()
    return {"findings": findings, "total": len(findings)}


@router.delete("/redteam/evidence/{finding_id}")
async def delete_evidence(finding_id: str):
    deleted = evidence_service.delete_finding(finding_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return {"status": "ok", "deleted": finding_id}
