"""
Analyst playbook endpoints.

GET  /playbooks/templates                                        — list all built-in templates
GET  /playbooks/templates/{template_id}                          — template detail with steps
POST /cases/{case_id}/playbooks                                  — attach a template to a case
GET  /cases/{case_id}/playbooks                                  — list case playbooks + suggestions
GET  /cases/{case_id}/playbooks/{playbook_id}                    — single case playbook
PATCH /cases/{case_id}/playbooks/{playbook_id}/steps/{step_id}  — update step status/notes
"""

import json
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.case_playbook import CasePlaybook
from socmat.services.api.models.case_playbook_step import CasePlaybookStep
from socmat.services.api.models.playbook_template import PlaybookTemplate
from socmat.services.api.schemas.playbook_schema import (
    AttachPlaybookRequest,
    CasePlaybookResponse,
    CasePlaybooksListResponse,
    PlaybookStepResponse,
    PlaybookSuggestion,
    PlaybookTemplateDetail,
    PlaybookTemplateSummary,
    UpdatePlaybookStepRequest,
)

router = APIRouter(tags=["playbooks"])


# ── Template endpoints ──────────────────────────────────────────────────────────

@router.get("/playbooks/templates", response_model=List[PlaybookTemplateSummary])
def list_templates(db: Session = Depends(get_db)):
    """List all built-in investigation playbook templates."""
    templates = db.query(PlaybookTemplate).order_by(PlaybookTemplate.id).all()
    return [_build_template_summary(t) for t in templates]


@router.get("/playbooks/templates/{template_id}", response_model=PlaybookTemplateDetail)
def get_template(template_id: int, db: Session = Depends(get_db)):
    """Return a playbook template with its full step list."""
    t = db.query(PlaybookTemplate).filter(PlaybookTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Playbook template not found")
    return _build_template_detail(t)


# ── Case playbook endpoints ─────────────────────────────────────────────────────

@router.post("/cases/{case_id}/playbooks", response_model=CasePlaybookResponse)
def attach_playbook(case_id: int, body: AttachPlaybookRequest, db: Session = Depends(get_db)):
    """Attach a playbook template to a case, creating a fresh step checklist."""
    _require_case(case_id, db)
    template = db.query(PlaybookTemplate).filter(PlaybookTemplate.id == body.template_id).first()
    if not template:
        raise HTTPException(status_code=404, detail="Playbook template not found")

    steps_data = _load_json(template.steps_json, [])

    playbook = CasePlaybook(
        case_id=case_id,
        template_id=template.id,
        name=template.name,
        status="not_started",
        progress_percent=0,
    )
    db.add(playbook)
    db.flush()  # get playbook.id before creating steps

    for step in steps_data:
        db.add(CasePlaybookStep(
            case_playbook_id=playbook.id,
            step_order=step.get("order", 0),
            title=step.get("title", ""),
            description=step.get("description"),
            status="pending",
        ))

    db.commit()
    db.refresh(playbook)
    return _build_playbook_response(playbook)


@router.get("/cases/{case_id}/playbooks", response_model=CasePlaybooksListResponse)
def list_case_playbooks(case_id: int, db: Session = Depends(get_db)):
    """List all playbooks attached to a case, plus auto-suggestions from case findings."""
    _require_case(case_id, db)
    playbooks = (
        db.query(CasePlaybook)
        .filter(CasePlaybook.case_id == case_id)
        .order_by(CasePlaybook.created_at)
        .all()
    )
    suggestions = _suggest_playbooks(db, case_id, attached_template_ids={pb.template_id for pb in playbooks})
    return CasePlaybooksListResponse(
        playbooks=[_build_playbook_response(pb) for pb in playbooks],
        suggestions=suggestions,
    )


@router.get("/cases/{case_id}/playbooks/{playbook_id}", response_model=CasePlaybookResponse)
def get_case_playbook(case_id: int, playbook_id: int, db: Session = Depends(get_db)):
    """Return a single case playbook with all its steps."""
    pb = _require_playbook(case_id, playbook_id, db)
    return _build_playbook_response(pb)


@router.patch(
    "/cases/{case_id}/playbooks/{playbook_id}/steps/{step_id}",
    response_model=PlaybookStepResponse,
)
def update_playbook_step(
    case_id: int,
    playbook_id: int,
    step_id: int,
    body: UpdatePlaybookStepRequest,
    db: Session = Depends(get_db),
):
    """Update a playbook step status, analyst notes, or evidence reference."""
    pb = _require_playbook(case_id, playbook_id, db)
    step = db.query(CasePlaybookStep).filter(
        CasePlaybookStep.id == step_id,
        CasePlaybookStep.case_playbook_id == playbook_id,
    ).first()
    if not step:
        raise HTTPException(status_code=404, detail="Playbook step not found")

    if body.status is not None:
        step.status = body.status
    if body.analyst_notes is not None:
        step.analyst_notes = body.analyst_notes
    if body.evidence_reference is not None:
        step.evidence_reference = body.evidence_reference

    # Recalculate progress on the parent playbook
    all_steps = pb.steps
    total = len(all_steps)
    if total > 0:
        closed = sum(1 for s in all_steps if s.status in ("done", "skipped"))
        pb.progress_percent = int(closed / total * 100)
        if pb.progress_percent == 100:
            pb.status = "completed"
        elif pb.progress_percent > 0:
            pb.status = "in_progress"
        else:
            pb.status = "not_started"

    db.commit()
    db.refresh(step)
    return _build_step_response(step)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _load_json(value, fallback=None):
    if fallback is None:
        fallback = []
    if value is None:
        return fallback
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _require_case(case_id: int, db: Session) -> None:
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")


def _require_playbook(case_id: int, playbook_id: int, db: Session) -> CasePlaybook:
    pb = db.query(CasePlaybook).filter(
        CasePlaybook.id == playbook_id,
        CasePlaybook.case_id == case_id,
    ).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found for this case")
    return pb


def _build_step_response(step: CasePlaybookStep) -> PlaybookStepResponse:
    return PlaybookStepResponse(
        id=step.id,
        step_order=step.step_order,
        title=step.title,
        description=step.description,
        status=step.status,
        analyst_notes=step.analyst_notes,
        evidence_reference=step.evidence_reference,
        created_at=step.created_at.isoformat(),
        updated_at=step.updated_at.isoformat(),
    )


def _build_playbook_response(pb: CasePlaybook) -> CasePlaybookResponse:
    return CasePlaybookResponse(
        id=pb.id,
        case_id=pb.case_id,
        template_id=pb.template_id,
        name=pb.name,
        status=pb.status,
        assigned_to=pb.assigned_to,
        progress_percent=pb.progress_percent,
        steps=[_build_step_response(s) for s in pb.steps],
        created_at=pb.created_at.isoformat(),
        updated_at=pb.updated_at.isoformat(),
    )


def _build_template_summary(t: PlaybookTemplate) -> PlaybookTemplateSummary:
    steps = _load_json(t.steps_json, [])
    return PlaybookTemplateSummary(
        id=t.id,
        name=t.name,
        description=t.description,
        alert_type=t.alert_type,
        severity=t.severity,
        step_count=len(steps),
    )


def _build_template_detail(t: PlaybookTemplate) -> PlaybookTemplateDetail:
    steps = _load_json(t.steps_json, [])
    sources = _load_json(t.required_data_sources, [])
    return PlaybookTemplateDetail(
        id=t.id,
        name=t.name,
        description=t.description,
        alert_type=t.alert_type,
        severity=t.severity,
        required_data_sources=sources,
        steps=steps,
        step_count=len(steps),
    )


def _suggest_playbooks(
    db: Session,
    case_id: int,
    attached_template_ids: set,
) -> list:
    """Auto-suggest relevant playbooks based on case findings."""
    from socmat.services.api.models.normalized_event import NormalizedEvent
    from socmat.services.api.models.detection_finding import DetectionFinding
    from socmat.services.api.models.malware_triage_result import MalwareTriageResult
    from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
    from socmat.services.api.models.correlated_finding import CorrelatedFinding

    # Map alert_type → (reason string, condition_fn)
    candidates: list[tuple[str, str]] = []

    # Brute force: many failed logins
    failed_count = (
        db.query(NormalizedEvent)
        .filter(NormalizedEvent.case_id == case_id, NormalizedEvent.event_id == 4625)
        .count()
    )
    if failed_count >= 3:
        candidates.append(("brute_force", f"Found {failed_count} failed logon events (EID 4625)"))

    # Suspicious PowerShell: Sigma detections mentioning powershell
    ps_count = (
        db.query(DetectionFinding)
        .filter(DetectionFinding.case_id == case_id, DetectionFinding.rule_title.ilike("%powershell%"))
        .count()
    )
    if ps_count > 0:
        candidates.append(("suspicious_powershell", f"{ps_count} PowerShell-related Sigma detection(s) found"))

    # Malware triage: any YARA hit
    yara_hits = (
        db.query(MalwareTriageResult)
        .filter(MalwareTriageResult.case_id == case_id, MalwareTriageResult.risk_score > 0)
        .count()
    )
    if yara_hits > 0:
        candidates.append(("malware_triage", f"{yara_hits} YARA triage hit(s) with non-zero risk score"))

    # IDS high severity: high-risk network analysis result
    high_net = (
        db.query(NetworkAnalysisResult)
        .filter(NetworkAnalysisResult.case_id == case_id, NetworkAnalysisResult.risk_score >= 60)
        .count()
    )
    if high_net > 0:
        candidates.append(("ids_high_severity", f"{high_net} network analysis result(s) with high risk score"))

    # C2 traffic: correlated finding title suggests C2
    c2_corr = (
        db.query(CorrelatedFinding)
        .filter(
            CorrelatedFinding.case_id == case_id,
            CorrelatedFinding.title.ilike("%c2%") | CorrelatedFinding.title.ilike("%command%control%"),
        )
        .count()
    )
    if c2_corr > 0:
        candidates.append(("c2_traffic", f"{c2_corr} correlated finding(s) suggest command-and-control activity"))

    # DNS tunneling: network analysis summary mentions tunneling
    dns_tunnel = (
        db.query(NetworkAnalysisResult)
        .filter(
            NetworkAnalysisResult.case_id == case_id,
            NetworkAnalysisResult.summary.ilike("%dns tunnel%") | NetworkAnalysisResult.summary.ilike("%tunneling%"),
        )
        .count()
    )
    if dns_tunnel > 0:
        candidates.append(("dns_tunneling", "DNS log analysis indicates possible tunneling activity"))

    # Lateral movement: correlated finding title suggests lateral movement
    lateral = (
        db.query(CorrelatedFinding)
        .filter(CorrelatedFinding.case_id == case_id, CorrelatedFinding.title.ilike("%lateral%"))
        .count()
    )
    if lateral > 0:
        candidates.append(("lateral_movement", f"{lateral} correlated finding(s) suggest lateral movement"))

    if not candidates:
        return []

    # Resolve template IDs from alert_type strings
    suggestions = []
    for alert_type, reason in candidates:
        template = (
            db.query(PlaybookTemplate)
            .filter(PlaybookTemplate.alert_type == alert_type)
            .first()
        )
        if template and template.id not in attached_template_ids:
            suggestions.append(
                PlaybookSuggestion(
                    template_id=template.id,
                    name=template.name,
                    alert_type=alert_type,
                    reason=reason,
                )
            )
    return suggestions
