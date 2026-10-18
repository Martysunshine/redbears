"""
Sigma rule library endpoints.

GET  /sigma/rules           — list all loaded rules (filterable)
GET  /sigma/rules/{rule_id} — rule detail with explanation
POST /sigma/rules/reload    — reload rules from disk

POST   /cases/{case_id}/sigma/rules                   — attach rule to case
GET    /cases/{case_id}/sigma/rules                   — list attached rules
DELETE /cases/{case_id}/sigma/rules/{rule_sigma_id}   — detach rule from case
"""

import sys
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.sigma.loader import get_cached_rules, get_rule_by_id, load_rules  # noqa: E402
from socmat.integrations.sigma.explainer import explain  # noqa: E402
from socmat.integrations.sigma.matcher import run_rules_against_events  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.case_sigma_rule import CaseSigmaRule
from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.sigma import (
    AttachRuleRequest,
    CaseSigmaRuleResponse,
    RuleExplanation,
    SigmaRuleResponse,
)
from socmat.services.api.schemas.detection import DetectionFindingResponse, SigmaRunResponse

router = APIRouter(tags=["sigma"])


@router.get("/sigma/rules", response_model=List[SigmaRuleResponse])
def list_sigma_rules(
    level: Optional[str] = Query(None, description="Filter by rule level"),
    logsource_product: Optional[str] = Query(None, description="Filter by logsource product"),
    logsource_category: Optional[str] = Query(None, description="Filter by logsource category"),
    tag: Optional[str] = Query(None, description="Filter by tag substring"),
):
    rules = get_cached_rules()
    if level:
        rules = [r for r in rules if r["level"].lower() == level.lower()]
    if logsource_product:
        rules = [r for r in rules
                 if r["logsource"].get("product", "").lower() == logsource_product.lower()]
    if logsource_category:
        rules = [r for r in rules
                 if r["logsource"].get("category", "").lower() == logsource_category.lower()]
    if tag:
        tag_lower = tag.lower()
        rules = [r for r in rules
                 if any(tag_lower in t.lower() for t in r["tags"])]
    return [SigmaRuleResponse(**r) for r in rules]


@router.post("/sigma/rules/reload")
def reload_sigma_rules():
    rules = load_rules()
    return {"loaded": len(rules)}


@router.get("/sigma/rules/{rule_id}", response_model=SigmaRuleResponse)
def get_sigma_rule(rule_id: str):
    rule = get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
    return SigmaRuleResponse(**rule, explanation=RuleExplanation(**explain(rule)))


@router.post("/cases/{case_id}/sigma/rules", response_model=CaseSigmaRuleResponse, status_code=201)
def attach_sigma_rule(
    case_id: int,
    body: AttachRuleRequest,
    db: Session = Depends(get_db),
):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    if not get_rule_by_id(body.rule_sigma_id):
        raise HTTPException(status_code=404, detail="Sigma rule not found")

    existing = db.query(CaseSigmaRule).filter(
        CaseSigmaRule.case_id == case_id,
        CaseSigmaRule.rule_sigma_id == body.rule_sigma_id,
    ).first()
    if existing:
        return CaseSigmaRuleResponse(
            id=existing.id,
            case_id=existing.case_id,
            rule_sigma_id=existing.rule_sigma_id,
            rule_title=existing.rule_title,
            rule_level=existing.rule_level,
            attached_at=existing.attached_at.isoformat(),
        )

    row = CaseSigmaRule(
        case_id=case_id,
        rule_sigma_id=body.rule_sigma_id,
        rule_title=body.rule_title,
        rule_level=body.rule_level,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return CaseSigmaRuleResponse(
        id=row.id,
        case_id=row.case_id,
        rule_sigma_id=row.rule_sigma_id,
        rule_title=row.rule_title,
        rule_level=row.rule_level,
        attached_at=row.attached_at.isoformat(),
    )


@router.get("/cases/{case_id}/sigma/rules", response_model=List[CaseSigmaRuleResponse])
def list_case_sigma_rules(case_id: int, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    rows = db.query(CaseSigmaRule).filter(CaseSigmaRule.case_id == case_id).all()
    return [
        CaseSigmaRuleResponse(
            id=r.id,
            case_id=r.case_id,
            rule_sigma_id=r.rule_sigma_id,
            rule_title=r.rule_title,
            rule_level=r.rule_level,
            attached_at=r.attached_at.isoformat(),
        )
        for r in rows
    ]


@router.delete("/cases/{case_id}/sigma/rules/{rule_sigma_id}", status_code=204)
def detach_sigma_rule(
    case_id: int,
    rule_sigma_id: str,
    db: Session = Depends(get_db),
):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    row = db.query(CaseSigmaRule).filter(
        CaseSigmaRule.case_id == case_id,
        CaseSigmaRule.rule_sigma_id == rule_sigma_id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Rule not attached to this case")
    db.delete(row)
    db.commit()


@router.post("/cases/{case_id}/sigma/run", response_model=SigmaRunResponse)
def run_sigma_rules(
    case_id: int,
    rule_id: Optional[str] = Query(None, description="Run a single rule by ID; omit to run all loaded rules"),
    db: Session = Depends(get_db),
):
    """
    Run loaded Sigma rules against normalized Windows/Sysmon events for a case.
    Clears previous findings for the targeted rule(s) before storing new ones.
    """
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    # Determine which rules to run
    if rule_id:
        rule = get_rule_by_id(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Sigma rule not found")
        rules_to_run = [rule]
    else:
        rules_to_run = get_cached_rules()

    # Load normalised events for this case
    db_events = (
        db.query(NormalizedEvent)
        .filter(NormalizedEvent.case_id == case_id)
        .order_by(NormalizedEvent.timestamp.asc())
        .all()
    )

    events_as_dicts = [
        {
            "id": e.id,
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "host": e.host,
            "user": e.user,
            "process_name": e.process_name,
            "parent_process_name": e.parent_process_name,
            "command_line": e.command_line,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "destination_port": e.destination_port,
            "source": e.source,
        }
        for e in db_events
    ]

    # Clear stale findings for the rules being run
    rule_ids_to_run = [r["id"] for r in rules_to_run]
    db.query(DetectionFinding).filter(
        DetectionFinding.case_id == case_id,
        DetectionFinding.rule_id.in_(rule_ids_to_run),
    ).delete(synchronize_session=False)

    # Run matching
    raw_findings = run_rules_against_events(rules_to_run, events_as_dicts)

    # Persist findings and timeline entries
    created: list = []
    seen_timeline: set = set()
    for f in raw_findings:
        ts = f.get("event_timestamp")
        row = DetectionFinding(
            case_id=case_id,
            rule_id=f["rule_id"],
            rule_title=f["rule_title"],
            severity=f["severity"],
            matched_event_id=f["matched_event_id"],
            match_reason=f["match_reason"],
            event_id_str=f.get("event_id_str"),
            event_timestamp=ts,
        )
        db.add(row)
        db.flush()  # Get row.id before commit

        # Add one timeline entry per unique rule match (avoid duplicates)
        tl_key = (f["rule_id"], f["matched_event_id"])
        if tl_key not in seen_timeline:
            seen_timeline.add(tl_key)
            from datetime import datetime as _dt
            te = TimelineEvent(
                case_id=case_id,
                timestamp=ts or _dt.utcnow(),
                source="sigma",
                event_type="Sigma Detection",
                description=f"[{f['severity'].upper()}] {f['rule_title']} — {f['match_reason']}",
                severity=f["severity"],
                raw_reference=f["rule_id"],
            )
            db.add(te)

        created.append(
            DetectionFindingResponse(
                id=row.id,
                case_id=row.case_id,
                rule_id=row.rule_id,
                rule_title=row.rule_title,
                severity=row.severity,
                matched_event_id=row.matched_event_id,
                match_reason=row.match_reason,
                event_id_str=row.event_id_str,
                event_timestamp=row.event_timestamp.isoformat() if row.event_timestamp else None,
                created_at=row.created_at.isoformat(),
            )
        )

    db.commit()

    return SigmaRunResponse(
        rules_run=len(rules_to_run),
        events_scanned=len(db_events),
        findings_created=len(created),
        findings=created,
    )


@router.get("/cases/{case_id}/sigma/findings", response_model=List[DetectionFindingResponse])
def list_sigma_findings(case_id: int, db: Session = Depends(get_db)):
    """List all Sigma detection findings for a case, ordered newest-first."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    rows = (
        db.query(DetectionFinding)
        .filter(DetectionFinding.case_id == case_id)
        .order_by(DetectionFinding.created_at.desc())
        .all()
    )
    return [
        DetectionFindingResponse(
            id=r.id,
            case_id=r.case_id,
            rule_id=r.rule_id,
            rule_title=r.rule_title,
            severity=r.severity,
            matched_event_id=r.matched_event_id,
            match_reason=r.match_reason,
            event_id_str=r.event_id_str,
            event_timestamp=r.event_timestamp.isoformat() if r.event_timestamp else None,
            created_at=r.created_at.isoformat(),
        )
        for r in rows
    ]
