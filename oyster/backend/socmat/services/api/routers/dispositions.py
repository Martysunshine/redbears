from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.finding_disposition import FindingDisposition
from socmat.services.api.schemas.disposition_schema import (
    CaseDispositionsResponse,
    CreateDispositionRequest,
    DispositionSummary,
    FindingDispositionResponse,
    UpdateDispositionRequest,
    VALID_CONFIDENCE,
    VALID_DISPOSITIONS,
    VALID_FINDING_TYPES,
)

router = APIRouter(tags=["dispositions"])


def _build_summary(dispositions: List[FindingDisposition]) -> DispositionSummary:
    counts = {k: 0 for k in ("true_positive", "false_positive", "benign", "suspicious",
                               "needs_review", "escalated", "duplicate", "insufficient_data")}
    for d in dispositions:
        key = d.disposition if d.disposition in counts else "needs_review"
        counts[key] += 1
    return DispositionSummary(total=len(dispositions), **counts)


def _get_case_or_404(case_id: int, db: Session) -> Case:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases/{case_id}/dispositions", response_model=FindingDispositionResponse, status_code=201)
def create_disposition(
    case_id: int,
    body: CreateDispositionRequest,
    db: Session = Depends(get_db),
):
    _get_case_or_404(case_id, db)

    if body.finding_type not in VALID_FINDING_TYPES:
        raise HTTPException(status_code=422, detail=f"Invalid finding_type. Valid: {sorted(VALID_FINDING_TYPES)}")
    if body.disposition not in VALID_DISPOSITIONS:
        raise HTTPException(status_code=422, detail=f"Invalid disposition. Valid: {sorted(VALID_DISPOSITIONS)}")
    if body.confidence not in VALID_CONFIDENCE:
        raise HTTPException(status_code=422, detail=f"Invalid confidence. Valid: {sorted(VALID_CONFIDENCE)}")

    disposition = FindingDisposition(
        case_id=case_id,
        finding_type=body.finding_type,
        finding_id=str(body.finding_id),
        disposition=body.disposition,
        confidence=body.confidence,
        reason=body.reason,
        analyst_name=body.analyst_name,
        follow_up_action=body.follow_up_action,
    )
    db.add(disposition)
    db.commit()
    db.refresh(disposition)
    return disposition


@router.get("/cases/{case_id}/dispositions", response_model=CaseDispositionsResponse)
def list_dispositions(
    case_id: int,
    finding_type: Optional[str] = None,
    finding_id: Optional[str] = None,
    disposition: Optional[str] = None,
    db: Session = Depends(get_db),
):
    _get_case_or_404(case_id, db)

    q = db.query(FindingDisposition).filter(FindingDisposition.case_id == case_id)
    if finding_type:
        q = q.filter(FindingDisposition.finding_type == finding_type)
    if finding_id:
        q = q.filter(FindingDisposition.finding_id == finding_id)
    if disposition:
        q = q.filter(FindingDisposition.disposition == disposition)

    dispositions = q.order_by(FindingDisposition.created_at.desc()).all()
    summary = _build_summary(dispositions)
    return CaseDispositionsResponse(case_id=case_id, dispositions=dispositions, summary=summary)


@router.get("/cases/{case_id}/dispositions/{disposition_id}", response_model=FindingDispositionResponse)
def get_disposition(
    case_id: int,
    disposition_id: int,
    db: Session = Depends(get_db),
):
    _get_case_or_404(case_id, db)
    d = db.query(FindingDisposition).filter(
        FindingDisposition.id == disposition_id,
        FindingDisposition.case_id == case_id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Disposition not found")
    return d


@router.patch("/cases/{case_id}/dispositions/{disposition_id}", response_model=FindingDispositionResponse)
def update_disposition(
    case_id: int,
    disposition_id: int,
    body: UpdateDispositionRequest,
    db: Session = Depends(get_db),
):
    _get_case_or_404(case_id, db)
    d = db.query(FindingDisposition).filter(
        FindingDisposition.id == disposition_id,
        FindingDisposition.case_id == case_id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Disposition not found")

    if body.disposition is not None:
        if body.disposition not in VALID_DISPOSITIONS:
            raise HTTPException(status_code=422, detail=f"Invalid disposition. Valid: {sorted(VALID_DISPOSITIONS)}")
        d.disposition = body.disposition
    if body.confidence is not None:
        if body.confidence not in VALID_CONFIDENCE:
            raise HTTPException(status_code=422, detail=f"Invalid confidence. Valid: {sorted(VALID_CONFIDENCE)}")
        d.confidence = body.confidence
    if body.reason is not None:
        d.reason = body.reason
    if body.analyst_name is not None:
        d.analyst_name = body.analyst_name
    if body.follow_up_action is not None:
        d.follow_up_action = body.follow_up_action

    db.commit()
    db.refresh(d)
    return d


@router.delete("/cases/{case_id}/dispositions/{disposition_id}", status_code=204)
def delete_disposition(
    case_id: int,
    disposition_id: int,
    db: Session = Depends(get_db),
):
    _get_case_or_404(case_id, db)
    d = db.query(FindingDisposition).filter(
        FindingDisposition.id == disposition_id,
        FindingDisposition.case_id == case_id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Disposition not found")
    db.delete(d)
    db.commit()
