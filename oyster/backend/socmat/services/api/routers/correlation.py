"""
Correlation endpoints.

POST /cases/{case_id}/correlate  — run deterministic correlation, replace previous results
GET  /cases/{case_id}/correlate  — list existing correlated findings
"""

import json
from datetime import datetime as _dt
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.correlated_finding import CorrelatedFinding
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.correlation_schema import CorrelatedFindingResponse, CorrelationEntity
from socmat.services.api.correlation_engine import run_correlation

router = APIRouter(tags=["correlation"])


@router.post("/cases/{case_id}/correlate", response_model=List[CorrelatedFindingResponse])
def run_case_correlation(case_id: int, db: Session = Depends(get_db)):
    """Run deterministic correlation across all case modules. Replaces previous results."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    finding_dicts = run_correlation(db, case_id)

    # Idempotent: delete previous results before inserting new ones
    db.query(CorrelatedFinding).filter(
        CorrelatedFinding.case_id == case_id
    ).delete(synchronize_session=False)

    rows: List[CorrelatedFinding] = []
    for fd in finding_dicts:
        row = CorrelatedFinding(
            case_id=case_id,
            title=fd['title'],
            severity=fd['severity'],
            confidence=fd['confidence'],
            entities=json.dumps(fd['entities']),
            related_event_ids=json.dumps(fd['related_event_ids']),
            related_finding_ids=json.dumps(fd['related_finding_ids']),
            summary=fd['summary'],
            recommended_action=fd['recommended_action'],
        )
        db.add(row)
        rows.append(row)

    if finding_dicts:
        high_count = sum(1 for f in finding_dicts if f['severity'] in ('high', 'critical'))
        te = TimelineEvent(
            case_id=case_id,
            timestamp=_dt.utcnow(),
            source="correlation",
            event_type="Investigation Correlation",
            description=(
                f"Correlation engine found {len(finding_dicts)} correlated "
                f"finding{'s' if len(finding_dicts) != 1 else ''} across case modules."
            ),
            severity='high' if high_count > 0 else 'medium',
            raw_reference=None,
        )
        db.add(te)

    db.commit()
    for row in rows:
        db.refresh(row)

    return [_build_response(r) for r in rows]


@router.get("/cases/{case_id}/correlate", response_model=List[CorrelatedFindingResponse])
def list_correlated_findings(case_id: int, db: Session = Depends(get_db)):
    """List existing correlated findings for a case, newest first."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    rows = (
        db.query(CorrelatedFinding)
        .filter(CorrelatedFinding.case_id == case_id)
        .order_by(CorrelatedFinding.created_at.desc())
        .all()
    )
    return [_build_response(r) for r in rows]


# ── helper ────────────────────────────────────────────────────────────────────

def _build_response(row: CorrelatedFinding) -> CorrelatedFindingResponse:
    entities = [
        CorrelationEntity(**e) for e in json.loads(row.entities or '[]')
    ]
    return CorrelatedFindingResponse(
        id=row.id,
        case_id=row.case_id,
        title=row.title,
        severity=row.severity,
        confidence=row.confidence,
        entities=entities,
        related_event_ids=json.loads(row.related_event_ids or '[]'),
        related_finding_ids=json.loads(row.related_finding_ids or '[]'),
        summary=row.summary or '',
        recommended_action=row.recommended_action or '',
        created_at=row.created_at.isoformat(),
    )
