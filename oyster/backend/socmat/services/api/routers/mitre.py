"""
MITRE ATT&CK mapping endpoints.

GET  /mitre/mappings                  — list local technique catalog
POST /cases/{case_id}/mitre/map       — run ATT&CK mapping for a case (idempotent)
GET  /cases/{case_id}/mitre/map       — list existing mappings for a case
"""

import json
from datetime import datetime as _dt
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.case_mitre_mapping import CaseMitreMapping
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.mitre_schema import EvidenceRef, MitreMappingResponse, MitreTechniqueInfo
from socmat.services.api.mitre_mapper import _load_catalog, run_mitre_mapping

router = APIRouter(tags=["mitre"])


@router.get("/mitre/mappings", response_model=List[MitreTechniqueInfo])
def list_mitre_catalog():
    """Return the local MITRE ATT&CK technique catalog."""
    catalog = _load_catalog()
    return [MitreTechniqueInfo(**v) for v in catalog.values()]


@router.post("/cases/{case_id}/mitre/map", response_model=List[MitreMappingResponse])
def run_case_mitre_mapping(case_id: int, db: Session = Depends(get_db)):
    """Run MITRE ATT&CK mapping for a case. Replaces previous results."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    mapping_dicts = run_mitre_mapping(db, case_id)

    db.query(CaseMitreMapping).filter(
        CaseMitreMapping.case_id == case_id
    ).delete(synchronize_session=False)

    rows: List[CaseMitreMapping] = []
    for md in mapping_dicts:
        row = CaseMitreMapping(
            case_id=case_id,
            tactic=md['tactic'],
            technique_id=md['technique_id'],
            technique_name=md['technique_name'],
            evidence_reference=json.dumps(md['evidence_reference']),
            confidence=md['confidence'],
        )
        db.add(row)
        rows.append(row)

    if mapping_dicts:
        tactic_count = len({md['tactic'] for md in mapping_dicts})
        te = TimelineEvent(
            case_id=case_id,
            timestamp=_dt.utcnow(),
            source="mitre",
            event_type="MITRE ATT&CK Mapping",
            description=(
                f"MITRE ATT&CK mapping identified {len(mapping_dicts)} "
                f"technique{'s' if len(mapping_dicts) != 1 else ''} across "
                f"{tactic_count} tactic{'s' if tactic_count != 1 else ''}."
            ),
            severity='medium',
            raw_reference=None,
        )
        db.add(te)

    db.commit()
    for row in rows:
        db.refresh(row)

    return [_build_response(r) for r in rows]


@router.get("/cases/{case_id}/mitre/map", response_model=List[MitreMappingResponse])
def get_case_mitre_mappings(case_id: int, db: Session = Depends(get_db)):
    """List existing MITRE ATT&CK mappings for a case, ordered by tactic."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    rows = (
        db.query(CaseMitreMapping)
        .filter(CaseMitreMapping.case_id == case_id)
        .order_by(CaseMitreMapping.tactic, CaseMitreMapping.technique_id)
        .all()
    )
    return [_build_response(r) for r in rows]


# ── helper ─────────────────────────────────────────────────────────────────────

def _build_response(row: CaseMitreMapping) -> MitreMappingResponse:
    refs = [EvidenceRef(**r) for r in json.loads(row.evidence_reference or '[]')]
    return MitreMappingResponse(
        id=row.id,
        case_id=row.case_id,
        tactic=row.tactic,
        technique_id=row.technique_id,
        technique_name=row.technique_name,
        evidence_reference=refs,
        confidence=row.confidence,
        created_at=row.created_at.isoformat(),
    )
