"""
IOC Basket endpoints.

POST   /cases/{case_id}/iocs/extract              — extract IOCs from all case data
GET    /cases/{case_id}/iocs/export?format=csv|json — download all IOCs
GET    /cases/{case_id}/iocs                       — list IOCs (filterable)
POST   /cases/{case_id}/iocs                       — manually add an IOC
PATCH  /cases/{case_id}/iocs/{ioc_id}             — update confidence / tags
DELETE /cases/{case_id}/iocs/{ioc_id}             — remove an IOC
"""

import csv
import io
import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.ioc_extractor import extract_iocs, _normalize_value
from socmat.services.api.models.case import Case
from socmat.services.api.models.ioc import Ioc
from socmat.services.api.schemas.ioc_schema import (
    CreateIocRequest,
    ExtractIocsResponse,
    IocResponse,
    UpdateIocRequest,
)

router = APIRouter(tags=["iocs"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_case(case_id: int, db: Session) -> None:
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")


def _to_response(ioc: Ioc) -> IocResponse:
    tags = json.loads(ioc.tags_json) if ioc.tags_json else []
    return IocResponse(
        id=ioc.id,
        case_id=ioc.case_id,
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        normalized_value=ioc.normalized_value,
        source_type=ioc.source_type,
        source_id=ioc.source_id,
        confidence=ioc.confidence,
        tags=tags,
        first_seen=ioc.first_seen.isoformat() if ioc.first_seen else None,
        last_seen=ioc.last_seen.isoformat() if ioc.last_seen else None,
        created_at=ioc.created_at.isoformat(),
    )


# ── Specific paths first (before parameterised {ioc_id}) ─────────────────────

@router.post("/cases/{case_id}/iocs/extract", response_model=ExtractIocsResponse)
def extract(case_id: int, db: Session = Depends(get_db)):
    """Extract IOCs from all evidence, events, findings, and notes for a case."""
    _require_case(case_id, db)
    new_count, total = extract_iocs(db, case_id)
    return ExtractIocsResponse(extracted=new_count, total=total)


@router.get("/cases/{case_id}/iocs/export")
def export_iocs(
    case_id: int,
    format: str = Query(default="csv", pattern="^(csv|json)$"),
    db: Session = Depends(get_db),
):
    """Export all IOCs for a case as CSV or JSON."""
    _require_case(case_id, db)
    iocs = (
        db.query(Ioc)
        .filter(Ioc.case_id == case_id)
        .order_by(Ioc.ioc_type, Ioc.normalized_value)
        .all()
    )
    items = [_to_response(ioc) for ioc in iocs]

    if format == "json":
        content = json.dumps([i.model_dump() for i in items], indent=2, default=str)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="case_{case_id}_iocs.json"'},
        )

    # CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "ioc_type", "value", "normalized_value",
        "source_type", "source_id", "confidence", "tags",
        "first_seen", "last_seen", "created_at",
    ])
    for i in items:
        writer.writerow([
            i.id, i.ioc_type, i.value, i.normalized_value,
            i.source_type or "", i.source_id or "",
            i.confidence, ",".join(i.tags),
            i.first_seen or "", i.last_seen or "", i.created_at,
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="case_{case_id}_iocs.csv"'},
    )


# ── Collection routes ─────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/iocs", response_model=List[IocResponse])
def list_iocs(
    case_id: int,
    ioc_type: Optional[str] = Query(default=None),
    tag: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """List IOCs for a case, with optional filtering."""
    _require_case(case_id, db)
    q = db.query(Ioc).filter(Ioc.case_id == case_id)
    if ioc_type:
        q = q.filter(Ioc.ioc_type == ioc_type)
    iocs = q.order_by(Ioc.ioc_type, Ioc.normalized_value).all()
    results = [_to_response(ioc) for ioc in iocs]
    if tag:
        results = [r for r in results if tag in r.tags]
    if search:
        s = search.lower()
        results = [r for r in results if s in r.normalized_value or s in r.value.lower()]
    return results


@router.post("/cases/{case_id}/iocs", response_model=IocResponse, status_code=201)
def create_ioc(case_id: int, body: CreateIocRequest, db: Session = Depends(get_db)):
    """Manually add an IOC to the case basket."""
    _require_case(case_id, db)
    norm = _normalize_value(body.value, body.ioc_type)
    existing = db.query(Ioc).filter(
        Ioc.case_id == case_id,
        Ioc.ioc_type == body.ioc_type,
        Ioc.normalized_value == norm,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="This IOC already exists for the case")
    ioc = Ioc(
        case_id=case_id,
        ioc_type=body.ioc_type,
        value=body.value,
        normalized_value=norm,
        source_type=None,
        source_id=None,
        confidence=body.confidence,
        tags_json=json.dumps(body.tags),
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return _to_response(ioc)


# ── Item routes ───────────────────────────────────────────────────────────────

@router.patch("/cases/{case_id}/iocs/{ioc_id}", response_model=IocResponse)
def update_ioc(
    case_id: int,
    ioc_id: int,
    body: UpdateIocRequest,
    db: Session = Depends(get_db),
):
    """Update confidence and/or tags on an IOC."""
    ioc = db.query(Ioc).filter(Ioc.id == ioc_id, Ioc.case_id == case_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found for this case")
    if body.confidence is not None:
        ioc.confidence = body.confidence
    if body.tags is not None:
        ioc.tags_json = json.dumps(body.tags)
    db.commit()
    db.refresh(ioc)
    return _to_response(ioc)


@router.delete("/cases/{case_id}/iocs/{ioc_id}", status_code=204)
def delete_ioc(case_id: int, ioc_id: int, db: Session = Depends(get_db)):
    """Remove an IOC from the basket."""
    ioc = db.query(Ioc).filter(Ioc.id == ioc_id, Ioc.case_id == case_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found for this case")
    db.delete(ioc)
    db.commit()
    return Response(status_code=204)
