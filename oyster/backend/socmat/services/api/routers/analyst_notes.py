"""
Analyst notes endpoints — polymorphic notes attached to any case entity.

POST   /cases/{case_id}/notes                        — create a note
GET    /cases/{case_id}/notes?entity_type=&entity_id= — list notes (optionally filtered)
PATCH  /cases/{case_id}/notes/{note_id}              — update note body / type
DELETE /cases/{case_id}/notes/{note_id}              — delete a note
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.analyst_note import AnalystNote
from socmat.services.api.models.case import Case
from socmat.services.api.schemas.analyst_note_schema import (
    AnalystNoteResponse,
    CreateNoteRequest,
    UpdateNoteRequest,
)

router = APIRouter(tags=["analyst_notes"])


@router.post("/cases/{case_id}/notes", response_model=AnalystNoteResponse, status_code=201)
def create_note(case_id: int, body: CreateNoteRequest, db: Session = Depends(get_db)):
    """Create an analyst note attached to any case entity."""
    _require_case(case_id, db)
    note = AnalystNote(
        case_id=case_id,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        note_type=body.note_type,
        body=body.body,
        author_name=body.author_name,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return _to_response(note)


@router.get("/cases/{case_id}/notes", response_model=List[AnalystNoteResponse])
def list_notes(
    case_id: int,
    entity_type: Optional[str] = Query(default=None),
    entity_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
):
    """List all notes for a case, optionally filtered by entity_type and entity_id."""
    _require_case(case_id, db)
    q = db.query(AnalystNote).filter(AnalystNote.case_id == case_id)
    if entity_type is not None:
        q = q.filter(AnalystNote.entity_type == entity_type)
    if entity_id is not None:
        q = q.filter(AnalystNote.entity_id == entity_id)
    notes = q.order_by(AnalystNote.created_at.desc()).all()
    return [_to_response(n) for n in notes]


@router.get("/notes", response_model=List[AnalystNoteResponse])
def list_all_notes(
    note_type: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """List every note across ALL of this account's cases (owner-wide feed).

    The DB session is already isolated to the caller's account
    (database.get_db keys off request.state.socmat_owner), so this only ever
    returns the caller's own notes. Used by the top-level Blue Team "Notes"
    surface; each note carries its case_id so the UI can label it."""
    q = db.query(AnalystNote)
    if note_type is not None:
        q = q.filter(AnalystNote.note_type == note_type)
    notes = q.order_by(AnalystNote.created_at.desc()).all()
    return [_to_response(n) for n in notes]


@router.patch("/cases/{case_id}/notes/{note_id}", response_model=AnalystNoteResponse)
def update_note(
    case_id: int,
    note_id: int,
    body: UpdateNoteRequest,
    db: Session = Depends(get_db),
):
    """Update note body, type, or author."""
    note = _require_note(case_id, note_id, db)
    if body.body is not None:
        note.body = body.body
    if body.note_type is not None:
        note.note_type = body.note_type
    if body.author_name is not None:
        note.author_name = body.author_name
    db.commit()
    db.refresh(note)
    return _to_response(note)


@router.delete("/cases/{case_id}/notes/{note_id}", status_code=204)
def delete_note(case_id: int, note_id: int, db: Session = Depends(get_db)):
    """Delete an analyst note."""
    note = _require_note(case_id, note_id, db)
    db.delete(note)
    db.commit()
    return Response(status_code=204)


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _require_case(case_id: int, db: Session) -> None:
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")


def _require_note(case_id: int, note_id: int, db: Session) -> AnalystNote:
    note = db.query(AnalystNote).filter(
        AnalystNote.id == note_id,
        AnalystNote.case_id == case_id,
    ).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found for this case")
    return note


def _to_response(note: AnalystNote) -> AnalystNoteResponse:
    return AnalystNoteResponse(
        id=note.id,
        case_id=note.case_id,
        entity_type=note.entity_type,
        entity_id=note.entity_id,
        note_type=note.note_type,
        body=note.body,
        author_name=note.author_name,
        created_at=note.created_at.isoformat(),
        updated_at=note.updated_at.isoformat(),
    )
