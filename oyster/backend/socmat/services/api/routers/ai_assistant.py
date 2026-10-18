"""
AI investigation assistant endpoints.

POST /cases/{case_id}/ai/summarize  — AI case summary grounded in stored data
POST /cases/{case_id}/ai/recommend  — AI recommended next steps and evidence gaps
"""

import sys
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.ai_assistant.context_builder import build_case_context
from socmat.services.api.ai_assistant.provider import call_ai, get_provider_name, _DISCLAIMER
from socmat.services.api.schemas.ai_schema import AIAnalysisResponse

router = APIRouter(tags=["ai-assistant"])


@router.post("/cases/{case_id}/ai/summarize", response_model=AIAnalysisResponse)
def ai_summarize(case_id: int, db: Session = Depends(get_db)):
    """Generate an AI-assisted summary of all case findings."""
    _require_case(case_id, db)
    context = build_case_context(db, case_id)
    try:
        result = call_ai("summarize", context)
    except RuntimeError as exc:
        raise _unavailable(exc) from exc

    return AIAnalysisResponse(
        provider=get_provider_name(),
        mode="summarize",
        case_id=case_id,
        generated_at=datetime.utcnow().isoformat(),
        disclaimer=_DISCLAIMER,
        **result,
    )


@router.post("/cases/{case_id}/ai/recommend", response_model=AIAnalysisResponse)
def ai_recommend(case_id: int, db: Session = Depends(get_db)):
    """Generate AI-assisted recommendations and identify investigation gaps."""
    _require_case(case_id, db)
    context = build_case_context(db, case_id)
    try:
        result = call_ai("recommend", context)
    except RuntimeError as exc:
        raise _unavailable(exc) from exc

    return AIAnalysisResponse(
        provider=get_provider_name(),
        mode="recommend",
        case_id=case_id,
        generated_at=datetime.utcnow().isoformat(),
        disclaimer=_DISCLAIMER,
        **result,
    )


def _require_case(case_id: int, db: Session) -> None:
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")


def _unavailable(exc: Exception) -> HTTPException:
    """503 without the provider's own words: those name packages, environment
    variables and hosts, which belong in the server log, not on the analyst's
    screen."""
    print(f"  [socmat.ai] provider failure: {type(exc).__name__}: {exc}", file=sys.stderr)
    return HTTPException(status_code=503, detail="The AI assistant is unavailable right now.")
