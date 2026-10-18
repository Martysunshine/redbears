"""
Incident report endpoints.

POST /cases/{case_id}/report/generate  — generate Markdown report (idempotent: always creates new)
GET  /cases/{case_id}/report           — get most recent report metadata for a case
GET  /cases/{case_id}/report/content   — return raw Markdown content for download
GET  /reports                          — list all reports across all cases
"""

from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.report import Report
from socmat.services.api.report_generator import generate_report, _REPO_ROOT
from socmat.services.api.report_readiness import compute_readiness
from socmat.services.api.pdf_generator import generate_pdf
from socmat.services.api.schemas.readiness_schema import ReadinessResponse
from socmat.services.api.schemas.report_schema import ReportResponse

router = APIRouter(tags=["reports"])


@router.post("/cases/{case_id}/report/generate", response_model=ReportResponse)
def generate_case_report(case_id: int, db: Session = Depends(get_db)):
    """Generate a Markdown incident report for a case. Always creates a new report file."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    report_path, summary = generate_report(db, case_id)

    row = Report(
        case_id=case_id,
        report_path=report_path,
        format="markdown",
        summary=summary,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return _build_response(row)


@router.get("/cases/{case_id}/report", response_model=Optional[ReportResponse])
def get_case_report(case_id: int, db: Session = Depends(get_db)):
    """Return metadata for the most recently generated report of a case."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    row = (
        db.query(Report)
        .filter(Report.case_id == case_id)
        .order_by(Report.generated_at.desc())
        .first()
    )
    if not row:
        return None

    return _build_response(row)


@router.get("/cases/{case_id}/report/content", response_class=PlainTextResponse)
def get_case_report_content(case_id: int, db: Session = Depends(get_db)):
    """Return the raw Markdown content of the most recent report for download."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    row = (
        db.query(Report)
        .filter(Report.case_id == case_id)
        .order_by(Report.generated_at.desc())
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="No report generated for this case")

    path = _REPO_ROOT / row.report_path
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return path.read_text(encoding='utf-8')


@router.get("/cases/{case_id}/report/readiness", response_model=ReadinessResponse)
def get_report_readiness(case_id: int, db: Session = Depends(get_db)):
    """Compute a report readiness score for a case based on 22 completeness checks."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    result = compute_readiness(db, case_id)
    return result


@router.get("/cases/{case_id}/report/pdf")
def download_case_report_pdf(case_id: int, db: Session = Depends(get_db)):
    """Generate and return a PDF incident report for a case as a file download."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    pdf_bytes = generate_pdf(db, case_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=case-{case_id}-incident-report.pdf"},
    )


@router.get("/reports", response_model=List[ReportResponse])
def list_all_reports(db: Session = Depends(get_db)):
    """List all generated reports across all cases, newest first."""
    rows = db.query(Report).order_by(Report.generated_at.desc()).all()
    return [_build_response(r) for r in rows]


# ── helper ─────────────────────────────────────────────────────────────────────

def _build_response(row: Report) -> ReportResponse:
    return ReportResponse(
        id=row.id,
        case_id=row.case_id,
        report_path=row.report_path,
        format=row.format,
        generated_at=row.generated_at.isoformat(),
        summary=row.summary,
    )
