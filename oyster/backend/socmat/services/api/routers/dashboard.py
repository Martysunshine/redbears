"""
Dashboard summary endpoint.

GET /dashboard/summary
    Returns aggregate counts and recent activity for the SOC Copilot dashboard.
"""

from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.report import Report
from socmat.services.api.models.timeline_event import TimelineEvent

router = APIRouter(tags=["dashboard"])


class RecentCase(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class RecentTimelineEvent(BaseModel):
    id: int
    case_id: int
    event_type: str
    description: str
    severity: str
    timestamp: str
    source: str

    model_config = ConfigDict(from_attributes=True)


class DashboardSummary(BaseModel):
    total_cases: int
    open_cases: int
    investigating_cases: int
    critical_cases: int
    high_cases: int
    total_evidence: int
    total_timeline_events: int
    total_reports: int
    recent_cases: List[RecentCase]
    recent_timeline: List[RecentTimelineEvent]


@router.get("/dashboard/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Return aggregate counts and recent activity for the SOC dashboard."""
    total_cases = db.query(Case).count()
    open_cases = db.query(Case).filter(Case.status == "open").count()
    investigating_cases = db.query(Case).filter(Case.status == "investigating").count()
    critical_cases = db.query(Case).filter(Case.severity == "critical").count()
    high_cases = db.query(Case).filter(Case.severity == "high").count()
    total_evidence = db.query(Evidence).count()
    total_timeline_events = db.query(TimelineEvent).count()
    total_reports = db.query(Report).count()

    recent_case_rows = (
        db.query(Case)
        .order_by(Case.created_at.desc())
        .limit(5)
        .all()
    )
    recent_timeline_rows = (
        db.query(TimelineEvent)
        .order_by(TimelineEvent.timestamp.desc())
        .limit(5)
        .all()
    )

    return DashboardSummary(
        total_cases=total_cases,
        open_cases=open_cases,
        investigating_cases=investigating_cases,
        critical_cases=critical_cases,
        high_cases=high_cases,
        total_evidence=total_evidence,
        total_timeline_events=total_timeline_events,
        total_reports=total_reports,
        recent_cases=[
            RecentCase(
                id=c.id,
                title=c.title,
                severity=c.severity,
                status=c.status,
                created_at=c.created_at.isoformat() if c.created_at else "",
            )
            for c in recent_case_rows
        ],
        recent_timeline=[
            RecentTimelineEvent(
                id=e.id,
                case_id=e.case_id,
                event_type=e.event_type,
                description=e.description,
                severity=e.severity,
                timestamp=e.timestamp.isoformat() if e.timestamp else "",
                source=e.source,
            )
            for e in recent_timeline_rows
        ],
    )
