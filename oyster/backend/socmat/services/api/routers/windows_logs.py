"""
POST /cases/{case_id}/analyze/windows-logs

Accepts an evidence_id, reads the stored file, runs the Windows/Sysmon
parser, saves normalized events to the DB, and adds timeline entries for
all suspicious findings.
"""

import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

# Add integrations/ to the Python path so the parser can be imported
# whether uvicorn is launched from services/api/ or the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.windows_logs.parser import parse_windows_logs  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.windows_logs import WindowsAnalysisResponse, SuspiciousFinding

router = APIRouter(prefix="/cases", tags=["analysis"])


@router.post("/{case_id}/analyze/windows-logs", response_model=WindowsAnalysisResponse)
def analyze_windows_logs(
    case_id: int,
    evidence_id: int,
    db: Session = Depends(get_db),
):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    ev = db.query(Evidence).filter(
        Evidence.id == evidence_id,
        Evidence.case_id == case_id,
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found for this case")

    try:
        content = Path(ev.storage_path).read_bytes()
    except OSError as e:
        # The OSError text carries the absolute storage path. That is a server
        # detail, not something the analyst can act on — log it, return a
        # message that says what happened and nothing about the filesystem.
        print(f"  [socmat.windows_logs] evidence {ev.id} unreadable: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Could not read the stored evidence file.")

    normalised, findings = parse_windows_logs(content, ev.original_filename)

    # Count events by ID
    id_counts: Counter = Counter(r.get("event_id", "") for r in normalised)
    events_by_id = {k: v for k, v in id_counts.most_common() if k}

    # Deduplicate findings by description to avoid spamming identical timeline entries
    seen_descs: set = set()
    unique_findings: List[SuspiciousFinding] = []
    for f in findings:
        if f["description"] not in seen_descs:
            seen_descs.add(f["description"])
            unique_findings.append(SuspiciousFinding(**f))

    # Save all normalized events to DB (replace prior run for same evidence)
    db.query(NormalizedEvent).filter(
        NormalizedEvent.case_id == case_id,
        NormalizedEvent.evidence_id == evidence_id,
    ).delete()

    saved = 0
    for rec in normalised:
        ne = NormalizedEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            timestamp=rec.get("timestamp_dt"),
            source="windows_logs",
            host=rec.get("host") or None,
            user=rec.get("user") or None,
            event_id=rec.get("event_id") or None,
            event_name=rec.get("event_name") or None,
            process_name=rec.get("process_name") or None,
            parent_process_name=rec.get("parent_process_name") or None,
            command_line=rec.get("command_line") or None,
            source_ip=rec.get("source_ip") or None,
            destination_ip=rec.get("destination_ip") or None,
            destination_port=rec.get("destination_port") or None,
            severity="info",
            description=rec.get("event_name") or f"Event {rec.get('event_id', 'unknown')}",
            raw_json=rec.get("raw") or None,
        )
        db.add(ne)
        saved += 1

    # Add suspicious findings to timeline (deduplicated)
    tl_added = 0
    for f in unique_findings:
        ts = datetime.utcnow()
        # Try to find the first matching event's timestamp for better accuracy
        for rec in normalised:
            if rec.get("event_id") == f.event_id and rec.get("timestamp_dt"):
                ts = rec["timestamp_dt"]
                break
        te = TimelineEvent(
            case_id=case_id,
            timestamp=ts,
            source="windows_logs",
            event_type=f"Event {f.event_id}" if f.event_id else "Detection",
            description=f.description,
            severity=f.severity,
            raw_reference=None,
        )
        db.add(te)
        tl_added += 1

    db.commit()

    return WindowsAnalysisResponse(
        evidence_id=evidence_id,
        total_events=len(normalised),
        events_by_id=events_by_id,
        suspicious_findings=unique_findings,
        timeline_events_added=tl_added,
        normalized_events_saved=saved,
    )


@router.get("/{case_id}/analyze/windows-logs", response_model=List[dict])
def list_normalized_events(case_id: int, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    events = (
        db.query(NormalizedEvent)
        .filter(NormalizedEvent.case_id == case_id)
        .order_by(NormalizedEvent.timestamp.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "evidence_id": e.evidence_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_id": e.event_id,
            "event_name": e.event_name,
            "host": e.host,
            "user": e.user,
            "process_name": e.process_name,
            "command_line": e.command_line,
            "source_ip": e.source_ip,
            "severity": e.severity,
        }
        for e in events
    ]
