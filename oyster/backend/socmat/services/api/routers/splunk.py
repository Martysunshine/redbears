"""
Splunk Export Analysis and SPL Query Assistant endpoints.

POST /cases/{case_id}/analyze/splunk-export?evidence_id=N
    Parse an uploaded Splunk CSV/JSON export, normalise fields, save events.

GET  /cases/{case_id}/analyze/splunk-export
    List normalised Splunk events for a case.

GET  /splunk/query-templates
    Return all SPL query templates.

POST /splunk/query-assistant
    Match a free-text intent against the template library and return
    a structured SPL query with full analyst guidance.
"""

import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.splunk.parser import parse_splunk_export  # noqa: E402
from socmat.integrations.splunk.query_templates import (  # noqa: E402
    INTENT_KEYWORDS,
    QUERY_TEMPLATES,
)

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.splunk_event import SplunkEvent
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.splunk_schema import (
    SPLQueryAssistantRequest,
    SPLQueryAssistantResponse,
    SPLQueryTemplate,
    SplunkAnalysisResponse,
    SplunkEventResponse,
)

router = APIRouter(tags=["splunk"])


# ── Analysis endpoints ────────────────────────────────────────────────────────

@router.post(
    "/cases/{case_id}/analyze/splunk-export",
    response_model=SplunkAnalysisResponse,
)
def analyze_splunk_export(
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
    except OSError as exc:
        # The OSError text carries the absolute storage path. That is a server
        # detail, not something the analyst can act on — log it, return a
        # message that says what happened and nothing about the filesystem.
        print(f"  [socmat.splunk] evidence {ev.id} unreadable: {exc}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Could not read the stored evidence file.")

    events = parse_splunk_export(content, ev.original_filename)
    if not events:
        raise HTTPException(
            status_code=422,
            detail="No parseable Splunk events found. "
                   "Upload a Splunk CSV or JSON export.",
        )

    # Persist normalised events
    saved = 0
    for evt in events:
        db.add(SplunkEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            event_time=evt.get("event_time"),
            index=evt.get("index"),
            sourcetype=evt.get("sourcetype"),
            host=evt.get("host"),
            source=evt.get("source"),
            user=evt.get("user"),
            src_ip=evt.get("src_ip"),
            dest_ip=evt.get("dest_ip"),
            process_name=evt.get("process_name"),
            command_line=evt.get("command_line"),
            event_code=evt.get("event_code"),
            raw=evt.get("raw"),
        ))
        saved += 1

    # Summary stats
    sourcetypes = sorted(
        {e.get("sourcetype") for e in events if e.get("sourcetype")}
    )
    host_counter: Counter = Counter(e.get("host") for e in events if e.get("host"))
    top_hosts = [h for h, _ in host_counter.most_common(5)]

    # High-signal timeline events
    timeline_added = 0
    for evt in events:
        ec = evt.get("event_code") or ""
        if ec in ("4625", "4697", "4648", "4688") or evt.get("command_line"):
            label = _event_label(ec, evt)
            db.add(TimelineEvent(
                case_id=case_id,
                timestamp=_parse_time(evt.get("event_time")),
                event_type="splunk_event",
                description=label,
                source="splunk",
                severity=_event_severity(ec),
                host=evt.get("host"),
                user=evt.get("user"),
            ))
            timeline_added += 1
            if timeline_added >= 20:
                break

    db.commit()

    return SplunkAnalysisResponse(
        evidence_id=evidence_id,
        total_events=len(events),
        sourcetypes=sourcetypes,
        top_hosts=top_hosts,
        timeline_events_added=timeline_added,
        normalized_events_saved=saved,
    )


@router.get(
    "/cases/{case_id}/analyze/splunk-export",
    response_model=List[SplunkEventResponse],
)
def list_splunk_events(case_id: int, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    rows = (
        db.query(SplunkEvent)
        .filter(SplunkEvent.case_id == case_id)
        .order_by(SplunkEvent.analyzed_at.desc())
        .all()
    )
    return [
        SplunkEventResponse(
            id=r.id,
            case_id=r.case_id,
            evidence_id=r.evidence_id,
            event_time=r.event_time,
            index=r.index,
            sourcetype=r.sourcetype,
            host=r.host,
            source=r.source,
            user=r.user,
            src_ip=r.src_ip,
            dest_ip=r.dest_ip,
            process_name=r.process_name,
            command_line=r.command_line,
            event_code=r.event_code,
            analyzed_at=r.analyzed_at.isoformat() if r.analyzed_at else "",
        )
        for r in rows
    ]


# ── Query template endpoints ──────────────────────────────────────────────────

@router.get("/splunk/query-templates", response_model=List[SPLQueryTemplate])
def list_query_templates():
    """Return all SPL query templates."""
    return QUERY_TEMPLATES


@router.post("/splunk/query-assistant", response_model=SPLQueryAssistantResponse)
def query_assistant(body: SPLQueryAssistantRequest):
    """
    Match a free-text investigation intent to an SPL query template.
    Returns the best-matching template plus full analyst guidance.
    """
    intent_lower = body.intent.lower()
    matched_id: str = QUERY_TEMPLATES[0]["id"]
    matched_by: str = "default"

    for template_id, keywords in INTENT_KEYWORDS.items():
        for kw in keywords:
            if kw in intent_lower:
                matched_id = template_id
                matched_by = kw
                break
        else:
            continue
        break

    template = next((t for t in QUERY_TEMPLATES if t["id"] == matched_id), QUERY_TEMPLATES[0])
    return SPLQueryAssistantResponse(**template, matched_by=matched_by)


# ── Helpers ───────────────────────────────────────────────────────────────────

_HIGH_SIGNAL_CODES = {"4625", "4648", "4697", "4688", "4719", "4732", "4756"}
_MED_SIGNAL_CODES = {"4624", "4720", "4726", "4740"}


def _event_severity(event_code: str) -> str:
    if event_code in _HIGH_SIGNAL_CODES:
        return "high"
    if event_code in _MED_SIGNAL_CODES:
        return "medium"
    return "info"


def _event_label(event_code: str, evt: dict) -> str:
    labels = {
        "4625": "Failed logon",
        "4624": "Successful logon",
        "4648": "Explicit credential logon",
        "4697": "New service installed",
        "4688": "Process created",
        "4719": "Audit policy changed",
        "4732": "User added to privileged group",
        "4756": "Member added to universal group",
        "4720": "User account created",
        "4726": "User account deleted",
        "4740": "User account locked out",
    }
    base = labels.get(event_code, f"Splunk event {event_code}" if event_code else "Splunk event")
    parts = [base]
    if evt.get("user"):
        parts.append(f"user={evt['user']}")
    if evt.get("host"):
        parts.append(f"host={evt['host']}")
    if evt.get("process_name") and not event_code:
        parts.append(f"process={evt['process_name']}")
    return " | ".join(parts)


def _parse_time(ts: str | None) -> datetime:
    if not ts:
        return datetime.utcnow()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts[:26], fmt)
            return dt.replace(tzinfo=None)
        except (ValueError, TypeError):
            continue
    return datetime.utcnow()
