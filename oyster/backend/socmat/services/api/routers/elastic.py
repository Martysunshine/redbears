"""
Elastic Export Analysis and KQL/ES|QL Hunt Assistant endpoints.

POST /cases/{case_id}/analyze/elastic-export?evidence_id=N
    Parse an uploaded Kibana/ES CSV/JSON export, normalise ECS fields, save events.

GET  /cases/{case_id}/analyze/elastic-export
    List normalised Elastic events for a case.

GET  /elastic/hunt-templates
    Return all KQL/ES|QL hunt templates.

POST /elastic/hunt-assistant
    Match a free-text intent against the template library and return
    a structured query with full analyst guidance.
    If case_id is provided, records the hunt in the case timeline.
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

from socmat.integrations.elastic.parser import parse_elastic_export  # noqa: E402
from socmat.integrations.elastic.hunt_templates import (  # noqa: E402
    INTENT_KEYWORDS,
    HUNT_TEMPLATES,
)

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.elastic_event import ElasticEvent
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.elastic_schema import (
    ElasticAnalysisResponse,
    ElasticEventResponse,
    HuntAssistantRequest,
    HuntAssistantResponse,
    HuntTemplate,
)

router = APIRouter(tags=["elastic"])


# ── Analysis endpoints ────────────────────────────────────────────────────────

@router.post(
    "/cases/{case_id}/analyze/elastic-export",
    response_model=ElasticAnalysisResponse,
)
def analyze_elastic_export(
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
        print(f"  [socmat.elastic] evidence {ev.id} unreadable: {exc}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Could not read the stored evidence file.")

    events = parse_elastic_export(content, ev.original_filename)
    if not events:
        raise HTTPException(
            status_code=422,
            detail="No parseable Elastic events found. "
                   "Upload a Kibana CSV, JSON array, NDJSON, or Elasticsearch _search export.",
        )

    # Persist normalised events
    saved = 0
    for evt in events:
        db.add(ElasticEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            event_time=evt.get("event_time"),
            host_name=evt.get("host_name"),
            user_name=evt.get("user_name"),
            src_ip=evt.get("src_ip"),
            dest_ip=evt.get("dest_ip"),
            process_name=evt.get("process_name"),
            parent_process_name=evt.get("parent_process_name"),
            command_line=evt.get("command_line"),
            event_code=evt.get("event_code"),
            event_category=evt.get("event_category"),
            event_action=evt.get("event_action"),
            file_hash_sha256=evt.get("file_hash_sha256"),
            dns_question=evt.get("dns_question"),
            raw=evt.get("raw"),
        ))
        saved += 1

    # Summary stats
    event_categories = sorted(
        {e.get("event_category") for e in events if e.get("event_category")}
    )
    host_counter: Counter = Counter(
        e.get("host_name") for e in events if e.get("host_name")
    )
    top_hosts = [h for h, _ in host_counter.most_common(5)]

    # High-signal timeline events
    timeline_added = 0
    for evt in events:
        ec = evt.get("event_code") or ""
        cat = (evt.get("event_category") or "").lower()
        if ec in _HIGH_SIGNAL_CODES or "authentication" in cat or evt.get("command_line"):
            label = _event_label(ec, cat, evt)
            db.add(TimelineEvent(
                case_id=case_id,
                timestamp=_parse_time(evt.get("event_time")),
                event_type="elastic_event",
                description=label,
                source="elastic",
                severity=_event_severity(ec, cat),
            ))
            timeline_added += 1
            if timeline_added >= 20:
                break

    db.commit()

    return ElasticAnalysisResponse(
        evidence_id=evidence_id,
        total_events=len(events),
        event_categories=event_categories,
        top_hosts=top_hosts,
        timeline_events_added=timeline_added,
        normalized_events_saved=saved,
    )


@router.get(
    "/cases/{case_id}/analyze/elastic-export",
    response_model=List[ElasticEventResponse],
)
def list_elastic_events(case_id: int, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    rows = (
        db.query(ElasticEvent)
        .filter(ElasticEvent.case_id == case_id)
        .order_by(ElasticEvent.analyzed_at.desc())
        .all()
    )
    return [
        ElasticEventResponse(
            id=r.id,
            case_id=r.case_id,
            evidence_id=r.evidence_id,
            event_time=r.event_time,
            host_name=r.host_name,
            user_name=r.user_name,
            src_ip=r.src_ip,
            dest_ip=r.dest_ip,
            process_name=r.process_name,
            parent_process_name=r.parent_process_name,
            command_line=r.command_line,
            event_code=r.event_code,
            event_category=r.event_category,
            event_action=r.event_action,
            file_hash_sha256=r.file_hash_sha256,
            dns_question=r.dns_question,
            analyzed_at=r.analyzed_at.isoformat() if r.analyzed_at else "",
        )
        for r in rows
    ]


# ── Hunt template endpoints ───────────────────────────────────────────────────

@router.get("/elastic/hunt-templates", response_model=List[HuntTemplate])
def list_hunt_templates():
    """Return all KQL/ES|QL hunt templates."""
    return HUNT_TEMPLATES


@router.post("/elastic/hunt-assistant", response_model=HuntAssistantResponse)
def hunt_assistant(body: HuntAssistantRequest, db: Session = Depends(get_db)):
    """
    Match a free-text investigation intent to a hunt template.
    Returns the best-matching template with full analyst guidance.
    If case_id is provided, records the hunt in the case timeline.
    """
    intent_lower = body.intent.lower()
    matched_id: str = HUNT_TEMPLATES[0]["id"]
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

    template = next(
        (t for t in HUNT_TEMPLATES if t["id"] == matched_id), HUNT_TEMPLATES[0]
    )

    if body.case_id:
        case = db.query(Case).filter(Case.id == body.case_id).first()
        if case:
            db.add(TimelineEvent(
                case_id=body.case_id,
                timestamp=datetime.utcnow(),
                event_type="hunt_generated",
                description=f"Hunt query generated: {template['title']}",
                source="elastic",
                severity="info",
            ))
            db.commit()

    return HuntAssistantResponse(**template, matched_by=matched_by)


# ── Helpers ───────────────────────────────────────────────────────────────────

_HIGH_SIGNAL_CODES = {"4625", "4648", "4697", "4688", "4719", "4732", "4756"}
_MED_SIGNAL_CODES = {"4624", "4720", "4726", "4740"}


def _event_severity(event_code: str, event_category: str) -> str:
    if event_code in _HIGH_SIGNAL_CODES:
        return "high"
    if event_code in _MED_SIGNAL_CODES:
        return "medium"
    if "authentication" in event_category:
        return "medium"
    return "info"


def _event_label(event_code: str, event_category: str, evt: dict) -> str:
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
    base = labels.get(
        event_code,
        f"Elastic event {event_code}" if event_code else "Elastic event",
    )
    parts = [base]
    if evt.get("user_name"):
        parts.append(f"user={evt['user_name']}")
    if evt.get("host_name"):
        parts.append(f"host={evt['host_name']}")
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
