"""
POST /cases/{case_id}/analyze/suricata

Accepts an evidence_id, reads the stored eve.json file, runs the
Suricata alert parser, saves normalised alert records to the DB,
and adds high-signal findings to the case timeline.
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

from socmat.integrations.suricata.parser import parse_suricata  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.suricata import SuricataAnalysisResponse, SuricataFinding, TopEntry

router = APIRouter(prefix="/cases", tags=["analysis"])


@router.post("/{case_id}/analyze/suricata", response_model=SuricataAnalysisResponse)
def analyze_suricata(
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
        print(f"  [socmat.suricata] evidence {ev.id} unreadable: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail="Could not read the stored evidence file.")

    alerts, findings = parse_suricata(content, ev.original_filename)

    # Build summary counters
    src_counter: Counter = Counter(a["src_ip"] for a in alerts if a["src_ip"])
    dest_counter: Counter = Counter(a["dest_ip"] for a in alerts if a["dest_ip"])
    sig_counter: Counter = Counter(a["signature"] for a in alerts if a["signature"])

    top_src_ips = [TopEntry(value=ip, count=c) for ip, c in src_counter.most_common(10)]
    top_dest_ips = [TopEntry(value=ip, count=c) for ip, c in dest_counter.most_common(10)]
    top_signatures = [TopEntry(value=s, count=c) for s, c in sig_counter.most_common(10)]

    # Deduplicate findings by description
    seen: set = set()
    unique_findings: List[SuricataFinding] = []
    for f in findings:
        if f["description"] not in seen:
            seen.add(f["description"])
            unique_findings.append(SuricataFinding(**f))

    # Replace prior run for same evidence
    db.query(NormalizedEvent).filter(
        NormalizedEvent.case_id == case_id,
        NormalizedEvent.evidence_id == evidence_id,
        NormalizedEvent.source == "suricata",
    ).delete()

    saved = 0
    for a in alerts:
        ne = NormalizedEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            timestamp=a.get("timestamp_dt"),
            source="suricata",
            host=a.get("dest_ip") or None,
            user=None,
            event_id=a.get("signature_id") or None,
            event_name=a.get("signature") or None,
            process_name=a.get("app_proto") or None,
            parent_process_name=None,
            command_line=None,
            source_ip=a.get("src_ip") or None,
            destination_ip=a.get("dest_ip") or None,
            destination_port=a.get("dest_port") or None,
            severity=a.get("severity", "info"),
            description=a.get("category") or a.get("signature") or "Suricata Alert",
            raw_json=a.get("raw") or None,
        )
        db.add(ne)
        saved += 1

    # Add deduplicated findings to timeline
    tl_added = 0
    for f in unique_findings:
        ts = datetime.utcnow()
        # Use the first matching alert's timestamp when available
        for a in alerts:
            if f.signature and a.get("signature") == f.signature and a.get("timestamp_dt"):
                ts = a["timestamp_dt"]
                break
            if not f.signature and a.get("src_ip") == f.src_ip and a.get("timestamp_dt"):
                ts = a["timestamp_dt"]
                break
        te = TimelineEvent(
            case_id=case_id,
            timestamp=ts,
            source="suricata",
            event_type="IDS Alert",
            description=f.description,
            severity=f.severity,
            raw_reference=None,
        )
        db.add(te)
        tl_added += 1

    db.commit()

    return SuricataAnalysisResponse(
        evidence_id=evidence_id,
        total_alerts=len(alerts),
        unique_signatures=len(sig_counter),
        top_src_ips=top_src_ips,
        top_dest_ips=top_dest_ips,
        top_signatures=top_signatures,
        suspicious_findings=unique_findings,
        timeline_events_added=tl_added,
        normalized_events_saved=saved,
    )


@router.get("/{case_id}/analyze/suricata", response_model=List[dict])
def list_suricata_events(case_id: int, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    events = (
        db.query(NormalizedEvent)
        .filter(
            NormalizedEvent.case_id == case_id,
            NormalizedEvent.source == "suricata",
        )
        .order_by(NormalizedEvent.timestamp.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "evidence_id": e.evidence_id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "signature_id": e.event_id,
            "signature": e.event_name,
            "app_proto": e.process_name,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "destination_port": e.destination_port,
            "severity": e.severity,
            "category": e.description,
        }
        for e in events
    ]
