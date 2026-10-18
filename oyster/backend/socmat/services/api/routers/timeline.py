import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from socmat.services.api.database import get_db
from socmat.services.api.models.analyst_note import AnalystNote
from socmat.services.api.models.case import Case
from socmat.services.api.models.case_mitre_mapping import CaseMitreMapping
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.evidence import TimelineEventCreate, TimelineEventResponse
from socmat.services.api.schemas.replay_schema import ReplayEvent, ReplayMetadata, ReplayResponse

router = APIRouter(prefix="/cases", tags=["timeline"])


@router.get("/{case_id}/timeline", response_model=List[TimelineEventResponse])
def list_timeline(case_id: int, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    return (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )


@router.post("/{case_id}/timeline", response_model=TimelineEventResponse, status_code=status.HTTP_201_CREATED)
def create_timeline_event(case_id: int, data: TimelineEventCreate, db: Session = Depends(get_db)):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")
    event = TimelineEvent(case_id=case_id, **data.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


@router.get("/{case_id}/timeline/replay", response_model=ReplayResponse)
def get_timeline_replay(
    case_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    source: Optional[str] = Query(None, description="Filter by source"),
    db: Session = Depends(get_db),
):
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    all_events = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )

    filtered = all_events
    if severity:
        filtered = [e for e in filtered if e.severity == severity]
    if source:
        filtered = [e for e in filtered if e.source == source]

    evidence_all = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    det_findings = db.query(DetectionFinding).filter(DetectionFinding.case_id == case_id).all()
    mitre_all = db.query(CaseMitreMapping).filter(CaseMitreMapping.case_id == case_id).all()
    notes_all = (
        db.query(AnalystNote)
        .filter(AnalystNote.case_id == case_id, AnalystNote.entity_type == "timeline_event")
        .all()
    )

    mitre_list = [
        {"technique_id": m.technique_id, "technique_name": m.technique_name, "tactic": m.tactic}
        for m in mitre_all[:8]
    ]

    replay_events: List[ReplayEvent] = []
    for i, ev in enumerate(filtered):
        desc_lower = (ev.description or "").lower()
        raw_lower = (ev.raw_reference or "").lower()

        # Evidence referenced by filename in description or raw_reference
        rel_evidence = [
            {"id": evid.id, "filename": evid.original_filename, "file_type": evid.file_type}
            for evid in evidence_all
            if evid.original_filename.lower() in desc_lower or evid.original_filename.lower() in raw_lower
        ]

        # Detection findings matching by source or keyword in description
        rel_findings = []
        for df in det_findings:
            rule_lower = (df.rule_title or "").lower()
            eid = df.event_id_str or ""
            if (ev.source == "sigma" and eid and eid in desc_lower) or (rule_lower and rule_lower in desc_lower):
                rel_findings.append(
                    {"rule_title": df.rule_title, "severity": df.severity, "match_reason": df.match_reason}
                )
        rel_findings = rel_findings[:5]

        # Analyst notes attached to this timeline event
        ev_notes = [
            {"body": n.body, "note_type": n.note_type, "author": n.author_name or "analyst"}
            for n in notes_all
            if n.entity_id == ev.id
        ]

        ts_str = ev.timestamp.isoformat() if isinstance(ev.timestamp, datetime) else str(ev.timestamp)

        replay_events.append(
            ReplayEvent(
                id=ev.id,
                timestamp=ts_str,
                order=i + 1,
                title=_build_title(ev),
                description=ev.description,
                source=ev.source,
                severity=ev.severity,
                affected_entities=_extract_entities(ev.description),
                related_evidence=rel_evidence,
                related_findings=rel_findings,
                mitre_mappings=mitre_list,
                analyst_notes=ev_notes,
                explanation=_generate_explanation(ev.event_type, ev.source, ev.description),
                recommended_focus=_generate_recommended_focus(ev.event_type, ev.source, ev.severity, ev.description),
            )
        )

    _SEV_ORDER = ["info", "low", "medium", "high", "critical"]
    sources = sorted({e.source for e in filtered})
    severities = sorted(
        {e.severity for e in filtered},
        key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 99,
    )
    first_ts = filtered[0].timestamp.isoformat() if filtered else None
    last_ts = filtered[-1].timestamp.isoformat() if filtered else None

    return ReplayResponse(
        events=replay_events,
        metadata=ReplayMetadata(
            case_id=case_id,
            total_events=len(replay_events),
            sources=sources,
            severities=severities,
            date_range={"start": first_ts, "end": last_ts},
        ),
    )


# ── Replay helpers ──────────────────────────────────────────────────────────────

_TITLE_MAP = {
    "process_creation": "Process Creation",
    "network_connection": "Network Connection",
    "network_traffic": "Network Traffic",
    "logon": "User Logon",
    "logon_success": "Successful Logon",
    "logon_failure": "Failed Logon Attempt",
    "authentication_failure": "Authentication Failure",
    "file_creation": "File Created",
    "file_modification": "File Modified",
    "registry_modification": "Registry Modified",
    "sigma_match": "Sigma Rule Match",
    "yara_match": "YARA Rule Match",
    "suricata_alert": "IDS/IPS Alert",
    "ids_alert": "IDS/IPS Alert",
    "correlation": "Correlated Activity",
    "dns_query": "DNS Query",
    "http_request": "HTTP Request",
    "c2_beacon": "C2 Beaconing",
    "lateral_movement": "Lateral Movement",
    "privilege_escalation": "Privilege Escalation",
    "credential_access": "Credential Access",
    "persistence": "Persistence Mechanism",
    "exfiltration": "Data Exfiltration",
}


def _build_title(ev) -> str:
    et = (ev.event_type or "").lower().replace(" ", "_")
    if et in _TITLE_MAP:
        return _TITLE_MAP[et]
    if ev.event_type:
        return ev.event_type.replace("_", " ").title()
    return f"{ev.source.replace('_', ' ').title()} Event"


def _extract_entities(description: str) -> List[str]:
    entities: List[str] = []
    seen: set = set()

    for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', description):
        if ip not in seen:
            entities.append(ip)
            seen.add(ip)

    # DOMAIN\user or standalone ALLCAPS words that look like hostnames
    for host in re.findall(r'\b[A-Z][A-Z0-9\-]{3,20}\b', description):
        if host not in seen and not host.isdigit():
            entities.append(host)
            seen.add(host)

    # user: something or User: something
    for user in re.findall(r'(?:user|account)[:\s]+([A-Za-z0-9\-_\\@\.]+)', description, re.IGNORECASE):
        if user not in seen:
            entities.append(user)
            seen.add(user)

    return entities[:8]


def _generate_explanation(event_type: str, source: str, description: str) -> str:
    et = (event_type or "").lower()
    src = (source or "").lower()
    desc = (description or "").lower()

    # Authentication
    if "4625" in et or "failed" in et and ("logon" in et or "login" in desc):
        return (
            "A failed authentication event was recorded. This may indicate a user mistake, "
            "expired credentials, or a brute-force attempt against the account."
        )
    if "4624" in et or ("success" in desc and ("login" in desc or "logon" in desc)) or "logon_success" in et:
        return (
            "A successful authentication was recorded. If preceded by failures, "
            "this may indicate a successful account takeover."
        )
    if "logon" in et or "authentication" in et:
        return (
            "An authentication event was recorded. Review the logon type, source IP, "
            "and account name to determine if this is expected activity."
        )

    # PowerShell / execution
    if "powershell" in et or "powershell" in desc:
        return (
            "PowerShell execution was observed. Attackers commonly use PowerShell for download, "
            "execution, and lateral movement. Review the command line for encoded commands or suspicious syntax."
        )
    if "process_creation" in et or "4688" in et or "process" in et:
        return (
            "A process creation event was recorded. Review the parent and child process relationship, "
            "command-line arguments, and execution context for suspicious patterns."
        )

    # C2 / network
    if "c2" in et or ("command" in desc and "control" in desc) or "beacon" in desc or "c2" in desc:
        return (
            "Network communication consistent with command-and-control (C2) activity was detected. "
            "This may indicate a compromised host calling back to attacker infrastructure."
        )
    if "dns" in et or "dns" in desc:
        return (
            "DNS query activity was recorded. Review the queried domain for high entropy, "
            "unusual record types, or patterns consistent with DNS tunneling or C2 beaconing."
        )

    # Detection sources
    if src == "yara" or "yara" in et:
        return (
            "A YARA static analysis rule matched content in an uploaded file. "
            "This indicates the file contains patterns associated with known malware or attacker tools. "
            "Review the matched rule names and file metadata."
        )
    if src == "sigma" or "sigma" in et:
        return (
            "A Sigma detection rule matched a Windows or Sysmon event. "
            "This indicates the event pattern corresponds to a known attack technique. "
            "Review the rule name and the originating event for context."
        )
    if src == "suricata" or "suricata" in et or "ids" in et or "alert" in et:
        return (
            "An IDS/IPS alert was triggered. Network traffic matched a known threat signature. "
            "Review the alert category, source and destination IPs, and protocol for next steps."
        )
    if src == "correlation" or "correlation" in et:
        return (
            "The correlation engine identified a relationship between multiple events or data sources. "
            "Multi-signal activity is more likely to represent a real threat than a single alert."
        )
    if src == "zeek" or "zeek" in et:
        return (
            "Network telemetry was recorded from Zeek. Review this event for anomalous destinations, "
            "connection frequencies, or protocol behaviour that deviates from baseline."
        )

    # File / registry
    if "file" in et:
        return (
            "A file system event was recorded. Review the file path, creating process, "
            "and timestamp to determine whether this represents attacker tool deployment or data staging."
        )
    if "registry" in et:
        return (
            "A registry modification was recorded. Attackers use registry keys for persistence, "
            "defence evasion, and configuration. Review the key path and value for known persistence locations."
        )

    # Lateral movement / privilege
    if "lateral" in desc or "psexec" in desc or "wmi" in desc:
        return (
            "Lateral movement activity was observed. An attacker may be pivoting between systems. "
            "Identify all affected hosts and the credentials or tools used."
        )
    if "privilege" in et or "escalat" in et or "4672" in et:
        return (
            "A privilege escalation or elevated logon event was recorded. "
            "Review whether the account normally holds these privileges and what actions followed."
        )

    return (
        "An investigation event was recorded. Review the event details, source, and severity "
        "in context with surrounding timeline activity to determine significance."
    )


def _generate_recommended_focus(event_type: str, source: str, severity: str, description: str) -> str:
    sev = (severity or "info").lower()
    src = (source or "").lower()
    desc = (description or "").lower()

    if sev == "critical":
        return (
            "Critical-severity event. Prioritise immediate review and consider containment actions. "
            "Cross-reference with correlated findings and MITRE mappings for full attack context."
        )
    if sev == "high":
        return (
            "High-severity event. Review in context with adjacent timeline events. "
            "Check for matching Sigma or YARA findings and consider escalation."
        )
    if src == "correlation":
        return (
            "Review the full correlated finding in the Correlation section. "
            "Cross-reference with MITRE ATT&CK mappings to understand the attack tactic."
        )
    if src == "suricata":
        return (
            "Check the source and destination IP in threat intelligence. "
            "Review related network connections in Zeek logs for corroborating evidence."
        )
    if src == "yara":
        return (
            "Review the matched YARA rule names. Consider submitting the file hash "
            "to a sandbox or threat intelligence platform for deeper analysis."
        )
    if src == "sigma":
        return (
            "Review the Sigma rule that triggered and examine events within ±5 minutes "
            "for related activity on the same host or by the same user."
        )
    if src == "zeek":
        return (
            "Review related Zeek network logs. Check for periodic beaconing intervals "
            "or DNS tunneling indicators in adjacent events."
        )
    if "powershell" in desc or "encoded" in desc:
        return (
            "Decode any base64-encoded content. Review the spawning parent process "
            "and check for subsequent file drops or network connections."
        )

    return (
        "Review this event in context with surrounding timeline activity. "
        "Note any affected entities and pivot to related analysis modules."
    )
