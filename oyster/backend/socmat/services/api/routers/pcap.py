"""
PCAP network traffic analysis endpoints.

POST /cases/{case_id}/analyze/pcap  — run analysis on an uploaded evidence file
GET  /cases/{case_id}/analyze/pcap  — list results for a case

Files are parsed statically via dpkt. No live capture. No file execution.
"""

import json
import sys
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.pcap.parser import parse_pcap, SAFE_NOTICE  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.pcap_analysis_result import PcapAnalysisResult
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.pcap_schema import (
    PcapScanRequest,
    PcapAnalysisResponse,
    PcapFinding,
    PcapTopTalker,
    PcapDnsQuery,
    PcapHttpRequest,
    PcapTlsHost,
)
from datetime import datetime as _dt

router = APIRouter(tags=["pcap"])

# PCAP file extensions accepted as valid
_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.post("/cases/{case_id}/analyze/pcap", response_model=PcapAnalysisResponse)
def run_pcap_analysis(
    case_id: int,
    body: PcapScanRequest,
    db: Session = Depends(get_db),
):
    """
    Analyse a PCAP or PCAPNG evidence file attached to the given case.
    The file is never executed — bytes only.
    """
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    ev = db.query(Evidence).filter(
        Evidence.id == body.evidence_id,
        Evidence.case_id == case_id,
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence file not found in this case")

    storage_path = Path(ev.storage_path)
    if not storage_path.exists():
        raise HTTPException(status_code=404, detail="Evidence file missing from storage")

    suffix = Path(ev.original_filename).suffix.lower()
    if suffix not in _PCAP_EXTENSIONS:
        raise HTTPException(
            status_code=422,
            detail=(
                f"File '{ev.original_filename}' does not appear to be a PCAP file. "
                f"Expected extensions: {', '.join(sorted(_PCAP_EXTENSIONS))}"
            ),
        )

    # ── parse ─────────────────────────────────────────────────────────────────
    result = parse_pcap(str(storage_path))
    if result.get("error") and result["total_packets"] == 0:
        raise HTTPException(status_code=422, detail=result["error"])

    # ── persist (replace previous result for the same evidence file) ──────────
    db.query(PcapAnalysisResult).filter(
        PcapAnalysisResult.case_id == case_id,
        PcapAnalysisResult.evidence_id == ev.id,
    ).delete(synchronize_session=False)

    row = PcapAnalysisResult(
        case_id=case_id,
        evidence_id=ev.id,
        total_packets=result["total_packets"],
        total_bytes=result["total_bytes"],
        duration_seconds=int(result["duration_seconds"]),
        start_time=result.get("start_time"),
        protocol_counts=json.dumps(result["protocol_counts"]),
        top_talkers=json.dumps(result["top_talkers"]),
        dns_queries=json.dumps(result["dns_queries"]),
        http_requests=json.dumps(result["http_requests"]),
        tls_hosts=json.dumps(result["tls_hosts"]),
        findings=json.dumps(result["findings"]),
        risk_score=result["risk_score"],
        summary=result["summary"],
    )
    db.add(row)
    db.flush()

    # ── add to timeline if there are notable findings ─────────────────────────
    if result["risk_score"] > 0:
        sev = (
            "critical" if result["risk_score"] >= 76
            else "high" if result["risk_score"] >= 51
            else "medium" if result["risk_score"] >= 26
            else "low"
        )
        db.add(TimelineEvent(
            case_id=case_id,
            timestamp=_dt.utcnow(),
            source="pcap",
            event_type="PCAP Network Analysis",
            description=result["summary"],
            severity=sev,
            raw_reference=ev.original_filename,
        ))

    db.commit()
    db.refresh(row)
    return _build_response(row, ev.original_filename)


@router.get("/cases/{case_id}/analyze/pcap", response_model=List[PcapAnalysisResponse])
def list_pcap_results(case_id: int, db: Session = Depends(get_db)):
    """List all PCAP analysis results for a case, newest first."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    rows = (
        db.query(PcapAnalysisResult, Evidence.original_filename)
        .join(Evidence, Evidence.id == PcapAnalysisResult.evidence_id)
        .filter(PcapAnalysisResult.case_id == case_id)
        .order_by(PcapAnalysisResult.created_at.desc())
        .all()
    )
    return [_build_response(r, fname) for r, fname in rows]


# ── helper ────────────────────────────────────────────────────────────────────

def _build_response(row: PcapAnalysisResult, original_filename: str) -> PcapAnalysisResponse:
    def _load(field) -> list:
        return json.loads(field or "[]")

    def _load_dict(field) -> dict:
        return json.loads(field or "{}")

    raw_findings = _load(row.findings)
    raw_talkers = _load(row.top_talkers)
    raw_dns = _load(row.dns_queries)
    raw_http = _load(row.http_requests)
    raw_tls = _load(row.tls_hosts)
    proto_counts = _load_dict(row.protocol_counts)

    return PcapAnalysisResponse(
        id=row.id,
        case_id=row.case_id,
        evidence_id=row.evidence_id,
        original_filename=original_filename,
        total_packets=row.total_packets or 0,
        total_bytes=row.total_bytes or 0,
        duration_seconds=float(row.duration_seconds or 0),
        start_time=row.start_time,
        protocol_counts=proto_counts,
        top_talkers=[PcapTopTalker(**t) for t in raw_talkers],
        dns_queries=[PcapDnsQuery(**q) for q in raw_dns],
        http_requests=[PcapHttpRequest(**h) for h in raw_http],
        tls_hosts=[PcapTlsHost(**t) for t in raw_tls],
        findings=[PcapFinding(**f) for f in raw_findings],
        risk_score=row.risk_score or 0,
        summary=row.summary or "",
        created_at=row.created_at.isoformat() if row.created_at else "",
    )
