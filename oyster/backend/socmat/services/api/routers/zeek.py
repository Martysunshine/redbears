"""
Zeek network log analysis endpoints.

POST /cases/{case_id}/analyze/zeek  — run analysis on an evidence file
GET  /cases/{case_id}/analyze/zeek  — list results for a case
"""

import json
import sys
from datetime import datetime as _dt
from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.zeek.parser import detect_log_type, parse_zeek_log  # noqa: E402
from socmat.integrations.zeek.analyzer import (  # noqa: E402
    analyze_conn_log,
    analyze_dns_log,
    analyze_http_log,
    compute_risk_score,
    generate_summary,
)

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.zeek_schema import (
    DnsSummary,
    HttpSummary,
    NetworkAnalysisResponse,
    TopTalker,
    ZeekFinding,
    ZeekScanRequest,
)

router = APIRouter(tags=["zeek"])


@router.post("/cases/{case_id}/analyze/zeek", response_model=NetworkAnalysisResponse)
def run_zeek_analysis(
    case_id: int,
    body: ZeekScanRequest,
    db: Session = Depends(get_db),
):
    """Analyze a Zeek network log file. File is never executed."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    ev = db.query(Evidence).filter(
        Evidence.id == body.evidence_id,
        Evidence.case_id == case_id,
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence file not found in this case")

    if not Path(ev.storage_path).exists():
        raise HTTPException(status_code=404, detail="Evidence file missing from storage")

    # ── parse ─────────────────────────────────────────────────────────────────
    log_type = detect_log_type(ev.original_filename)
    _, records = parse_zeek_log(ev.storage_path)

    findings: list = []
    summary_data: dict = {}

    if log_type == 'conn':
        data = analyze_conn_log(records)
        findings = data['findings']
        summary_data = {'top_talkers': data['top_talkers']}
    elif log_type == 'dns':
        data = analyze_dns_log(records)
        findings = data['findings']
        summary_data = {
            'dns_summary': {
                'total_queries': data['total_queries'],
                'unique_domains': data['unique_domains'],
                'top_queried': data['top_queried'],
                'suspicious_domains': data['suspicious_domains'],
            }
        }
    elif log_type == 'http':
        data = analyze_http_log(records)
        findings = data['findings']
        summary_data = {
            'http_summary': {
                'total_requests': data['total_requests'],
                'unique_hosts': data['unique_hosts'],
                'top_hosts': data['top_hosts'],
                'suspicious_agents': data['suspicious_agents'],
            }
        }

    risk_score = compute_risk_score(findings)
    summary = generate_summary(ev.original_filename, log_type, len(records), findings, risk_score)

    # ── persist (replace previous result for same evidence file) ─────────────
    db.query(NetworkAnalysisResult).filter(
        NetworkAnalysisResult.case_id == case_id,
        NetworkAnalysisResult.evidence_id == ev.id,
    ).delete(synchronize_session=False)

    row = NetworkAnalysisResult(
        case_id=case_id,
        evidence_id=ev.id,
        log_type=log_type,
        total_records=len(records),
        findings=json.dumps(findings),
        summary_data=json.dumps(summary_data),
        risk_score=risk_score,
        summary=summary,
    )
    db.add(row)
    db.flush()

    if risk_score > 0:
        tl_severity = (
            "critical" if risk_score >= 76
            else "high" if risk_score >= 51
            else "medium" if risk_score >= 26
            else "low"
        )
        te = TimelineEvent(
            case_id=case_id,
            timestamp=_dt.utcnow(),
            source="zeek",
            event_type="Zeek Network Analysis",
            description=summary,
            severity=tl_severity,
            raw_reference=ev.original_filename,
        )
        db.add(te)

    db.commit()
    db.refresh(row)

    return _build_response(row, ev.original_filename)


@router.get("/cases/{case_id}/analyze/zeek", response_model=List[NetworkAnalysisResponse])
def list_zeek_results(case_id: int, db: Session = Depends(get_db)):
    """List all Zeek analysis results for a case, newest first."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    rows = (
        db.query(NetworkAnalysisResult, Evidence.original_filename)
        .join(Evidence, Evidence.id == NetworkAnalysisResult.evidence_id)
        .filter(NetworkAnalysisResult.case_id == case_id)
        .order_by(NetworkAnalysisResult.created_at.desc())
        .all()
    )

    return [_build_response(r, fname) for r, fname in rows]


# ── helper ────────────────────────────────────────────────────────────────────

def _build_response(row: NetworkAnalysisResult, original_filename: str) -> NetworkAnalysisResponse:
    raw_findings: list = json.loads(row.findings or "[]")
    raw_summary: dict = json.loads(row.summary_data or "{}")

    findings = [
        ZeekFinding(
            category=f.get('category', ''),
            severity=f.get('severity', 'low'),
            description=f.get('description', ''),
            host=f.get('host'),
            count=f.get('count'),
            details=f.get('details'),
        )
        for f in raw_findings
    ]

    top_talkers = [TopTalker(**t) for t in raw_summary.get('top_talkers', [])]

    dns_raw = raw_summary.get('dns_summary')
    dns_summary = DnsSummary(**dns_raw) if dns_raw else None

    http_raw = raw_summary.get('http_summary')
    http_summary = HttpSummary(**http_raw) if http_raw else None

    return NetworkAnalysisResponse(
        id=row.id,
        case_id=row.case_id,
        evidence_id=row.evidence_id,
        original_filename=original_filename,
        log_type=row.log_type,
        total_records=row.total_records,
        findings=findings,
        top_talkers=top_talkers,
        dns_summary=dns_summary,
        http_summary=http_summary,
        risk_score=row.risk_score,
        summary=row.summary or "",
        created_at=row.created_at.isoformat(),
    )
