"""
YARA static triage endpoints.

GET  /yara/rules                     — list loaded YARA rules
POST /yara/rules/reload              — reload rules from disk
POST /cases/{case_id}/analyze/yara   — run YARA triage on an evidence file
GET  /cases/{case_id}/analyze/yara   — list triage results for a case
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

from socmat.integrations.yara.loader import (  # noqa: E402
    get_compiled_rules,
    get_rule_metadata,
    load_yara_rules,
    yara_available,
)
from socmat.integrations.yara.scanner import (  # noqa: E402
    compute_hashes,
    compute_risk_score,
    detect_file_type,
    detect_suspicious_strings,
    extract_strings,
    generate_summary,
    run_yara_scan,
)

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.schemas.yara_schema import (
    MalwareTriageResponse,
    SuspiciousStrings,
    YaraMatch,
    YaraRuleInfo,
    YaraScanRequest,
)

router = APIRouter(tags=["yara"])


@router.get("/yara/rules", response_model=List[YaraRuleInfo])
def list_yara_rules():
    return [YaraRuleInfo(**r) for r in get_rule_metadata()]


@router.post("/yara/rules/reload")
def reload_yara_rules():
    rules = load_yara_rules()
    return {"loaded": len(rules), "yara_available": yara_available()}


@router.post("/cases/{case_id}/analyze/yara", response_model=MalwareTriageResponse)
def run_yara_triage(
    case_id: int,
    body: YaraScanRequest,
    db: Session = Depends(get_db),
):
    """
    Run static YARA triage against an uploaded evidence file.
    The file is NEVER executed — all analysis is static.
    """
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    ev = db.query(Evidence).filter(
        Evidence.id == body.evidence_id,
        Evidence.case_id == case_id,
    ).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence file not found in this case")

    file_path = ev.storage_path
    if not Path(file_path).exists():
        raise HTTPException(status_code=404, detail="Evidence file missing from storage")

    # ── static analysis — file is never executed ──────────────────────────────
    hashes = compute_hashes(file_path)
    file_type = detect_file_type(file_path)
    strings = extract_strings(file_path)
    suspicious = detect_suspicious_strings(strings)
    yara_matches = run_yara_scan(file_path, get_compiled_rules())

    risk_score = compute_risk_score(yara_matches, suspicious)
    summary = generate_summary(
        ev.original_filename,
        file_type,
        yara_matches,
        suspicious,
        risk_score,
    )

    # ── persist (replace previous result for this evidence file) ─────────────
    db.query(MalwareTriageResult).filter(
        MalwareTriageResult.case_id == case_id,
        MalwareTriageResult.evidence_id == ev.id,
    ).delete(synchronize_session=False)

    row = MalwareTriageResult(
        case_id=case_id,
        evidence_id=ev.id,
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        file_type=file_type,
        file_size=ev.file_size,
        yara_matches=json.dumps(yara_matches),
        suspicious_strings=json.dumps(suspicious),
        risk_score=risk_score,
        summary=summary,
    )
    db.add(row)
    db.flush()

    # ── add timeline entry when risk_score > 0 ────────────────────────────────
    if risk_score > 0:
        tl_severity = (
            "critical" if risk_score >= 76
            else "high" if risk_score >= 51
            else "medium" if risk_score >= 26
            else "low"
        )
        from datetime import datetime as _dt
        te = TimelineEvent(
            case_id=case_id,
            timestamp=_dt.utcnow(),
            source="yara",
            event_type="YARA Triage",
            description=summary,
            severity=tl_severity,
            raw_reference=ev.original_filename,
        )
        db.add(te)

    db.commit()
    db.refresh(row)

    return _build_response(row, ev.original_filename)


@router.get("/cases/{case_id}/analyze/yara", response_model=List[MalwareTriageResponse])
def list_yara_results(case_id: int, db: Session = Depends(get_db)):
    """List all YARA triage results for a case, ordered newest-first."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    rows = (
        db.query(MalwareTriageResult, Evidence.original_filename)
        .join(Evidence, Evidence.id == MalwareTriageResult.evidence_id)
        .filter(MalwareTriageResult.case_id == case_id)
        .order_by(MalwareTriageResult.created_at.desc())
        .all()
    )

    return [_build_response(r, fname) for r, fname in rows]


# ── helper ────────────────────────────────────────────────────────────────────

def _build_response(row: MalwareTriageResult, original_filename: str) -> MalwareTriageResponse:
    raw_matches: list = json.loads(row.yara_matches or "[]")
    raw_suspicious: dict = json.loads(row.suspicious_strings or "{}")

    yara_matches = [
        YaraMatch(
            rule=m.get("rule", ""),
            tags=m.get("tags", []),
            meta=m.get("meta", {}),
            strings_matched=m.get("strings_matched", []),
        )
        for m in raw_matches
    ]

    suspicious = SuspiciousStrings(
        powershell=raw_suspicious.get("powershell", []),
        lolbas=raw_suspicious.get("lolbas", []),
        base64=raw_suspicious.get("base64", []),
        urls=raw_suspicious.get("urls", []),
        ips=raw_suspicious.get("ips", []),
    )

    return MalwareTriageResponse(
        id=row.id,
        case_id=row.case_id,
        evidence_id=row.evidence_id,
        original_filename=original_filename,
        sha256=row.sha256,
        sha1=row.sha1,
        md5=row.md5,
        file_type=row.file_type,
        file_size=row.file_size,
        yara_matches=yara_matches,
        suspicious_strings=suspicious,
        risk_score=row.risk_score,
        summary=row.summary or "",
        created_at=row.created_at.isoformat(),
    )
