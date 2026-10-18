from typing import List, Optional
from pydantic import BaseModel


class DetectionFindingResponse(BaseModel):
    id: int
    case_id: int
    rule_id: str
    rule_title: str
    severity: str
    matched_event_id: int
    match_reason: str
    event_id_str: Optional[str]
    event_timestamp: Optional[str]
    created_at: str


class SigmaRunResponse(BaseModel):
    rules_run: int
    events_scanned: int
    findings_created: int
    findings: List[DetectionFindingResponse]
