from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, ConfigDict


class NormalizedEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    evidence_id: int
    timestamp: Optional[datetime]
    source: str
    host: Optional[str]
    user: Optional[str]
    event_id: Optional[str]
    event_name: Optional[str]
    process_name: Optional[str]
    parent_process_name: Optional[str]
    command_line: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[str]
    severity: str
    description: Optional[str]
    created_at: datetime


class SuspiciousFinding(BaseModel):
    event_id: str
    severity: str
    description: str
    host: Optional[str] = None
    user: Optional[str] = None
    count: int = 1


class WindowsAnalysisResponse(BaseModel):
    evidence_id: int
    total_events: int
    events_by_id: Dict[str, int]
    suspicious_findings: List[SuspiciousFinding]
    timeline_events_added: int
    normalized_events_saved: int
