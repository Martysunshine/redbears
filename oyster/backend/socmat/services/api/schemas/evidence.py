from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict

TimelineSource = Literal["manual", "windows_logs", "suricata", "zeek", "sigma", "yara", "correlation"]
TimelineSeverity = Literal["info", "low", "medium", "high", "critical"]


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    filename: str
    original_filename: str
    file_type: Optional[str]
    file_size: int
    sha256: str
    uploaded_at: datetime
    notes: Optional[str]


class TimelineEventCreate(BaseModel):
    timestamp: datetime
    source: TimelineSource = "manual"
    event_type: str
    description: str
    severity: TimelineSeverity = "info"
    raw_reference: Optional[str] = None


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    timestamp: datetime
    source: str
    event_type: str
    description: str
    severity: str
    raw_reference: Optional[str]
    created_at: datetime
