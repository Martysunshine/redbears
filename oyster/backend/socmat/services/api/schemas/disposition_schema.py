from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


VALID_DISPOSITIONS = {
    "needs_review", "true_positive", "false_positive",
    "benign", "suspicious", "escalated", "duplicate", "insufficient_data",
}

VALID_CONFIDENCE = {"low", "medium", "high"}

VALID_FINDING_TYPES = {
    "sigma", "yara", "suricata", "zeek", "splunk",
    "elastic", "pcap", "correlation", "mitre", "timeline",
}


class FindingDispositionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    finding_type: str
    finding_id: str
    disposition: str
    confidence: str
    reason: Optional[str]
    analyst_name: Optional[str]
    follow_up_action: Optional[str]
    created_at: datetime
    updated_at: datetime


class CreateDispositionRequest(BaseModel):
    finding_type: str
    finding_id: str
    disposition: str = "needs_review"
    confidence: str = "medium"
    reason: Optional[str] = None
    analyst_name: Optional[str] = None
    follow_up_action: Optional[str] = None


class UpdateDispositionRequest(BaseModel):
    disposition: Optional[str] = None
    confidence: Optional[str] = None
    reason: Optional[str] = None
    analyst_name: Optional[str] = None
    follow_up_action: Optional[str] = None


class DispositionSummary(BaseModel):
    total: int
    true_positive: int
    false_positive: int
    benign: int
    suspicious: int
    needs_review: int
    escalated: int
    duplicate: int
    insufficient_data: int


class CaseDispositionsResponse(BaseModel):
    case_id: int
    dispositions: List[FindingDispositionResponse]
    summary: DispositionSummary
