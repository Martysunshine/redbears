from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ReplayEvent(BaseModel):
    id: int
    timestamp: str
    order: int
    title: str
    description: str
    source: str
    severity: str
    affected_entities: List[str]
    related_evidence: List[Dict[str, Any]]
    related_findings: List[Dict[str, Any]]
    mitre_mappings: List[Dict[str, Any]]
    analyst_notes: List[Dict[str, Any]]
    explanation: str
    recommended_focus: str


class ReplayMetadata(BaseModel):
    case_id: int
    total_events: int
    sources: List[str]
    severities: List[str]
    date_range: Dict[str, Optional[str]]


class ReplayResponse(BaseModel):
    events: List[ReplayEvent]
    metadata: ReplayMetadata
