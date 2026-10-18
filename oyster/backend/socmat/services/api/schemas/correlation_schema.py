from typing import List
from pydantic import BaseModel


class CorrelationEntity(BaseModel):
    type: str   # hostname | username | ip | hash | domain | process | service | port
    value: str


class CorrelatedFindingResponse(BaseModel):
    id: int
    case_id: int
    title: str
    severity: str
    confidence: str
    entities: List[CorrelationEntity]
    related_event_ids: List[int]
    related_finding_ids: List[int]
    summary: str
    recommended_action: str
    created_at: str
