from typing import List
from pydantic import BaseModel


class AIAnalysisResponse(BaseModel):
    provider: str
    mode: str
    case_id: int
    generated_at: str
    summary: str
    key_evidence: List[str]
    likely_incident_type: str
    confidence: str
    recommended_next_steps: List[str]
    missing_evidence: List[str]
    disclaimer: str
