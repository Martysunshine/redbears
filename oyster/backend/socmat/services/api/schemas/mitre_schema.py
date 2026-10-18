from typing import List
from pydantic import BaseModel


class EvidenceRef(BaseModel):
    source: str   # windows_event | sigma_rule | yara | zeek | suricata | correlation
    detail: str


class MitreTechniqueInfo(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str


class MitreMappingResponse(BaseModel):
    id: int
    case_id: int
    tactic: str
    technique_id: str
    technique_name: str
    evidence_reference: List[EvidenceRef]
    confidence: str
    created_at: str
