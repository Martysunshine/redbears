from typing import List, Optional
from pydantic import BaseModel


class TopEntry(BaseModel):
    value: str
    count: int


class SuricataFinding(BaseModel):
    severity: str
    description: str
    src_ip: str = ""
    dest_ip: str = ""
    signature: str = ""


class SuricataAnalysisResponse(BaseModel):
    evidence_id: int
    total_alerts: int
    unique_signatures: int
    top_src_ips: List[TopEntry]
    top_dest_ips: List[TopEntry]
    top_signatures: List[TopEntry]
    suspicious_findings: List[SuricataFinding]
    timeline_events_added: int
    normalized_events_saved: int
