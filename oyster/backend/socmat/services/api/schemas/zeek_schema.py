from typing import List, Optional
from pydantic import BaseModel


class ZeekFinding(BaseModel):
    category: str
    severity: str
    description: str
    host: Optional[str] = None
    count: Optional[int] = None
    details: Optional[str] = None


class TopTalker(BaseModel):
    host: str
    connection_count: int
    total_bytes: int
    destinations: int


class DnsSummary(BaseModel):
    total_queries: int
    unique_domains: int
    top_queried: List[str]
    suspicious_domains: List[str]


class HttpSummary(BaseModel):
    total_requests: int
    unique_hosts: int
    top_hosts: List[str]
    suspicious_agents: List[str]


class NetworkAnalysisResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int
    original_filename: str
    log_type: str
    total_records: int
    findings: List[ZeekFinding]
    top_talkers: List[TopTalker]
    dns_summary: Optional[DnsSummary] = None
    http_summary: Optional[HttpSummary] = None
    risk_score: int
    summary: str
    created_at: str


class ZeekScanRequest(BaseModel):
    evidence_id: int
