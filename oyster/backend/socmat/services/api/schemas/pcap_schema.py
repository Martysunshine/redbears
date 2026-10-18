from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class PcapScanRequest(BaseModel):
    evidence_id: int


class PcapFinding(BaseModel):
    category: str
    severity: str
    description: str
    host: Optional[str] = None
    details: Optional[str] = None


class PcapTopTalker(BaseModel):
    host: str
    packets: int
    bytes_sent: int
    destinations: int


class PcapDnsQuery(BaseModel):
    src_ip: str
    query: str
    query_type: str


class PcapHttpRequest(BaseModel):
    src_ip: str
    dst_ip: str
    method: str
    host: str
    uri: str
    user_agent: str


class PcapTlsHost(BaseModel):
    host: str
    dst_ip: str


class PcapAnalysisResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int
    original_filename: str
    total_packets: int
    total_bytes: int
    duration_seconds: float
    start_time: Optional[str] = None
    protocol_counts: Dict[str, int]
    top_talkers: List[PcapTopTalker]
    dns_queries: List[PcapDnsQuery]
    http_requests: List[PcapHttpRequest]
    tls_hosts: List[PcapTlsHost]
    findings: List[PcapFinding]
    risk_score: int
    summary: str
    created_at: str
