from sqlalchemy import Column, Integer, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from socmat.services.api.database import Base


class PcapAnalysisResult(Base):
    __tablename__ = "pcap_analysis_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    total_packets = Column(Integer, default=0)
    total_bytes = Column(Integer, default=0)
    duration_seconds = Column(Integer, default=0)
    start_time = Column(Text, nullable=True)          # ISO timestamp string
    protocol_counts = Column(Text, nullable=True)     # JSON dict
    top_talkers = Column(Text, nullable=True)         # JSON list
    dns_queries = Column(Text, nullable=True)         # JSON list (capped at 200)
    http_requests = Column(Text, nullable=True)       # JSON list (capped at 200)
    tls_hosts = Column(Text, nullable=True)           # JSON list (capped at 100)
    findings = Column(Text, nullable=True)            # JSON list
    risk_score = Column(Integer, default=0)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
