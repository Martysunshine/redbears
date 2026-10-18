from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class NetworkAnalysisResult(Base):
    __tablename__ = "network_analysis_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    log_type = Column(String, nullable=False, default="unknown")  # conn | dns | http | unknown
    total_records = Column(Integer, nullable=False, default=0)
    findings = Column(Text, nullable=True)       # JSON list
    summary_data = Column(Text, nullable=True)   # JSON dict: top_talkers, dns_summary, http_summary
    risk_score = Column(Integer, nullable=False, default=0)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
