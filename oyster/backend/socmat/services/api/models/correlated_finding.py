from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class CorrelatedFinding(Base):
    __tablename__ = "correlated_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    confidence = Column(String, nullable=False, default="medium")  # low | medium | high
    entities = Column(Text, nullable=True)            # JSON list of {type, value}
    related_event_ids = Column(Text, nullable=True)   # JSON list of NormalizedEvent.id
    related_finding_ids = Column(Text, nullable=True) # JSON list of analysis result IDs
    summary = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
