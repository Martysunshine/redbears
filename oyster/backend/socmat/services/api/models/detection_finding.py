from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class DetectionFinding(Base):
    __tablename__ = "detection_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(String, nullable=False)
    rule_title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium")
    matched_event_id = Column(
        Integer,
        ForeignKey("normalized_events.id", ondelete="CASCADE"),
        nullable=False,
    )
    match_reason = Column(Text, nullable=False, default="")
    event_id_str = Column(String, nullable=True)
    event_timestamp = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
