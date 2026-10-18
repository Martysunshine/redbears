from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False)
    timestamp = Column(DateTime, nullable=True)
    source = Column(String, nullable=False, default="windows_logs")
    host = Column(String, nullable=True)
    user = Column(String, nullable=True)
    event_id = Column(String, nullable=True)
    event_name = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    parent_process_name = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    destination_port = Column(String, nullable=True)
    severity = Column(String, nullable=False, default="info")
    description = Column(Text, nullable=True)
    raw_json = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
