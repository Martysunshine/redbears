from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class SplunkEvent(Base):
    __tablename__ = "splunk_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True)
    event_time = Column(String, nullable=True)
    index = Column(String, nullable=True)
    sourcetype = Column(String, nullable=True)
    host = Column(String, nullable=True)
    source = Column(String, nullable=True)
    user = Column(String, nullable=True)
    src_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    event_code = Column(String, nullable=True)
    raw = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
