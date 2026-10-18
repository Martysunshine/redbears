from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class ElasticEvent(Base):
    __tablename__ = "elastic_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True)
    event_time = Column(String, nullable=True)
    host_name = Column(String, nullable=True)
    user_name = Column(String, nullable=True)
    src_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    process_name = Column(String, nullable=True)
    parent_process_name = Column(String, nullable=True)
    command_line = Column(Text, nullable=True)
    event_code = Column(String, nullable=True)
    event_category = Column(String, nullable=True)
    event_action = Column(String, nullable=True)
    file_hash_sha256 = Column(String, nullable=True)
    dns_question = Column(String, nullable=True)
    raw = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
