from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from socmat.services.api.database import Base


class Ioc(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    normalized_value = Column(String, nullable=False)
    source_type = Column(String, nullable=True)
    source_id = Column(Integer, nullable=True)
    confidence = Column(String, nullable=False, default="medium")  # low | medium | high
    tags_json = Column(Text, nullable=False, default="[]")         # JSON array of tag strings
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
