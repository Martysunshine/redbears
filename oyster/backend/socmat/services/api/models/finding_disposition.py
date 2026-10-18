from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from socmat.services.api.database import Base


class FindingDisposition(Base):
    __tablename__ = "finding_dispositions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, nullable=False, index=True)
    finding_type = Column(String, nullable=False)
    finding_id = Column(String, nullable=False)
    disposition = Column(String, nullable=False, default="needs_review")
    confidence = Column(String, nullable=False, default="medium")
    reason = Column(Text, nullable=True)
    analyst_name = Column(String, nullable=True)
    follow_up_action = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
