from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from socmat.services.api.database import Base


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, nullable=False)  # enforced in router; no FK needed for perf
    entity_type = Column(String, nullable=False)   # case | evidence | timeline_event | ...
    entity_id = Column(Integer, nullable=True)     # None = case-level note
    note_type = Column(String, nullable=False, default="general")
    body = Column(Text, nullable=False)
    author_name = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
