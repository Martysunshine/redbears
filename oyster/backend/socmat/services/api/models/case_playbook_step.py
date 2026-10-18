from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from socmat.services.api.database import Base


class CasePlaybookStep(Base):
    __tablename__ = "case_playbook_steps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_playbook_id = Column(Integer, ForeignKey("case_playbooks.id", ondelete="CASCADE"), nullable=False)
    step_order = Column(Integer, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="pending")   # pending | done | skipped | needs_review
    analyst_notes = Column(Text, nullable=True)
    evidence_reference = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
