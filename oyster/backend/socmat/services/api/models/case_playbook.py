from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from socmat.services.api.database import Base


class CasePlaybook(Base):
    __tablename__ = "case_playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    template_id = Column(Integer, ForeignKey("playbook_templates.id", ondelete="SET NULL"), nullable=True)
    name = Column(String, nullable=False)
    status = Column(String, default="not_started")   # not_started | in_progress | completed
    assigned_to = Column(String, nullable=True)
    progress_percent = Column(Integer, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    steps = relationship(
        "CasePlaybookStep",
        cascade="all, delete-orphan",
        order_by="CasePlaybookStep.step_order",
        backref="playbook",
    )
