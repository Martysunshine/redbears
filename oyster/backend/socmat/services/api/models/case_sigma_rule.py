from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from socmat.services.api.database import Base


class CaseSigmaRule(Base):
    __tablename__ = "case_sigma_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    rule_sigma_id = Column(String, nullable=False)
    rule_title = Column(String, nullable=False)
    rule_level = Column(String, nullable=False, default="medium")
    attached_at = Column(DateTime, nullable=False, default=datetime.utcnow)
