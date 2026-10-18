from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class CaseMitreMapping(Base):
    __tablename__ = "case_mitre_mappings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    tactic = Column(String, nullable=False)
    technique_id = Column(String, nullable=False)
    technique_name = Column(String, nullable=False)
    evidence_reference = Column(Text, nullable=True)   # JSON list of {source, detail}
    confidence = Column(String, nullable=False, default="medium")  # low | medium | high
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
