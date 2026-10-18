from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    report_path = Column(String, nullable=False)   # relative path from repo root
    format = Column(String, nullable=False, default="markdown")
    generated_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    summary = Column(Text, nullable=True)
