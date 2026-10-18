from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from socmat.services.api.database import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False, default="medium")
    status = Column(String, nullable=False, default="open")
    source = Column(String, nullable=False, default="manual")
    affected_host = Column(String, nullable=True)
    affected_user = Column(String, nullable=True)
    affected_ip = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
