from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text

from socmat.services.api.database import Base


class PlaybookTemplate(Base):
    __tablename__ = "playbook_templates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, default="medium")
    required_data_sources = Column(Text, nullable=True)   # JSON array of strings
    steps_json = Column(Text, nullable=False)              # JSON array of {order, title, description}
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
