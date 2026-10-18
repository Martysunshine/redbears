from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from socmat.services.api.database import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String, nullable=False)           # uuid-prefixed stored name
    original_filename = Column(String, nullable=False)  # as uploaded by user
    file_type = Column(String, nullable=True)           # MIME type
    file_size = Column(Integer, nullable=False)         # bytes
    sha256 = Column(String, nullable=False)
    storage_path = Column(String, nullable=False)
    uploaded_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    notes = Column(Text, nullable=True)
