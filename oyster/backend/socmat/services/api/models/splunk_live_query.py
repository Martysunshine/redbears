from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
from socmat.services.api.database import Base


class SplunkLiveQuery(Base):
    __tablename__ = "splunk_live_queries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    spl_query = Column(Text, nullable=False)
    template_id = Column(String(100), nullable=True)
    earliest_time = Column(String(50), nullable=True)
    latest_time = Column(String(50), nullable=True)
    result_count = Column(Integer, default=0)
    result_sample = Column(Text, nullable=True)  # JSON string, capped at 20 rows
    status = Column(String(20), default="pending")  # pending | completed | error
    error_message = Column(Text, nullable=True)
    splunk_host = Column(String(255), nullable=True)  # hostname only, token never stored
    executed_at = Column(DateTime, server_default=func.now())
