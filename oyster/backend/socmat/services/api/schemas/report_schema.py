from typing import Optional
from pydantic import BaseModel


class ReportResponse(BaseModel):
    id: int
    case_id: int
    report_path: str
    format: str
    generated_at: str
    summary: Optional[str] = None
