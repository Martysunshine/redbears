from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class SplunkStatusResponse(BaseModel):
    configured: bool
    connected: bool
    server_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    warning: str


class SplunkLiveSearchRequest(BaseModel):
    spl_query: str = Field(..., min_length=1, max_length=2000)
    case_id: Optional[int] = None
    earliest_time: str = Field(default="-24h", max_length=50)
    latest_time: str = Field(default="now", max_length=50)
    max_results: int = Field(default=50, ge=1, le=500)


class SplunkLiveTemplateRunRequest(BaseModel):
    case_id: Optional[int] = None
    earliest_time: str = Field(default="-24h", max_length=50)
    latest_time: str = Field(default="now", max_length=50)
    max_results: int = Field(default=50, ge=1, le=500)


class SplunkLiveQueryResponse(BaseModel):
    id: int
    case_id: Optional[int]
    spl_query: str
    template_id: Optional[str]
    earliest_time: Optional[str]
    latest_time: Optional[str]
    result_count: int
    result_sample: Optional[str]
    status: str
    error_message: Optional[str]
    splunk_host: Optional[str]
    executed_at: str
    warning: str
