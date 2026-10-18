from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ElasticStatusResponse(BaseModel):
    configured: bool
    connected: bool
    cluster_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    warning: str


class ElasticLiveSearchRequest(BaseModel):
    esql_query: str = Field(..., min_length=1, max_length=4000)
    case_id: Optional[int] = None
    index_pattern: Optional[str] = Field(default=None, max_length=255)
    max_results: int = Field(default=50, ge=1, le=500)


class ElasticLiveTemplateRunRequest(BaseModel):
    case_id: Optional[int] = None
    max_results: int = Field(default=50, ge=1, le=500)


class ElasticLiveQueryResponse(BaseModel):
    id: int
    case_id: Optional[int]
    esql_query: str
    template_id: Optional[str]
    index_pattern: Optional[str]
    max_results: int
    result_count: int
    result_sample: Optional[str]
    status: str
    error_message: Optional[str]
    elastic_host: Optional[str]
    executed_at: str
    warning: str
