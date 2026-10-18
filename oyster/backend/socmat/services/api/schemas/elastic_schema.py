from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class ElasticEventResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: Optional[int]
    event_time: Optional[str]
    host_name: Optional[str]
    user_name: Optional[str]
    src_ip: Optional[str]
    dest_ip: Optional[str]
    process_name: Optional[str]
    parent_process_name: Optional[str]
    command_line: Optional[str]
    event_code: Optional[str]
    event_category: Optional[str]
    event_action: Optional[str]
    file_hash_sha256: Optional[str]
    dns_question: Optional[str]
    analyzed_at: str

    model_config = ConfigDict(from_attributes=True)


class ElasticAnalysisResponse(BaseModel):
    evidence_id: int
    total_events: int
    event_categories: List[str]
    top_hosts: List[str]
    timeline_events_added: int
    normalized_events_saved: int


class HuntTemplate(BaseModel):
    id: str
    title: str
    description: str
    kql_query: str
    esql_query: str
    index_pattern: str
    detects: str
    required_ecs_fields: List[str]
    false_positives: List[str]
    recommended_pivots: List[str]


class HuntAssistantRequest(BaseModel):
    intent: str
    case_id: Optional[int] = None


class HuntAssistantResponse(HuntTemplate):
    matched_by: str
