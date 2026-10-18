from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class SplunkEventResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: Optional[int]
    event_time: Optional[str]
    index: Optional[str]
    sourcetype: Optional[str]
    host: Optional[str]
    source: Optional[str]
    user: Optional[str]
    src_ip: Optional[str]
    dest_ip: Optional[str]
    process_name: Optional[str]
    command_line: Optional[str]
    event_code: Optional[str]
    analyzed_at: str

    model_config = ConfigDict(from_attributes=True)


class SplunkAnalysisResponse(BaseModel):
    evidence_id: int
    total_events: int
    sourcetypes: List[str]
    top_hosts: List[str]
    timeline_events_added: int
    normalized_events_saved: int


class SPLQueryTemplate(BaseModel):
    id: str
    title: str
    description: str
    spl_query: str
    index_sourcetype: str
    detects: str
    expected_fields: List[str]
    false_positives: List[str]
    investigation_steps: List[str]


class SPLQueryAssistantRequest(BaseModel):
    intent: str
    case_id: Optional[int] = None


class SPLQueryAssistantResponse(SPLQueryTemplate):
    matched_by: str
