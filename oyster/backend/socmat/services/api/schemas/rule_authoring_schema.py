from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class RuleAuthorRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=2000)
    event_type: Optional[str] = None
    example_fields: Optional[Dict[str, str]] = None


class RuleDraftResponse(BaseModel):
    event_type_detected: str
    event_type_label: str
    keyword_extracted: str
    sigma_yaml: str
    spl_query: str
    kql_query: str
    esql_query: str
    false_positives: List[str]
    log_source_notes: List[str]
    validation_warnings: List[str]
    quality_disclaimer: str


class EventTypeOption(BaseModel):
    value: str
    label: str
