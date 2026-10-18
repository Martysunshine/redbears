from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class PlaybookStepResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    step_order: int
    title: str
    description: Optional[str] = None
    status: str
    analyst_notes: Optional[str] = None
    evidence_reference: Optional[str] = None
    created_at: str
    updated_at: str


class CasePlaybookResponse(BaseModel):
    id: int
    case_id: int
    template_id: Optional[int] = None
    name: str
    status: str
    assigned_to: Optional[str] = None
    progress_percent: int
    steps: List[PlaybookStepResponse]
    created_at: str
    updated_at: str


class PlaybookTemplateSummary(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    alert_type: str
    severity: str
    step_count: int


class PlaybookTemplateDetail(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    alert_type: str
    severity: str
    required_data_sources: List[str]
    steps: List[Dict]   # [{order, title, description}]
    step_count: int


class AttachPlaybookRequest(BaseModel):
    template_id: int


class UpdatePlaybookStepRequest(BaseModel):
    status: Optional[str] = None
    analyst_notes: Optional[str] = None
    evidence_reference: Optional[str] = None


class PlaybookSuggestion(BaseModel):
    template_id: int
    name: str
    alert_type: str
    reason: str


class CasePlaybooksListResponse(BaseModel):
    playbooks: List[CasePlaybookResponse]
    suggestions: List[PlaybookSuggestion]
