from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

VALID_ENTITY_TYPES = frozenset({
    "case",
    "evidence",
    "timeline_event",
    "normalized_event",
    "detection_finding",
    "malware_triage_result",
    "network_analysis_result",
    "correlated_finding",
    "mitre_mapping",
    "report",
})

VALID_NOTE_TYPES = frozenset({
    "observation",
    "hypothesis",
    "decision",
    "false_positive_reason",
    "escalation_note",
    "report_note",
    "general",
})


class CreateNoteRequest(BaseModel):
    entity_type: str
    entity_id: Optional[int] = None
    note_type: str = "general"
    body: str
    author_name: Optional[str] = None

    @field_validator("entity_type")
    @classmethod
    def check_entity_type(cls, v: str) -> str:
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of: {sorted(VALID_ENTITY_TYPES)}")
        return v

    @field_validator("note_type")
    @classmethod
    def check_note_type(cls, v: str) -> str:
        if v not in VALID_NOTE_TYPES:
            raise ValueError(f"note_type must be one of: {sorted(VALID_NOTE_TYPES)}")
        return v

    @field_validator("body")
    @classmethod
    def check_body(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Note body cannot be empty")
        if len(v) > 10000:
            raise ValueError("Note body must not exceed 10 000 characters")
        return v


class UpdateNoteRequest(BaseModel):
    note_type: Optional[str] = None
    body: Optional[str] = None
    author_name: Optional[str] = None

    @field_validator("note_type")
    @classmethod
    def check_note_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_NOTE_TYPES:
            raise ValueError(f"note_type must be one of: {sorted(VALID_NOTE_TYPES)}")
        return v

    @field_validator("body")
    @classmethod
    def check_body(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("Note body cannot be empty")
            if len(v) > 10000:
                raise ValueError("Note body must not exceed 10 000 characters")
        return v


class AnalystNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    entity_type: str
    entity_id: Optional[int] = None
    note_type: str
    body: str
    author_name: Optional[str] = None
    created_at: str
    updated_at: str
