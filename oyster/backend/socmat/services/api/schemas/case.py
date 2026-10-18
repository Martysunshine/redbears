from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["open", "investigating", "contained", "escalated", "closed"]
Source = Literal["manual", "windows_logs", "suricata", "zeek", "splunk_export", "elastic_export", "yara"]


class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10_000)
    severity: Severity = "medium"
    status: Status = "open"
    source: Source = "manual"
    affected_host: Optional[str] = Field(default=None, max_length=253)
    affected_user: Optional[str] = Field(default=None, max_length=256)
    affected_ip: Optional[str] = Field(default=None, max_length=45)


class CaseUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=10_000)
    severity: Optional[Severity] = None
    status: Optional[Status] = None
    source: Optional[Source] = None
    affected_host: Optional[str] = Field(default=None, max_length=253)
    affected_user: Optional[str] = Field(default=None, max_length=256)
    affected_ip: Optional[str] = Field(default=None, max_length=45)


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    source: str
    affected_host: Optional[str]
    affected_user: Optional[str]
    affected_ip: Optional[str]
    created_at: datetime
    updated_at: datetime
