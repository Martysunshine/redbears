from typing import List, Optional

from pydantic import BaseModel, ConfigDict, field_validator

VALID_IOC_TYPES = frozenset({
    "ipv4", "ipv6", "domain", "url",
    "md5", "sha1", "sha256",
    "email", "hostname", "username",
    "process_name", "file_path", "registry_path",
    "mutex", "port", "user_agent",
})

VALID_CONFIDENCE = frozenset({"low", "medium", "high"})

VALID_TAGS = frozenset({
    "internal", "external", "suspicious",
    "confirmed_malicious", "benign", "needs_review",
})


class IocResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    ioc_type: str
    value: str
    normalized_value: str
    source_type: Optional[str] = None
    source_id: Optional[int] = None
    confidence: str
    tags: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    created_at: str


class ExtractIocsResponse(BaseModel):
    extracted: int
    total: int


class UpdateIocRequest(BaseModel):
    confidence: Optional[str] = None
    tags: Optional[List[str]] = None

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_CONFIDENCE:
            raise ValueError(f"confidence must be one of: {sorted(VALID_CONFIDENCE)}")
        return v

    @field_validator("tags")
    @classmethod
    def check_tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is not None:
            invalid = [t for t in v if t not in VALID_TAGS]
            if invalid:
                raise ValueError(f"Invalid tags: {invalid}. Must be from: {sorted(VALID_TAGS)}")
        return v


class CreateIocRequest(BaseModel):
    ioc_type: str
    value: str
    confidence: str = "medium"
    tags: List[str] = []

    @field_validator("ioc_type")
    @classmethod
    def check_ioc_type(cls, v: str) -> str:
        if v not in VALID_IOC_TYPES:
            raise ValueError(f"ioc_type must be one of: {sorted(VALID_IOC_TYPES)}")
        return v

    @field_validator("confidence")
    @classmethod
    def check_confidence(cls, v: str) -> str:
        if v not in VALID_CONFIDENCE:
            raise ValueError(f"confidence must be one of: {sorted(VALID_CONFIDENCE)}")
        return v

    @field_validator("tags")
    @classmethod
    def check_tags(cls, v: List[str]) -> List[str]:
        invalid = [t for t in v if t not in VALID_TAGS]
        if invalid:
            raise ValueError(f"Invalid tags: {invalid}. Must be from: {sorted(VALID_TAGS)}")
        return v
