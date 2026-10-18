from typing import Dict, List, Optional
from pydantic import BaseModel


class YaraMatch(BaseModel):
    rule: str
    tags: List[str]
    meta: Dict[str, str]
    strings_matched: List[str]


class SuspiciousStrings(BaseModel):
    powershell: List[str]
    lolbas: List[str]
    base64: List[str]
    urls: List[str]
    ips: List[str]


class MalwareTriageResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int
    original_filename: str
    sha256: Optional[str]
    sha1: Optional[str]
    md5: Optional[str]
    file_type: Optional[str]
    file_size: Optional[int]
    yara_matches: List[YaraMatch]
    suspicious_strings: SuspiciousStrings
    risk_score: int
    summary: str
    created_at: str


class YaraRuleInfo(BaseModel):
    name: str
    tags: List[str]
    meta: Dict[str, str]


class YaraScanRequest(BaseModel):
    evidence_id: int
