from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class RuleExplanation(BaseModel):
    summary: str
    log_source: str
    detection_fields: List[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    false_positives: List[str]
    investigation_steps: List[str]


class SigmaRuleResponse(BaseModel):
    id: str
    title: str
    status: str
    description: str
    author: str
    date: str
    modified: str
    level: str
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    falsepositives: List[str]
    references: List[str]
    explanation: Optional[RuleExplanation] = None


class AttachRuleRequest(BaseModel):
    rule_sigma_id: str
    rule_title: str
    rule_level: str = "medium"


class CaseSigmaRuleResponse(BaseModel):
    id: int
    case_id: int
    rule_sigma_id: str
    rule_title: str
    rule_level: str
    attached_at: str
