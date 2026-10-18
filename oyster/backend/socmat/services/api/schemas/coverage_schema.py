from typing import List
from pydantic import BaseModel


class RuleCoverage(BaseModel):
    rule_id: str
    rule_title: str
    rule_type: str
    required_logsource: str
    required_fields: List[str]
    mapped_mitre_techniques: List[str]
    severity: str
    triggered_in_case: bool
    blocked_by_missing_data: bool
    missing_fields: List[str]


class TelemetryGap(BaseModel):
    missing_log_source: str
    why_it_matters: str
    affected_detection_rules: List[str]
    related_mitre_techniques: List[str]
    recommendation: str


class CaseCoverageResponse(BaseModel):
    case_id: int
    rules_triggered: List[RuleCoverage]
    rules_not_triggered: List[RuleCoverage]
    rules_blocked: List[RuleCoverage]
    available_log_sources: List[str]
    missing_log_sources: List[str]
    mitre_covered_techniques: int
    mitre_total_techniques: int
    coverage_percent: float


class RuleCoverageListResponse(BaseModel):
    rules: List[RuleCoverage]
    total_count: int


class TelemetryGapListResponse(BaseModel):
    case_id: int
    gaps: List[TelemetryGap]
    available_log_sources: List[str]
    gap_count: int
