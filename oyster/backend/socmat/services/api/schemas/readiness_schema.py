from typing import Dict, List
from pydantic import BaseModel


class ReadinessCheck(BaseModel):
    id: str
    section: str
    name: str
    description: str
    status: str   # pass | fail | na
    weight: int
    optional: bool


class SectionScore(BaseModel):
    name: str
    score: float
    achieved: int
    max_score: int


class ReadinessResponse(BaseModel):
    case_id: int
    total_score: float
    grade: str    # poor | fair | good | excellent
    completed_checks: List[ReadinessCheck]
    missing_checks: List[ReadinessCheck]
    na_checks: List[ReadinessCheck]
    warnings: List[str]
    recommendations: List[str]
    section_scores: Dict[str, SectionScore]
    checked_at: str
