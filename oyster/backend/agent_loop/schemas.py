from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AgentLoopRequest(BaseModel):
    task: str
    model: str = "deepseek-r1"
    max_iterations: int = Field(default=8, ge=1, le=20)
    session_id: str | None = None


class ToolCallRecord(BaseModel):
    tool: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    ok: bool
    duration_ms: float


class IterationRecord(BaseModel):
    iteration: int
    reasoning: str
    tool_calls: list[ToolCallRecord]
    observation: str
    should_continue: bool


class AgentLoopResponse(BaseModel):
    task: str
    session_id: str
    iterations: list[IterationRecord]
    final_answer: str
    total_tool_calls: int
    model: str
    completed: bool
    stop_reason: str
