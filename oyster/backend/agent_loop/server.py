from __future__ import annotations

from fastapi import APIRouter

from .loop import run_agent_loop
from .schemas import AgentLoopRequest, AgentLoopResponse

router = APIRouter(tags=["agent"])


@router.post("/loop", response_model=AgentLoopResponse)
async def agent_loop(request: AgentLoopRequest) -> AgentLoopResponse:
    return await run_agent_loop(request)
