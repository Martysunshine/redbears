"""System-level endpoints: model listing and the unified tool/agent surface.

``/tools``, ``/tools/call`` and ``/agent/run`` are backed by the single unified
tool registry (``mcp_server.registry``) — the same registry the MCP server and
the agent loop use.
"""

from __future__ import annotations

import json
import re

from fastapi import APIRouter

import config
import log_config
from mcp_server.registry import MCP_TOOL_DEFINITIONS, call_tool
from models.schemas import AgentRunRequest, ToolCallRequest
from services import ollama_service

router = APIRouter(tags=["system"])


@router.get("/models")
async def list_models():
    return {"models": config.model_list(), "default": config.DEFAULT_MODEL}


@router.get("/tools")
async def list_tools():
    return {"tools": MCP_TOOL_DEFINITIONS, "total": len(MCP_TOOL_DEFINITIONS)}


@router.post("/tools/call")
async def call_tool_endpoint(request: ToolCallRequest):
    result, duration_ms = await call_tool(request.tool, request.arguments)
    ok = "error" not in result
    log_config.log_tool_call(
        request.tool, request.arguments, ok,
        allowed=ok and not result.get("blocked", False),
        reason=result.get("error", "ok") if not ok else "ok",
        duration_ms=duration_ms,
        result_summary=str(list(result.keys()))[:200],
        error=result.get("error") if not ok else None,
    )
    return {
        "ok": ok,
        "tool": request.tool,
        "result": result if ok else {},
        "error": result.get("error") if not ok else None,
        "duration_ms": round(duration_ms, 2),
    }


@router.post("/agent/run")
async def agent_run(request: AgentRunRequest):
    ollama_model = config.resolve_model(request.model)

    # Step 1 — Ask the LLM to select which tools (if any) are needed
    tools_desc = "\n".join(
        f"- {t['name']}: {t['description']}"
        for t in MCP_TOOL_DEFINITIONS
    )
    plan_prompt = (
        f"You are an AI agent with access to these tools:\n{tools_desc}\n\n"
        f"TASK: {request.task}\n\n"
        f"Respond with ONLY a JSON object — no markdown, no explanation:\n"
        f'{{"reasoning": "<why>", "tool_calls": [{{"tool": "<name>", "arguments": {{...}}}}]}}\n'
        f"If no tool is needed, use an empty tool_calls array."
    )
    plan_raw = await ollama_service.generate(plan_prompt, ollama_model)

    # Step 2 — Parse JSON and execute up to 5 tool calls
    tool_results: list[dict] = []
    try:
        json_match = re.search(r"\{.*\}", plan_raw, re.DOTALL)
        if json_match:
            plan = json.loads(json_match.group())
            for tc in plan.get("tool_calls", [])[:5]:
                t_name = tc.get("tool", "")
                t_args = tc.get("arguments", {})
                result, duration_ms = await call_tool(t_name, t_args)
                ok = "error" not in result
                log_config.log_tool_call(
                    t_name, t_args, ok,
                    allowed=ok and not result.get("blocked", False),
                    reason=result.get("error", "ok") if not ok else "ok",
                    duration_ms=duration_ms,
                    result_summary=str(list(result.keys()))[:200],
                    error=result.get("error") if not ok else None,
                )
                tool_results.append({"tool": t_name, "arguments": t_args, "result": result, "ok": ok})
    except (json.JSONDecodeError, AttributeError):
        pass  # LLM returned non-JSON — treat as zero tool calls

    # Step 3 — Synthesize a final answer from the results
    if tool_results:
        results_text = "\n\n".join(
            f"Tool: {r['tool']}\nResult:\n{json.dumps(r['result'], indent=2)[:2_000]}"
            for r in tool_results
        )
        answer_prompt = (
            f"TASK: {request.task}\n\n"
            f"TOOL RESULTS:\n{results_text}\n\n"
            f"Based on the tool results above, give a clear, concise answer."
        )
    else:
        answer_prompt = request.task

    answer = await ollama_service.generate(answer_prompt, ollama_model)

    return {
        "task": request.task,
        "tool_calls": tool_results,
        "answer": answer,
        "model": request.model,
    }
