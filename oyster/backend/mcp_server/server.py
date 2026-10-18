from __future__ import annotations

import json
import re

from fastapi import APIRouter

import log_config
from services import ollama_service

from .registry import MCP_TOOL_DEFINITIONS, call_tool
from .schemas import MCPAgentRequest, MCPToolCallRequest

router = APIRouter(tags=["mcp"])


@router.get("/tools")
async def list_mcp_tools():
    categories = sorted({t.get("category", "other") for t in MCP_TOOL_DEFINITIONS})
    return {
        "tools": MCP_TOOL_DEFINITIONS,
        "total": len(MCP_TOOL_DEFINITIONS),
        "categories": categories,
    }


@router.post("/call")
async def call_mcp_tool(request: MCPToolCallRequest):
    result, duration_ms = await call_tool(request.tool, request.arguments)
    ok = "error" not in result
    blocked = result.get("blocked", False)

    log_config.log_tool_call(
        tool=request.tool,
        arguments=request.arguments,
        ok=ok,
        allowed=ok and not blocked,
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


@router.post("/agent")
async def mcp_agent(request: MCPAgentRequest):
    tools_desc = "\n".join(
        f"- {t['name']} ({t.get('category', 'other')}): {t['description']}"
        for t in MCP_TOOL_DEFINITIONS
    )
    plan_prompt = (
        f"You are a security AI agent with access to these tools:\n{tools_desc}\n\n"
        f"TASK: {request.task}\n\n"
        f"Rules:\n"
        f"- Only call tools directly needed for the task\n"
        f"- Maximum 3 tool calls total\n"
        f"- All network tools require scope-authorised targets\n"
        f"- Prefer safe, read-only operations first\n\n"
        f"Respond with ONLY a JSON object (no markdown, no explanation):\n"
        f'{{"reasoning": "<why>", "tool_calls": [{{"tool": "<name>", "arguments": {{...}}}}]}}\n'
        f"If no tool is needed, set tool_calls to an empty array."
    )

    plan_raw = await ollama_service.generate(plan_prompt, request.model)

    tool_results: list[dict] = []
    try:
        match = re.search(r"\{.*\}", plan_raw, re.DOTALL)
        if match:
            plan = json.loads(match.group())
            for tc in plan.get("tool_calls", [])[:3]:
                t_name = tc.get("tool", "")
                t_args = tc.get("arguments", {})
                result, duration_ms = await call_tool(t_name, t_args)
                ok = "error" not in result
                log_config.log_tool_call(
                    tool=t_name,
                    arguments=t_args,
                    ok=ok,
                    allowed=ok and not result.get("blocked", False),
                    reason=result.get("error", "ok") if not ok else "ok",
                    duration_ms=duration_ms,
                    result_summary=str(list(result.keys()))[:200],
                    error=result.get("error") if not ok else None,
                )
                tool_results.append({
                    "tool": t_name,
                    "arguments": t_args,
                    "result": result,
                    "ok": ok,
                    "duration_ms": round(duration_ms, 2),
                })
    except (json.JSONDecodeError, AttributeError):
        pass  # LLM returned non-JSON — zero tool calls, fall through to direct answer

    if tool_results:
        results_text = "\n\n".join(
            f"Tool: {r['tool']}\nResult:\n{json.dumps(r['result'], indent=2)[:2_000]}"
            for r in tool_results
        )
        answer_prompt = (
            f"TASK: {request.task}\n\n"
            f"TOOL RESULTS:\n{results_text}\n\n"
            f"Summarise the findings clearly and concisely. "
            f"Suggest one safe next step if applicable."
        )
    else:
        answer_prompt = (
            f"TASK: {request.task}\n\n"
            f"No tools were invoked. Answer from security knowledge only."
        )

    answer = await ollama_service.generate(answer_prompt, request.model)

    return {
        "task": request.task,
        "tool_calls": tool_results,
        "answer": answer,
        "model": request.model,
    }
