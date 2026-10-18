from __future__ import annotations

from mcp_server.registry import call_tool

from .schemas import ToolCallRecord

MAX_TOOLS_PER_ITERATION = 5


async def execute_tool_calls(tool_calls_spec: list[dict]) -> list[ToolCallRecord]:
    records: list[ToolCallRecord] = []
    for tc in tool_calls_spec[:MAX_TOOLS_PER_ITERATION]:
        name = tc.get("tool", "")
        args = tc.get("arguments", {})
        if not name:
            continue
        result, duration_ms = await call_tool(name, args)
        ok = "error" not in result
        records.append(ToolCallRecord(
            tool=name,
            arguments=args,
            result=result,
            ok=ok,
            duration_ms=round(duration_ms, 2),
        ))
    return records
