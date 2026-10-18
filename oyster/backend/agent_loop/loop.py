from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import config
import log_config
from mcp_server.registry import MCP_TOOL_DEFINITIONS
from services import ollama_service

from . import context as agent_memory
from .executor import execute_tool_calls
from .memory import AgentScratchpad
from .planner import create_plan
from .schemas import AgentLoopRequest, AgentLoopResponse, IterationRecord

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load(name: str) -> str:
    p = _PROMPTS_DIR / name
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


def _extract_json(text: str) -> dict | None:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return None


async def run_agent_loop(request: AgentLoopRequest) -> AgentLoopResponse:
    session_id = request.session_id or str(uuid.uuid4())[:8]
    model_key = config.resolve_model(request.model, config.REASONING_MODEL)

    log_config.agent_event("loop_start", {"session_id": session_id, "task": request.task[:200]})

    tools_summary = "\n".join(
        f"- {t['name']} ({t.get('category', 'other')}): {t['description']}"
        for t in MCP_TOOL_DEFINITIONS
    )

    scratchpad = AgentScratchpad(task=request.task)

    # Retrieve prior knowledge (memories, findings, scans, attack surface) and
    # inject it into both planning and per-iteration reasoning.
    memory_context = agent_memory.retrieve_context(request.task, session_id)

    plan_text = await create_plan(request.task, request.model, tools_summary, memory_context)
    scratchpad.plan = plan_text

    iterations: list[IterationRecord] = []
    total_tool_calls = 0
    stop_reason = "max_iterations"
    completed = False

    reasoner_base = _load("reasoner_prompt.txt")
    observer_base = _load("observer_prompt.txt")

    for i in range(1, request.max_iterations + 1):
        # Reason: decide what to do next
        memory_section = f"{memory_context}\n\n" if memory_context else ""
        reasoner_prompt = (
            f"{reasoner_base}\n\n"
            f"{memory_section}"
            f"CURRENT STATE:\n{scratchpad.to_context_string()}\n\n"
            f"AVAILABLE TOOLS:\n{tools_summary}\n\n"
            f"ITERATION: {i} of {request.max_iterations}\n"
            f"TOTAL TOOL CALLS SO FAR: {total_tool_calls}\n\n"
            f"Respond ONLY with valid JSON (no markdown, no explanation outside JSON):\n"
            f'{{"reasoning": "<your reasoning>", "continue": <true|false>, '
            f'"tool_calls": [{{"tool": "<name>", "arguments": {{}}}}]}}'
        )
        raw_reason = await ollama_service.generate(reasoner_prompt, model_key)

        parsed = _extract_json(raw_reason)
        if parsed:
            reasoning = str(parsed.get("reasoning", raw_reason[:400]))
            should_continue = bool(parsed.get("continue", False))
            tool_calls_spec = parsed.get("tool_calls", [])
            if not isinstance(tool_calls_spec, list):
                tool_calls_spec = []
        else:
            reasoning = raw_reason[:400]
            should_continue = False
            tool_calls_spec = []

        # Execute
        tool_records = await execute_tool_calls(tool_calls_spec)
        total_tool_calls += len(tool_records)

        # Observe: summarize what was learned
        if tool_records:
            results_text = "\n\n".join(
                f"Tool: {r.tool}\nResult:\n{json.dumps(r.result, indent=2)[:800]}"
                for r in tool_records
            )
            obs_prompt = (
                f"{observer_base}\n\n"
                f"TASK: {request.task}\n\n"
                f"TOOL RESULTS:\n{results_text}\n\n"
                f"Summarize what was learned. Note any security concerns or findings. Be concise."
            )
            observation = await ollama_service.generate(obs_prompt, model_key)
        else:
            observation = "No tools were called this iteration."

        scratchpad.add_observation(f"Iteration {i}: {observation[:500]}")

        iterations.append(IterationRecord(
            iteration=i,
            reasoning=reasoning,
            tool_calls=tool_records,
            observation=observation,
            should_continue=should_continue,
        ))

        # Persist this iteration's observation + tool outputs to memory
        agent_memory.persist_iteration(session_id, request.task, i, observation, tool_records)

        if not should_continue:
            stop_reason = "agent_decided_complete"
            completed = True
            break

    # Final synthesis
    synthesis_prompt = (
        f"TASK: {request.task}\n\n"
        f"EXECUTION TRACE:\n{scratchpad.to_context_string()}\n\n"
        f"Total iterations: {len(iterations)}. Total tool calls: {total_tool_calls}.\n\n"
        f"Generate a comprehensive final security report covering:\n"
        f"1. Executive Summary\n"
        f"2. Key Findings\n"
        f"3. Recommendations\n"
        f"4. Suggested Next Steps"
    )
    final_answer = await ollama_service.generate(synthesis_prompt, model_key)

    # Persist the final synthesis so future runs can build on it
    agent_memory.persist_final(session_id, request.task, final_answer)
    log_config.agent_event(
        "loop_end",
        {"session_id": session_id, "iterations": len(iterations),
         "tool_calls": total_tool_calls, "stop_reason": stop_reason},
    )

    return AgentLoopResponse(
        task=request.task,
        session_id=session_id,
        iterations=iterations,
        final_answer=final_answer,
        total_tool_calls=total_tool_calls,
        model=request.model,
        completed=completed,
        stop_reason=stop_reason,
    )
