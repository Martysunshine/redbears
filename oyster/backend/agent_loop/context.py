"""Bridge between the Agent Loop and persistent SQLite memory.

Before the refactor the agent's scratchpad was purely in-RAM and the SQLite
memory subsystem had no callers. This module connects them:

  * ``retrieve_context`` pulls relevant memories, prior findings, recent scan
    history and known attack-surface entries so they can be injected into the
    planner / reasoner prompts.
  * ``persist_iteration`` stores each iteration's observation and any tool
    outputs (scans) back into memory.
  * ``persist_final`` stores the final synthesised summary.

All reads/writes are best-effort: memory is an enhancement, so a failure here
never breaks a run — it is logged to the ``memory`` channel and swallowed.
"""

from __future__ import annotations

from typing import Any

import log_config
from memory import service as memory_service
from services import evidence_service

# argument keys that identify a network/security target on a tool call
_TARGET_KEYS = ("target", "url", "base_url", "endpoint", "host")


def _target_of(arguments: dict) -> str | None:
    for key in _TARGET_KEYS:
        val = arguments.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def retrieve_context(task: str, session_id: str, limit: int = 5) -> str:
    """Build a MEMORY CONTEXT block for injection into planning/reasoning.

    Returns an empty string when there is nothing relevant, so callers can
    inject unconditionally without adding noise to a fresh engagement.
    """
    parts: list[str] = []
    try:
        relevant = memory_service.recall(query=task, limit=limit)
        if relevant:
            parts.append("Relevant memories:")
            for m in relevant:
                parts.append(f"  [{m['type']}] {m['key']}: {m['value'][:160]}")

        findings = evidence_service.list_findings()
        if findings:
            parts.append(f"\nPrevious findings ({len(findings)}):")
            for f in findings[:5]:
                parts.append(f"  [{f.get('severity', 'info').upper()}] {f.get('title', 'untitled')}"
                             f" @ {f.get('endpoint', 'n/a')}")

        surface = memory_service.get_attack_surface()
        if surface:
            parts.append(f"\nKnown attack surface ({len(surface)}):")
            for s in surface[:8]:
                parts.append(f"  [{s['severity'].upper()}] {s['component_type']}: {s['detail'][:120]}")

        recent_scans = memory_service.recall(type="scan", limit=5)
        if recent_scans:
            parts.append(f"\nRecent scan notes ({len(recent_scans)}):")
            for sc in recent_scans:
                parts.append(f"  {sc['key']}: {sc['value'][:120]}")

    except Exception as exc:  # memory is best-effort
        log_config.error("agent_loop.context.retrieve", str(exc), {"session_id": session_id})
        return ""

    if not parts:
        return ""

    log_config.memory_event("agent_retrieve", {"session_id": session_id, "sections": len(parts)})
    return "MEMORY CONTEXT (from previous work — use to inform, not to assume):\n" + "\n".join(parts)


def persist_iteration(
    session_id: str,
    task: str,
    iteration: int,
    observation: str,
    tool_records: list[Any],
) -> None:
    """Store an iteration's observation and any tool outputs into memory."""
    try:
        memory_service.store_note(
            key=f"obs:{task[:48]}#{iteration}",
            value=observation,
            tags=["observation", "agent"],
            session_id=session_id,
        )
        for rec in tool_records:
            arguments = getattr(rec, "arguments", {}) or {}
            target = _target_of(arguments)
            result = getattr(rec, "result", {}) or {}
            tool_name = getattr(rec, "tool", "unknown")
            if target:
                memory_service.log_scan(
                    target=target,
                    tool=tool_name,
                    result=result if isinstance(result, dict) else {"result": str(result)},
                    session_id=session_id,
                )
        log_config.memory_event(
            "agent_store_iteration",
            {"session_id": session_id, "iteration": iteration, "tool_outputs": len(tool_records)},
        )
    except Exception as exc:
        log_config.error("agent_loop.context.persist_iteration", str(exc), {"session_id": session_id})


def persist_final(session_id: str, task: str, final_answer: str) -> None:
    """Store the final synthesised summary into memory."""
    try:
        memory_service.store_note(
            key=f"summary:{task[:56]}",
            value=final_answer,
            tags=["summary", "agent"],
            session_id=session_id,
        )
        log_config.memory_event("agent_store_final", {"session_id": session_id})
    except Exception as exc:
        log_config.error("agent_loop.context.persist_final", str(exc), {"session_id": session_id})
