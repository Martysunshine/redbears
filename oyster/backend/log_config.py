"""Unified logging for Oyster.

One module, one place to configure every log channel. Each channel writes
newline-delimited JSON (JSONL) to its own file under ``config.LOGS_DIR``:

    audit   -> audit.log        engagement / scope / workflow events
    tools   -> tool_calls.jsonl every tool invocation (unified registry)
    agent   -> agent.jsonl      agent-loop lifecycle events
    memory  -> memory.jsonl     persistent-memory writes/reads
    errors  -> errors.jsonl     unexpected failures

Historic behaviour is preserved: ``audit`` still writes ``audit.log`` and tool
calls still land in ``tool_calls.jsonl`` with the same JSON shape, so anything
already tailing those files keeps working.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import config

_loggers: dict[str, logging.Logger] = {}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_logger(channel: str) -> logging.Logger:
    """Return (creating once) a JSONL file logger for the given channel."""
    if channel in _loggers:
        return _loggers[channel]

    filename = config.LOG_FILES.get(channel, f"{channel}.jsonl")
    path = config.LOGS_DIR / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)

    logger = logging.getLogger(f"oyster.{channel}")
    if not logger.handlers:
        handler = logging.FileHandler(str(path))
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    _loggers[channel] = logger
    return logger


def _write(channel: str, payload: dict[str, Any]) -> None:
    _get_logger(channel).info(json.dumps(payload))


# ---------------------------------------------------------------------------
# Public channel helpers
# ---------------------------------------------------------------------------

def audit(event: str, details: dict | None = None) -> None:
    """Append an engagement/workflow event to audit.log."""
    _write("audit", {"ts": _ts(), "event": event, **(details or {})})


def log_tool_call(
    tool: str,
    arguments: dict,
    ok: bool,
    *,
    allowed: bool = True,
    reason: str = "ok",
    duration_ms: float = 0.0,
    result_summary: str = "",
    error: str | None = None,
) -> None:
    """Append a single tool invocation to tool_calls.jsonl."""
    _write("tools", {
        "ts": _ts(),
        "tool": tool,
        "arguments": arguments,
        "ok": ok,
        "allowed": allowed,
        "reason": reason,
        "duration_ms": round(duration_ms, 2),
        "result_summary": (result_summary or "")[:200],
        "error": error,
    })


def agent_event(event: str, details: dict | None = None) -> None:
    """Append an agent-loop lifecycle event to agent.jsonl."""
    _write("agent", {"ts": _ts(), "event": event, **(details or {})})


def memory_event(event: str, details: dict | None = None) -> None:
    """Append a persistent-memory event to memory.jsonl."""
    _write("memory", {"ts": _ts(), "event": event, **(details or {})})


def error(where: str, message: str, details: dict | None = None) -> None:
    """Append an error record to errors.jsonl."""
    _write("errors", {"ts": _ts(), "where": where, "message": message, **(details or {})})
