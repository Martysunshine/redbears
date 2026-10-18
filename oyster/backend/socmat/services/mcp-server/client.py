"""
HTTP client for calling the SOC Copilot FastAPI backend.
Shared tool-call logger — writes structured JSONL entries per tool invocation.

Environment variables:
  MCP_BACKEND_URL — FastAPI backend URL  (default: http://localhost:8000)
  MCP_LOG_FILE    — Path to JSONL log    (default: ./mcp_tool_calls.jsonl)
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

BACKEND_URL = os.getenv("MCP_BACKEND_URL", "http://localhost:8000")
_LOG_FILE = os.getenv("MCP_LOG_FILE", "./mcp_tool_calls.jsonl")
_TIMEOUT = 30.0


def log_tool_call(
    tool_name: str,
    case_id: Optional[int],
    success: bool,
    error: Optional[str] = None,
) -> None:
    """Append one structured entry to the tool call log."""
    entry = {
        "tool_name": tool_name,
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": success,
        "error": error,
    }
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def api_get(path: str) -> Any:
    with httpx.Client(base_url=BACKEND_URL, timeout=_TIMEOUT) as http:
        r = http.get(path)
        r.raise_for_status()
        return r.json()


def api_post(
    path: str,
    body: Optional[dict] = None,
    params: Optional[dict] = None,
) -> Any:
    with httpx.Client(base_url=BACKEND_URL, timeout=_TIMEOUT) as http:
        r = http.post(path, json=body, params=params)
        r.raise_for_status()
        return r.json()
