"""Shared adapter result type + execution context."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AdapterContext:
    """Everything an adapter is allowed to know about its run."""
    target: str
    scope: dict
    timeout_seconds: int
    max_output_bytes: int
    parameters: dict = field(default_factory=dict)


@dataclass
class AdapterResult:
    """Uniform result across python + subprocess adapters."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    tool_version: str | None = None
    parsed: dict = field(default_factory=dict)
    truncated: bool = False
    error_summary: str | None = None
