"""The transport-agnostic tool dispatcher.

One code path decides and runs every tool call, whether it arrived over stdio or
HTTP. It enforces, in order:

  1. the gateway kill-switch
  2. tool existence
  3. role authorization (default-deny) — checked on EVERY call, not at login
  4. input-schema validation
  5. per-request project resolution (structural isolation)
  6. a bounded timeout
  7. secret redaction + result-size bounding on the way out
  8. an audit record for the decision and outcome (allow / deny / error /
     timeout), carrying the correlation id but never a secret or a raw argument

The handler in the catalogue only ever runs after steps 1-5 pass.
"""

from __future__ import annotations

import asyncio
import time

import config
import log_config
from services import project_context

from . import catalogue, security
from .identity import Identity
from .validation import SchemaError, validate


class DispatchResult:
    def __init__(self, *, ok: bool, result=None, error: str | None = None,
                 error_code: str | None = None, correlation_id: str = "",
                 duration_ms: float = 0.0, truncated: bool = False):
        self.ok = ok
        self.result = result
        self.error = error
        self.error_code = error_code
        self.correlation_id = correlation_id
        self.duration_ms = duration_ms
        self.truncated = truncated


def _audit(identity: Identity, tool: str, *, decision: str, status: str,
           duration_ms: float, project_id: str | None, reason: str = "",
           audit_category: str = "tool") -> None:
    """Structured audit for every tool decision. Arguments are intentionally not
    logged verbatim (they can contain sensitive project context); the tool name,
    decision, identity, project, timing and correlation id are."""
    payload = {
        "surface": "mcp_gateway",
        "transport": identity.transport,
        "client": f"{identity.client_name}/{identity.client_version}",
        "actor": identity.audit_actor(),
        "role": identity.role,
        "project_id": project_id,
        "tool": tool,
        "audit_category": audit_category,
        "decision": decision,          # allow | deny
        "status": status,              # ok | error | timeout | denied | disabled
        "reason": reason,
        "duration_ms": round(duration_ms, 2),
        "correlation_id": identity.correlation_id,
    }
    log_config.audit("mcp_tool_call", payload)
    log_config.log_tool_call(
        tool=f"mcp:{tool}", arguments={"correlation_id": identity.correlation_id},
        ok=(status == "ok"), allowed=(decision == "allow"), reason=reason or status,
        duration_ms=duration_ms, result_summary=f"{decision}/{status}",
        error=None if status == "ok" else reason,
    )


def _resolve_project(identity: Identity, spec: catalogue.ToolSpec, args: dict) -> str | None:
    if not spec.project_scoped:
        return None
    requested = str(args.get("project_id") or "").strip()
    if requested:
        return project_context.workspace_for_path(identity.oyster, requested)
    return project_context.workspace_id(identity.oyster)


async def dispatch(identity: Identity, tool_name: str, arguments: dict | None) -> DispatchResult:
    cid = identity.correlation_id or security.new_correlation_id()
    identity.correlation_id = cid
    args = arguments or {}
    t0 = time.perf_counter()

    def done(**kw) -> DispatchResult:
        return DispatchResult(correlation_id=cid,
                              duration_ms=(time.perf_counter() - t0) * 1000, **kw)

    if not config.MCP_GATEWAY_ENABLED:
        _audit(identity, tool_name, decision="deny", status="disabled",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=None,
               reason="gateway disabled")
        return done(ok=False, error="The Oyster MCP gateway is disabled.", error_code="disabled")

    spec = catalogue.by_name(tool_name)
    if spec is None:
        _audit(identity, tool_name, decision="deny", status="error",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=None,
               reason="unknown tool")
        return done(ok=False, error=f"Unknown tool '{tool_name}'.", error_code="unknown_tool")

    # Default-deny role check — on every call.
    if identity.role not in spec.permitted_roles:
        _audit(identity, tool_name, decision="deny", status="denied",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=None,
               reason="role not permitted", audit_category=spec.audit_category)
        return done(ok=False, error="You are not authorized to use this tool.",
                    error_code="forbidden")

    # Input validation.
    try:
        validate(spec.input_schema, args)
    except SchemaError as exc:
        _audit(identity, tool_name, decision="deny", status="error",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=None,
               reason="invalid input", audit_category=spec.audit_category)
        return done(ok=False, error=f"Invalid arguments: {exc}", error_code="invalid_params")

    # Per-request project resolution (structural isolation).
    try:
        project_id = _resolve_project(identity, spec, args)
    except Exception as exc:  # project_context raises HTTPException-likes
        _audit(identity, tool_name, decision="deny", status="error",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=None,
               reason="project resolution failed", audit_category=spec.audit_category)
        return done(ok=False, error=f"Cannot resolve project scope: {getattr(exc, 'detail', exc)}",
                    error_code="forbidden")

    # Run the handler under a bounded timeout.
    timeout = spec.timeout_s or config.MCP_TOOL_TIMEOUT_S
    try:
        result = await asyncio.wait_for(spec.handler(identity, project_id, args), timeout=timeout)
    except asyncio.TimeoutError:
        _audit(identity, tool_name, decision="allow", status="timeout",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=project_id,
               reason=f"timed out after {timeout}s", audit_category=spec.audit_category)
        return done(ok=False, error=f"Tool timed out after {timeout}s.", error_code="timeout")
    except Exception as exc:
        # Never leak internals — a stable message, details only to the audit log.
        _audit(identity, tool_name, decision="allow", status="error",
               duration_ms=(time.perf_counter() - t0) * 1000, project_id=project_id,
               reason=f"handler error: {type(exc).__name__}", audit_category=spec.audit_category)
        log_config.error("mcp_gateway", f"{tool_name} handler raised",
                         {"error": str(exc), "correlation_id": cid})
        return done(ok=False, error="The tool failed to complete.", error_code="tool_error")

    # Redact + bound on the way out.
    safe = security.redact(result)
    bounded, truncated = security.bound_result(safe, config.MCP_MAX_RESULT_BYTES)
    _audit(identity, tool_name, decision="allow", status="ok",
           duration_ms=(time.perf_counter() - t0) * 1000, project_id=project_id,
           reason="ok", audit_category=spec.audit_category)
    return done(ok=True, result=bounded, truncated=truncated)
