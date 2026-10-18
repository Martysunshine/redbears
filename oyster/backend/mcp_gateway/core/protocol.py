"""MCP protocol layer — JSON-RPC 2.0 method handling, transport-agnostic.

Given a parsed JSON-RPC message and an already-authenticated :class:`Identity`,
this returns the JSON-RPC response dict (or ``None`` for a notification). It
implements the MCP methods Oyster supports: ``initialize``, ``ping``,
``tools/list``, ``tools/call``, ``resources/list``, ``resources/read``,
``prompts/list`` and ``prompts/get``. Everything else is a clean
``method not found``.

Authentication and transport concerns (bearer tokens, origins, rate limits,
sessions) live in the transport entrypoints; by the time a message reaches here
the caller is known.
"""

from __future__ import annotations

import json

import config
import log_config

from .. import PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION
from . import catalogue, dispatch, prompts, resources, security
from .identity import Identity

# tools/call already enforces MCP_GATEWAY_ENABLED itself, inside
# dispatch.dispatch() — that check stays as-is (it returns a CallToolResult
# with isError=true, the MCP-appropriate shape for a tool-execution-level
# refusal, not a protocol-level error). resources/* and prompts/* never went
# through dispatch() at all — resources.read_resource() and prompts.get_prompt()
# are called directly below — so they bypassed the kill-switch ENTIRELY: with
# the gateway "disabled", an operator would still get real project names,
# knowledge-pack metadata and prompt templates back. This closes exactly that
# gap, for exactly those four methods; initialize/ping/tools/list/tools/call
# are unaffected.
_GATED_BY_KILL_SWITCH = {"resources/list", "resources/read", "prompts/list", "prompts/get"}

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# Application-defined (JSON-RPC reserves -32000..-32099 for this).
GATEWAY_DISABLED = -32000

_SERVER_INFO = {"name": SERVER_NAME, "title": "Oyster Security", "version": SERVER_VERSION}
_CAPABILITIES = {
    "tools": {"listChanged": False},
    "resources": {"listChanged": False, "subscribe": False},
    "prompts": {"listChanged": False},
    "logging": {},
}
_INSTRUCTIONS = (
    "Oyster exposes verified, source-attributed security knowledge and governed "
    "tools. Read-only knowledge tools run immediately and return citations "
    "(cite chunk_id). Project tools see only your own project. Active or "
    "mutating tools (request_authorized_scan, propose_file_change) return an "
    "approval request and never execute — approve them inside Oyster."
)


def _ok(msg_id, result) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code: int, message: str, data=None) -> dict:
    e = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": e}


def _tool_result(structured: dict, *, is_error: bool, correlation_id: str,
                 truncated: bool = False) -> dict:
    """Build an MCP CallToolResult. The text block is the JSON result so any
    client (including text-only ones) can read it; structuredContent carries the
    same data for clients that use it."""
    text = json.dumps(structured, ensure_ascii=False, indent=2, default=str)
    result = {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
        "_meta": {"oyster.correlationId": correlation_id, "oyster.truncated": truncated},
    }
    if not is_error:
        result["structuredContent"] = structured
    return result


async def handle_rpc(identity: Identity, message: dict) -> dict | None:
    """Handle one JSON-RPC request/notification. Returns a response dict, or
    None for a notification (no id)."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _err(message.get("id") if isinstance(message, dict) else None,
                    INVALID_REQUEST, "Invalid JSON-RPC 2.0 message")

    msg_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    is_notification = "id" not in message

    if not isinstance(method, str):
        return None if is_notification else _err(msg_id, INVALID_REQUEST, "Missing method")

    # Notifications — acknowledge silently.
    if method.startswith("notifications/"):
        return None

    # Ensure each request has a fresh correlation id for the audit trail.
    identity.correlation_id = security.new_correlation_id()

    # Gateway kill-switch for resources/* and prompts/* — see
    # _GATED_BY_KILL_SWITCH above for why this exists as a separate check
    # rather than relying on dispatch.dispatch()'s own MCP_GATEWAY_ENABLED gate.
    if not config.MCP_GATEWAY_ENABLED and method in _GATED_BY_KILL_SWITCH:
        log_config.audit("mcp_tool_call", {
            "surface": "mcp_gateway", "transport": identity.transport,
            "actor": identity.audit_actor(), "role": identity.role,
            "tool": method, "audit_category": "protocol",
            "decision": "deny", "status": "disabled", "reason": "gateway disabled",
            "correlation_id": identity.correlation_id,
        })
        if is_notification:
            return None
        return _err(msg_id, GATEWAY_DISABLED, "The Oyster MCP gateway is disabled.")

    try:
        if method == "initialize":
            ci = params.get("clientInfo") or {}
            identity.client_name = str(ci.get("name") or "unknown")[:80]
            identity.client_version = str(ci.get("version") or "unknown")[:40]
            return _ok(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": _CAPABILITIES,
                "serverInfo": _SERVER_INFO,
                "instructions": _INSTRUCTIONS,
            })

        if method == "ping":
            return _ok(msg_id, {})

        if method == "tools/list":
            return _ok(msg_id, {"tools": catalogue.list_public(identity.role)})

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str) or not name:
                return _err(msg_id, INVALID_PARAMS, "tools/call requires a tool name")
            if not isinstance(arguments, dict):
                return _err(msg_id, INVALID_PARAMS, "arguments must be an object")
            outcome = await dispatch.dispatch(identity, name, arguments)
            if outcome.ok:
                return _ok(msg_id, _tool_result(
                    outcome.result, is_error=False,
                    correlation_id=outcome.correlation_id, truncated=outcome.truncated))
            return _ok(msg_id, _tool_result(
                {"error": outcome.error, "code": outcome.error_code},
                is_error=True, correlation_id=outcome.correlation_id))

        if method == "resources/list":
            return _ok(msg_id, {"resources": resources.list_resources()})

        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri:
                return _err(msg_id, INVALID_PARAMS, "resources/read requires a uri")
            contents = await resources.read_resource(identity, uri)
            if contents is None:
                return _err(msg_id, INVALID_PARAMS, f"Unknown resource: {uri}")
            return _ok(msg_id, contents)

        if method == "prompts/list":
            return _ok(msg_id, {"prompts": prompts.list_prompts()})

        if method == "prompts/get":
            name = params.get("name")
            got = prompts.get_prompt(name, params.get("arguments"))
            if got is None:
                return _err(msg_id, INVALID_PARAMS, f"Unknown prompt: {name}")
            return _ok(msg_id, got)

        return _err(msg_id, METHOD_NOT_FOUND, f"Method not found: {method}")
    except Exception as exc:  # noqa: BLE001 — never leak a stack trace to a client
        log_config.error("mcp_gateway.protocol", f"{method} failed", {"error": str(exc)})
        return None if is_notification else _err(msg_id, INTERNAL_ERROR, "Internal error")
