"""Oyster MCP gateway — stdio transport.

The local transport for Claude Code and VS Code. Reads newline-delimited
JSON-RPC 2.0 messages from stdin and writes responses to stdout; every
diagnostic goes to stderr so it can never corrupt the protocol stream.

Run it directly:

    backend/venv/bin/python -m mcp_gateway.stdio_main

The caller is trusted as the configured local operator (OYSTER_MCP_LOCAL_EMAIL /
_SUB) — stdio is a process the operator launched on their own machine.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

# Make the backend package importable no matter the CWD the client launches us in.
_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from mcp_gateway.core import protocol  # noqa: E402
from mcp_gateway.core.identity import resolve_stdio_identity  # noqa: E402


def _log(msg: str) -> None:
    print(f"[oyster-mcp-stdio] {msg}", file=sys.stderr, flush=True)


def _write(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> int:
    import config
    identity = resolve_stdio_identity()
    _log(f"ready — protocol {protocol.PROTOCOL_VERSION if hasattr(protocol,'PROTOCOL_VERSION') else ''}"
         f" operator={identity.audit_actor()} enabled={config.MCP_GATEWAY_ENABLED}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        for raw in sys.stdin:
            line = raw.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                _write({"jsonrpc": "2.0", "id": None,
                        "error": {"code": protocol.PARSE_ERROR, "message": "Parse error"}})
                continue
            # A fresh identity object per message keeps client-reported name and
            # correlation id from leaking across calls; auth is fixed (local).
            per_msg = resolve_stdio_identity()
            per_msg.client_name = identity.client_name
            per_msg.client_version = identity.client_version
            try:
                response = loop.run_until_complete(protocol.handle_rpc(per_msg, message))
            except Exception as exc:  # noqa: BLE001
                _log(f"handler crashed: {type(exc).__name__}: {exc}")
                response = {"jsonrpc": "2.0", "id": message.get("id"),
                            "error": {"code": protocol.INTERNAL_ERROR, "message": "Internal error"}}
            # Carry the client info forward once initialize has set it.
            if message.get("method") == "initialize":
                identity.client_name = per_msg.client_name
                identity.client_version = per_msg.client_version
            if response is not None:
                _write(response)
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
        _log("shutdown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
