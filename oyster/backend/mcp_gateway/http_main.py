"""Oyster MCP gateway — HTTP transport entrypoint.

Runs the Streamable HTTP app under uvicorn, bound to loopback by default. A
network-reachable deployment must set OYSTER_MCP_HTTP_HOST deliberately AND put
a TLS-terminating reverse proxy in front (see docs/MCP_GATEWAY.md); the config
production guard refuses weak static tokens.

    backend/venv/bin/python -m mcp_gateway.http_main
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))


def main() -> int:
    import uvicorn
    import config

    host = config.MCP_HTTP_HOST
    port = config.MCP_HTTP_PORT
    if host not in ("127.0.0.1", "::1", "localhost"):
        print(f"[oyster-mcp-http] WARNING: binding {host}:{port} is NOT loopback. Ensure a TLS "
              f"reverse proxy and real authentication are in place.", file=sys.stderr)
    print(f"[oyster-mcp-http] serving MCP Streamable HTTP on http://{host}:{port}/mcp "
          f"(health: /healthz)", file=sys.stderr)
    uvicorn.run("mcp_gateway.http_app:app", host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
