"""Oyster governed MCP gateway.

A single, standards-compliant Model Context Protocol server that exposes a
CURATED, safe subset of Oyster's verified security knowledge and governed tools
to external AI clients (Claude Code and VS Code over stdio; a future ChatGPT
connector over Streamable HTTP).

The gateway is a thin, governed surface over the EXISTING Oyster service layer.
It never duplicates retrieval, authorization or execution logic and it never
exposes raw shell, unrestricted filesystem access, unrestricted networking or a
database session. Read-only knowledge tools run immediately; project analysis
inspects only material the caller is authorized to see; mutating or active
tools return an approval request through Oyster's Execution Engine and never
execute themselves.

See ``docs/MCP_GATEWAY.md`` for the architecture, threat model and setup.
"""

from __future__ import annotations

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "oyster-security"
SERVER_VERSION = "1.0.0"
