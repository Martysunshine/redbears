"""One-command onboarding for the Oyster MCP gateway.

Turns "connect Oyster to my AI client" into a single guided command. This
package is deliberately separate from ``mcp_gateway`` (the gateway itself is not
modified): it only detects the environment, writes/merges client configuration
safely, and reports what a user must do next.

Modules
-------
core        platform + path resolution, the stdio server-entry builder, and the
            backup / merge / remove / malformed-recovery config engine (pure,
            fully unit-testable)
environment health checks: python, gateway import, knowledge DB, configuration
clients     ClaudeCodeClient + VSCodeClient — detect / install / uninstall /
            status, via the Claude CLI when present, else safe file merge
installer   orchestration across clients for --client all|claude|vscode and the
            install / uninstall / repair / status / dry-run actions
"""

from __future__ import annotations

CLAUDE = "claude"
VSCODE = "vscode"
SERVER_NAME = "oyster-security"
