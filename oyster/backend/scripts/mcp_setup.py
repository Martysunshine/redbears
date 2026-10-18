#!/usr/bin/env python3
"""One-command setup for the Oyster MCP gateway in Claude Code and VS Code.

Typical use:

    # Connect Oyster to every AI client found on this machine:
    python backend/scripts/mcp_setup.py --client all --install

    # See what would happen, change nothing:
    python backend/scripts/mcp_setup.py --client all --install --dry-run

    # Check / repair / remove:
    python backend/scripts/mcp_setup.py --client all --status
    python backend/scripts/mcp_setup.py --client claude --repair
    python backend/scripts/mcp_setup.py --client vscode --uninstall

    # Just print config snippets (no changes):
    python backend/scripts/mcp_setup.py --print

The installer detects the OS and clients, locates Oyster's Python environment,
backs up any existing MCP config, merges the ``oyster-security`` entry WITHOUT
deleting other servers, is idempotent, and never writes a secret. Run
``python backend/scripts/mcp_doctor.py`` afterwards to verify end to end.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from mcp_onboarding import core, installer  # noqa: E402


def _print_snippets(local_email: str) -> None:
    claude = {"mcpServers": {"oyster-security": core.server_entry(local_email=local_email)}}
    vscode = {"servers": {"oyster-security": core.server_entry(local_email=local_email, vscode=True)}}
    print("# Claude Code — add to .mcp.json (project) or ~/.claude.json (user):")
    print(json.dumps(claude, indent=2))
    print("\n# VS Code — add to your user mcp.json (" + str(core.vscode_user_mcp_path()) + "):")
    print(json.dumps(vscode, indent=2))
    print("\n# Or just run:  python backend/scripts/mcp_setup.py --client all --install")


def main() -> int:
    ap = argparse.ArgumentParser(description="Set up Oyster in Claude Code / VS Code.")
    ap.add_argument("--client", choices=["all", "claude", "vscode"], default="all")
    action = ap.add_mutually_exclusive_group()
    action.add_argument("--install", action="store_true", help="Install/merge the Oyster entry.")
    action.add_argument("--uninstall", action="store_true", help="Remove the Oyster entry.")
    action.add_argument("--repair", action="store_true", help="Re-assert a correct entry.")
    action.add_argument("--status", action="store_true", help="Show whether Oyster is configured.")
    action.add_argument("--print", dest="print_only", action="store_true",
                        help="Print config snippets; change nothing.")
    ap.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing.")
    ap.add_argument("--local-email", default="dev-local",
                    help="Identity the local stdio operator authenticates as (audit + projects).")
    ap.add_argument("--no-cli", action="store_true",
                    help="For Claude Code, edit ~/.claude.json directly instead of the claude CLI.")
    args = ap.parse_args()

    if args.print_only or not (args.install or args.uninstall or args.repair or args.status):
        _print_snippets(args.local_email)
        return 0

    act = ("install" if args.install else "uninstall" if args.uninstall
           else "repair" if args.repair else "status")
    rep = installer.run(act, args.client, dry_run=args.dry_run, local_email=args.local_email,
                        use_cli=not args.no_cli)
    print(rep.render())
    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
