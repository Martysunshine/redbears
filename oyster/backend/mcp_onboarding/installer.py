"""Onboarding orchestration.

Ties pre-flight environment checks to per-client install / uninstall / repair /
status, across ``--client all | claude | vscode``, and produces a plain,
three-state report ending in one clear conclusion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import CLAUDE, VSCODE, core
from .clients import ClaudeCodeClient, ClientResult, VSCodeClient
from .environment import ACTION, FAIL, PASS, preflight


@dataclass
class Report:
    action: str
    which: str
    preflight_lines: list[str] = field(default_factory=list)
    client_results: list[ClientResult] = field(default_factory=list)
    conclusion: str = ""
    ok: bool = True

    def render(self) -> str:
        out = [f"Oyster MCP setup — action: {self.action}, client(s): {self.which}", ""]
        if self.preflight_lines:
            out.append("Environment:")
            out += [f"  {ln}" for ln in self.preflight_lines]
            out.append("")
        out.append("Clients:")
        out += [f"  {r.line()}" for r in self.client_results]
        out.append("")
        out.append(self.conclusion)
        return "\n".join(out)


def _clients(which: str, *, local_email: str, use_cli: bool,
             claude_config=None, vscode_config=None) -> list:
    cl = []
    if which in ("all", CLAUDE):
        cl.append(ClaudeCodeClient(claude_config, local_email=local_email, use_cli=use_cli))
    if which in ("all", VSCODE):
        cl.append(VSCodeClient(vscode_config, local_email=local_email))
    return cl


def run(action: str, which: str = "all", *, dry_run: bool = False,
        local_email: str = "dev-local", use_cli: bool = True,
        claude_config=None, vscode_config=None) -> Report:
    rep = Report(action=action, which=which)

    # Pre-flight only matters for install/repair (status/uninstall don't need it).
    if action in ("install", "repair"):
        checks = preflight()
        rep.preflight_lines = [c.line() for c in checks]
        if any(c.status == FAIL for c in checks):
            rep.ok = False
            rep.conclusion = ("FAIL — the environment has a software problem (see above). Fix it, "
                              "then re-run. Nothing was changed.")
            return rep

    clients = _clients(which, local_email=local_email, use_cli=use_cli,
                        claude_config=claude_config, vscode_config=vscode_config)

    for client in clients:
        detected = client.detected()
        if action in ("install", "repair") and not detected:
            rep.client_results.append(ClientResult(
                client.client, action, ACTION,
                "client not detected on this machine — install it, then re-run",
                config_path=str(client.config_path)))
            continue
        if action == "install":
            rep.client_results.append(client.install(dry_run=dry_run))
        elif action == "uninstall":
            rep.client_results.append(client.uninstall(dry_run=dry_run))
        elif action == "repair":
            rep.client_results.append(client.repair(dry_run=dry_run))
        elif action == "status":
            rep.client_results.append(client.status())
        else:
            raise ValueError(f"unknown action '{action}'")

    rep.ok = not any(r.status == FAIL for r in rep.client_results)
    rep.conclusion = _conclude(action, which, rep, dry_run)
    return rep


def _conclude(action: str, which: str, rep: Report, dry_run: bool) -> str:
    if not rep.ok:
        return ("FAIL — a software problem occurred (see the FAIL line above). "
                "No further action until it is fixed.")
    if dry_run:
        return "Dry run only — no files were changed."
    if action == "uninstall":
        return "Oyster was removed from the selected client(s). Restart the client to apply."
    if action == "status":
        return "Status shown above."
    # install / repair
    ready, action_needed = [], []
    label = {"claude": "Claude Code", "vscode": "VS Code"}
    for r in rep.client_results:
        (ready if r.status == PASS else action_needed).append(label.get(r.client, r.client))
    lines = []
    for name in ready:
        lines.append(f"Oyster is ready in {name} — restart {name}, then look for the "
                     f"'oyster-security' tools.")
    for name in action_needed:
        lines.append(f"{name}: action needed — see the line above (install the client, then "
                     f"re-run this command).")
    if not lines:
        lines.append("No clients selected.")
    return "\n".join(lines)
