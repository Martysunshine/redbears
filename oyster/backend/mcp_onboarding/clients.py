"""Per-client install / uninstall / status adapters.

* ClaudeCodeClient — uses the ``claude`` CLI when present (race-safe, correct for
  the installed version); otherwise merges into ``~/.claude.json`` top-level
  ``mcpServers``. Either way it preserves other servers and is idempotent.
* VSCodeClient — merges into VS Code's user ``mcp.json`` ``servers`` block.

Neither writes into a Git-tracked file, neither stores a secret (the only env
value is an identity label), and neither prints a credential.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import SERVER_NAME, core
from .environment import ACTION, FAIL, PASS


@dataclass
class ClientResult:
    client: str
    action: str
    status: str
    detail: str = ""
    changed: bool = False
    backup: str | None = None
    config_path: str | None = None

    def line(self) -> str:
        base = f"{self.status:<13} [{self.client}] {self.action}"
        if self.detail:
            base += f" — {self.detail}"
        if self.backup:
            base += f" (backup: {Path(self.backup).name})"
        return base


class _FileClient:
    """Shared JSON-file merge behaviour for a client whose config is a file."""

    client = "?"
    container_key = "mcpServers"
    vscode = False

    def __init__(self, config_path: Path, *, local_email: str = "dev-local"):
        self.config_path = Path(config_path)
        self.local_email = local_email

    def detected(self) -> bool:  # overridden
        return True

    def _entry(self) -> dict:
        return core.server_entry(local_email=self.local_email, vscode=self.vscode)

    def install(self, dry_run: bool = False) -> ClientResult:
        data, recovered = core.read_json_or_recover(self.config_path)
        entry = self._entry()
        # Decide the outcome without writing first (needed for dry-run + idempotency).
        preview = dict(data)
        # deep-ish copy of just the container we touch
        container = dict(preview.get(self.container_key) or {})
        preview[self.container_key] = container
        action = core.merge_server(preview, self.container_key, SERVER_NAME, entry)
        note = ""
        if recovered:
            note = f"recovered from malformed config (set aside as {Path(recovered).name}); "
        if action == "unchanged":
            return ClientResult(self.client, "install", PASS,
                                f"{note}already configured (idempotent)",
                                changed=False, config_path=str(self.config_path))
        if dry_run:
            verb = {"added": "add", "replaced": "replace"}.get(action, action)
            return ClientResult(self.client, "install (dry-run)", PASS,
                                f"{note}would {verb} '{SERVER_NAME}' in {self.config_path}",
                                changed=False, config_path=str(self.config_path))
        b = core.backup(self.config_path)
        core.merge_server(data, self.container_key, SERVER_NAME, entry)
        core.write_json(self.config_path, data)
        return ClientResult(self.client, "install", PASS,
                            f"{note}{action} '{SERVER_NAME}' (other servers preserved)",
                            changed=True, backup=b, config_path=str(self.config_path))

    def uninstall(self, dry_run: bool = False) -> ClientResult:
        data, _ = core.read_json_or_recover(self.config_path)
        if not core.server_present(data, self.container_key, SERVER_NAME):
            return ClientResult(self.client, "uninstall", PASS, "not present (nothing to remove)",
                                config_path=str(self.config_path))
        if dry_run:
            return ClientResult(self.client, "uninstall (dry-run)", PASS,
                                f"would remove '{SERVER_NAME}'", config_path=str(self.config_path))
        b = core.backup(self.config_path)
        core.remove_server(data, self.container_key, SERVER_NAME)
        core.write_json(self.config_path, data)
        return ClientResult(self.client, "uninstall", PASS,
                            f"removed '{SERVER_NAME}' (other servers preserved)",
                            changed=True, backup=b, config_path=str(self.config_path))

    def repair(self, dry_run: bool = False) -> ClientResult:
        # Repair = re-assert a correct entry (also fixes a stale/wrong one).
        data, recovered = core.read_json_or_recover(self.config_path)
        if dry_run:
            present = core.server_present(data, self.container_key, SERVER_NAME)
            return ClientResult(self.client, "repair (dry-run)", PASS,
                                f"would rewrite '{SERVER_NAME}' entry (currently "
                                f"{'present' if present else 'absent'})",
                                config_path=str(self.config_path))
        b = core.backup(self.config_path)
        core.merge_server(data, self.container_key, SERVER_NAME, self._entry())
        core.write_json(self.config_path, data)
        note = "recovered malformed config; " if recovered else ""
        return ClientResult(self.client, "repair", PASS, f"{note}re-wrote correct entry",
                            changed=True, backup=b, config_path=str(self.config_path))

    def status(self) -> ClientResult:
        if not self.detected():
            return ClientResult(self.client, "status", ACTION, "client not detected on this machine",
                                config_path=str(self.config_path))
        data, _ = core.read_json_or_recover(self.config_path)
        if core.server_present(data, self.container_key, SERVER_NAME):
            return ClientResult(self.client, "status", PASS, "oyster-security is configured",
                                config_path=str(self.config_path))
        return ClientResult(self.client, "status", ACTION,
                            "oyster-security not configured (run --install)",
                            config_path=str(self.config_path))

    def validate_config(self) -> tuple[bool, str]:
        """Config validity check for the doctor: file parses and the entry, if
        present, points at an existing command + cwd."""
        data, recovered = core.read_json_or_recover(self.config_path)
        if recovered:
            return False, "config was malformed (set aside)"
        if not core.server_present(data, self.container_key, SERVER_NAME):
            return False, "oyster-security not configured"
        entry = data[self.container_key][SERVER_NAME]
        cmd = entry.get("command", "")
        cwd = entry.get("cwd", "")
        if cmd and not Path(cmd).exists():
            return False, f"command path missing: {cmd}"
        if cwd and not Path(cwd).exists():
            return False, f"cwd missing: {cwd}"
        return True, "entry valid; command + cwd exist"


class VSCodeClient(_FileClient):
    client = "vscode"
    container_key = "servers"
    vscode = True

    def __init__(self, config_path: Path | None = None, *, local_email: str = "dev-local"):
        super().__init__(config_path or core.vscode_user_mcp_path(), local_email=local_email)

    def detected(self) -> bool:
        return core.vscode_present()


class ClaudeCodeClient(_FileClient):
    client = "claude"
    container_key = "mcpServers"
    vscode = False

    def __init__(self, config_path: Path | None = None, *, local_email: str = "dev-local",
                 use_cli: bool = True, scope: str = "user"):
        super().__init__(config_path or core.claude_user_config_path(), local_email=local_email)
        self._cli = core.claude_cli() if use_cli else None
        self.scope = scope

    def detected(self) -> bool:
        return bool(self._cli) or self.config_path.exists()

    # -- CLI helpers ----------------------------------------------------------
    def _run(self, args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run([self._cli, "mcp", *args], cwd=str(core.BACKEND_DIR),
                              capture_output=True, text=True, timeout=timeout)

    def install(self, dry_run: bool = False) -> ClientResult:
        if not self._cli:
            return super().install(dry_run)  # file merge into ~/.claude.json
        entry = self._entry()
        payload = json.dumps({k: entry[k] for k in ("command", "args", "cwd", "env")})
        if dry_run:
            return ClientResult(self.client, "install (dry-run)", PASS,
                                f"would run: claude mcp add-json {SERVER_NAME} <json> "
                                f"--scope {self.scope}", config_path=str(self.config_path))
        b = core.backup(self.config_path)
        # Idempotent: remove any existing entry, then add (CLI has no upsert).
        self._run(["remove", SERVER_NAME, "--scope", self.scope])
        proc = self._run(["add-json", SERVER_NAME, payload, "--scope", self.scope])
        if proc.returncode != 0:
            return ClientResult(self.client, "install", FAIL,
                                (proc.stderr or proc.stdout or "claude CLI failed").strip()[:200],
                                backup=b, config_path=str(self.config_path))
        return ClientResult(self.client, "install", PASS,
                            f"registered via claude CLI (scope {self.scope}; other servers kept)",
                            changed=True, backup=b, config_path=str(self.config_path))

    def uninstall(self, dry_run: bool = False) -> ClientResult:
        if not self._cli:
            return super().uninstall(dry_run)
        if dry_run:
            return ClientResult(self.client, "uninstall (dry-run)", PASS,
                                f"would run: claude mcp remove {SERVER_NAME} --scope {self.scope}",
                                config_path=str(self.config_path))
        b = core.backup(self.config_path)
        proc = self._run(["remove", SERVER_NAME, "--scope", self.scope])
        ok = proc.returncode == 0 or "No MCP server" in (proc.stderr + proc.stdout)
        return ClientResult(self.client, "uninstall", PASS if ok else FAIL,
                            "removed via claude CLI" if ok else (proc.stderr or "remove failed")[:200],
                            changed=ok, backup=b, config_path=str(self.config_path))

    def repair(self, dry_run: bool = False) -> ClientResult:
        if not self._cli:
            return super().repair(dry_run)
        if dry_run:
            return ClientResult(self.client, "repair (dry-run)", PASS,
                                "would re-register via claude CLI", config_path=str(self.config_path))
        self.uninstall()
        return self.install()

    def status(self) -> ClientResult:
        if not self._cli:
            return super().status()
        proc = self._run(["get", SERVER_NAME])
        out = (proc.stdout + proc.stderr)
        if proc.returncode != 0:
            return ClientResult(self.client, "status", ACTION,
                                "oyster-security not registered (run --install)",
                                config_path=str(self.config_path))
        # `claude mcp get` spawns the server for a health check.
        low = out.lower()
        if "connected" in low or "✓" in out:
            return ClientResult(self.client, "status", PASS,
                                "registered and Claude Code connected to it",
                                config_path=str(self.config_path))
        return ClientResult(self.client, "status", PASS, "registered (see `claude mcp get`)",
                            config_path=str(self.config_path))

    def validate_config(self) -> tuple[bool, str]:
        if not self._cli:
            return super().validate_config()
        proc = self._run(["get", SERVER_NAME])
        if proc.returncode == 0:
            return True, "registered in Claude Code (claude mcp get succeeded)"
        return False, "oyster-security not registered"
