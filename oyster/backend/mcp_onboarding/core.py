"""Platform paths, the stdio server-entry builder, and the config-merge engine.

Everything here is pure and side-effect-light so it can be unit-tested without a
real client installed and on any OS. The config engine's contract:

* never delete another MCP server — merge only
* back up any file before changing it
* recover from a malformed config by setting it aside (never crash, never lose
  the user's file silently)
* be idempotent — installing twice leaves exactly one Oyster entry
"""

from __future__ import annotations

import json
import platform
import shutil
import sys
from datetime import datetime
from pathlib import Path

from . import SERVER_NAME

# --- Oyster locations --------------------------------------------------------
# mcp_onboarding lives at oyster/backend/mcp_onboarding, so:
BACKEND_DIR = Path(__file__).resolve().parents[1]
OYSTER_ROOT = BACKEND_DIR.parent


def default_python() -> str:
    """The interpreter an MCP client should launch. Prefer the project venv so a
    client works without the user activating anything; fall back to the current
    interpreter."""
    if is_windows():
        cand = BACKEND_DIR / "venv" / "Scripts" / "python.exe"
    else:
        cand = BACKEND_DIR / "venv" / "bin" / "python"
    return str(cand if cand.exists() else Path(sys.executable))


# --- OS detection ------------------------------------------------------------

def os_name() -> str:
    s = platform.system().lower()
    if s.startswith("darwin"):
        return "macos"
    if s.startswith("windows"):
        return "windows"
    if s.startswith("linux"):
        return "linux"
    return s or "unknown"


def is_windows() -> bool:
    return os_name() == "windows"


# --- Client config paths -----------------------------------------------------

def claude_user_config_path() -> Path:
    """Claude Code's user config (holds top-level ``mcpServers``). Same location
    on every OS: the user's home directory."""
    return Path.home() / ".claude.json"


def vscode_user_mcp_path() -> Path:
    """VS Code's user-level MCP config (``servers`` block)."""
    home = Path.home()
    name = os_name()
    if name == "macos":
        base = home / "Library" / "Application Support" / "Code" / "User"
    elif name == "windows":
        import os
        base = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming"))) / "Code" / "User"
    else:
        base = home / ".config" / "Code" / "User"
    return base / "mcp.json"


def claude_cli() -> str | None:
    return shutil.which("claude")


def vscode_present() -> bool:
    if shutil.which("code"):
        return True
    name = os_name()
    if name == "macos":
        return Path("/Applications/Visual Studio Code.app").exists()
    if name == "windows":
        import os
        local = os.environ.get("LOCALAPPDATA", "")
        return bool(local) and (Path(local) / "Programs" / "Microsoft VS Code" / "Code.exe").exists()
    # linux
    return bool(shutil.which("code")) or Path("/usr/share/code").exists()


# --- Server entry builder ----------------------------------------------------

def server_entry(*, local_email: str = "dev-local", vscode: bool = False,
                 python_path: str | None = None, backend_dir: str | None = None) -> dict:
    """The stdio MCP server entry for a client config. No secrets — only an
    identity label and absolute launch paths resolved on this machine."""
    entry = {
        "command": python_path or default_python(),
        "args": ["-m", "mcp_gateway.stdio_main"],
        "cwd": backend_dir or str(BACKEND_DIR),
        "env": {"OYSTER_MCP_LOCAL_EMAIL": local_email},
    }
    if vscode:
        # VS Code wants an explicit transport type; order it first for readability.
        return {"type": "stdio", **entry}
    return entry


def entries_equivalent(a: dict, b: dict) -> bool:
    """True if two server entries mean the same launch (ignoring key order)."""
    def norm(e):
        return {"command": e.get("command"), "args": list(e.get("args") or []),
                "cwd": e.get("cwd"), "env": dict(e.get("env") or {}),
                "type": e.get("type")}
    return norm(a) == norm(b)


# --- Config file engine ------------------------------------------------------

def _ts() -> str:
    return datetime.now().strftime("%Y%m%d%H%M%S")


def read_json_or_recover(path: Path) -> tuple[dict, str | None]:
    """Return (data, recovered_backup_path_or_None).

    Missing file → ({}, None). Malformed file → set it aside as a ``.corrupt``
    backup and return ({}, that_path) so the caller can start clean without
    destroying whatever the user had."""
    if not path.exists():
        return {}, None
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}, None
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("top-level config is not an object")
        return data, None
    except (json.JSONDecodeError, ValueError):
        corrupt = path.with_name(path.name + f".corrupt.{_ts()}")
        shutil.copy2(path, corrupt)
        return {}, str(corrupt)


def backup(path: Path) -> str | None:
    """Copy an existing, non-empty config aside before modifying it. Returns the
    backup path, or None if there was nothing to back up."""
    if path.exists() and path.stat().st_size > 0:
        b = path.with_name(path.name + f".bak.{_ts()}")
        shutil.copy2(path, b)
        return str(b)
    return None


def merge_server(data: dict, container_key: str, name: str, entry: dict) -> str:
    """Insert/replace one server under ``container_key`` without touching others.
    Returns 'added' | 'replaced' | 'unchanged'."""
    container = data.get(container_key)
    if not isinstance(container, dict):
        container = {}
        data[container_key] = container
    if name in container:
        if entries_equivalent(container[name], entry):
            return "unchanged"
        container[name] = entry
        return "replaced"
    container[name] = entry
    return "added"


def remove_server(data: dict, container_key: str, name: str) -> bool:
    container = data.get(container_key)
    if isinstance(container, dict) and name in container:
        del container[name]
        return True
    return False


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def server_present(data: dict, container_key: str, name: str = SERVER_NAME) -> bool:
    container = data.get(container_key)
    return isinstance(container, dict) and name in container
