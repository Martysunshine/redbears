"""Allowlisted shell command execution.

Migrated from the legacy ``backend/tools/command_tools.py`` into the single
unified registry. Behaviour is unchanged: only a small allowlist of base
commands (plus a few compound prefixes) may run, blocked tokens are rejected in
any position, execution is ``shell=False`` with a timeout, and the working
directory is confined to the project root.
"""

from __future__ import annotations
from mcp_server.tools._safe_env import safe_env

import shlex
import subprocess

from .file_tools import _PROJECT_ROOT, _safe_path

# Simple commands whose first token alone determines safety
ALLOWED_BASE_COMMANDS: set[str] = {"ls", "pwd", "cat", "grep", "find"}

# Compound commands allowed in their exact prefix form; extra args are permitted
ALLOWED_COMPOUND_PREFIXES: list[list[str]] = [
    ["npm", "run", "build"],
    ["npm", "test"],
    ["python", "-m", "pytest"],
]

# Tokens that may never appear in any position (base command or argument)
BLOCKED_TOKENS: set[str] = {
    "rm", "sudo", "wget", "curl", "chmod", "chown",
    "ssh", "scp", "nc", "netcat", "ncat", "socat", "telnet", "ftp",
    "bash", "sh", "zsh", "fish", "ksh",
    "python", "python3",  # allowed only via ALLOWED_COMPOUND_PREFIXES
    "pip", "pip3",
    "eval", "exec", "source",
    "dd", "mkfs", "mount", "umount",
    "kill", "killall", "shutdown", "reboot",
    "crontab", "at", "nmap",
}

COMMAND_TIMEOUT = 30  # seconds


def _check_command(tokens: list[str]) -> str | None:
    """Return an error string if the command is not allowed, None if it is safe."""
    if not tokens:
        return "Empty command"

    # Compound prefixes are checked first — they override the blocked-token check
    # for their own base binary (e.g. 'python' is blocked globally but allowed
    # when the full prefix matches ['python', '-m', 'pytest']).
    for prefix in ALLOWED_COMPOUND_PREFIXES:
        if len(tokens) >= len(prefix) and tokens[: len(prefix)] == prefix:
            for tok in tokens[len(prefix):]:
                if tok.lower() in BLOCKED_TOKENS:
                    return f"Argument '{tok}' is not allowed"
            return None

    base = tokens[0].lower()

    if base in BLOCKED_TOKENS:
        return f"Command '{base}' is blocked for safety"

    for tok in tokens[1:]:
        if tok.lower() in BLOCKED_TOKENS:
            return f"Argument '{tok}' is not allowed"

    if base in ALLOWED_BASE_COMMANDS:
        return None

    return (
        f"Command '{base}' is not in the allowed list. "
        f"Allowed: {', '.join(sorted(ALLOWED_BASE_COMMANDS))} "
        f"+ npm run build | npm test | python -m pytest"
    )


def run_safe_command(command: str, cwd: str = ".") -> dict:
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        return {"error": f"Could not parse command: {e}"}

    block_reason = _check_command(tokens)
    if block_reason:
        return {"error": block_reason, "blocked": True}

    try:
        work_dir = _safe_path(cwd)
        if not work_dir.is_dir():
            work_dir = _PROJECT_ROOT
    except ValueError as e:
        return {"error": str(e)}

    try:
        proc = subprocess.run(
            tokens,
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            shell=False,
            env=safe_env(),
        )
        return {
            "command": command,
            "stdout": proc.stdout[:10_000],
            "stderr": proc.stderr[:2_000],
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {COMMAND_TIMEOUT}s", "command": command}
    except Exception as e:
        return {"error": f"run_safe_command failed: {e}", "command": command}
