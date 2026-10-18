"""Scrubbed environment for subprocesses started by MCP/agent tools.

Children used to inherit the backend's full environment, so a tool that could run
`env`/`printenv` (or a script reading os.environ) could read NVIDIA_API_KEY,
Supabase/JWT secrets, MCP tokens, etc. Only an allowlist is passed through; secrets
are never on it. Mirrors services/execution/runner.py::_minimal_env.
"""
import os

_ALLOW = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TZ")


def safe_env() -> dict[str, str]:
    env = {k: os.environ[k] for k in _ALLOW if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
    env.update({k: v for k, v in os.environ.items() if k.startswith("NEXT_PUBLIC_")})
    return env
