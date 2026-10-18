"""MCP/agent tool subprocesses must not inherit backend secrets."""
import subprocess
import sys

from mcp_server.tools._safe_env import safe_env


def test_secrets_not_inherited(monkeypatch):
    for k in ("NVIDIA_API_KEY", "NEMOTRON_RERANK_API_KEY", "OYSTER_SUPABASE_JWT_SECRET", "OYSTER_MCP_HTTP_TOKENS"):
        monkeypatch.setenv(k, "SECRET-VALUE")
    env = safe_env()
    assert not any("SECRET-VALUE" in v for v in env.values())
    out = subprocess.run([sys.executable, "-c", "import os;print(sorted(k for k in os.environ if 'KEY' in k or 'SECRET' in k or 'TOKEN' in k))"],
                         capture_output=True, text=True, env=env).stdout
    assert out.strip() == "[]"
