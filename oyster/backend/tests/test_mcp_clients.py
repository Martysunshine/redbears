"""MCP gateway — client compatibility.

Drives the two transports the way a real client would:

* stdio  — spawn ``python -m mcp_gateway.stdio_main`` as a subprocess, speak
  newline-delimited JSON-RPC, and confirm initialize / tools/list / tools/call.
* HTTP   — a Streamable HTTP client (starlette TestClient) initialises, gets a
  session, lists and calls tools, and cannot reuse another client's session.

These are compatibility tests against the SDK-free implementation, not a launch
of the Claude Code or VS Code applications themselves.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import config

_BACKEND = Path(config.BACKEND_DIR)


def _stdio_env():
    d = Path(tempfile.mkdtemp(prefix="oyster_mcp_stdio_"))
    env = dict(os.environ)
    env.update({
        "OYSTER_DATA_DIR": str(d / "data"),
        "OYSTER_LOGS_DIR": str(d / "logs"),
        "OYSTER_MEMORY_DB": str(d / "data" / "memory.db"),
        "OYSTER_VECTOR_DB_DIR": str(d / "data" / "vector_db"),
    })
    # Pre-create the knowledge schema in that temp DB so a tool call has a table.
    subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0,'.'); "
         "from services.knowledge import store as ks; ks.init_db()"],
        cwd=str(_BACKEND), env=env, check=True, capture_output=True, timeout=90)
    return env


def test_stdio_client_handshake_and_tool_call():
    env = _stdio_env()
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"clientInfo": {"name": "claude-code", "version": "test"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "list_knowledge_sources", "arguments": {}}},
    ]
    stdin = "\n".join(json.dumps(m) for m in messages) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_gateway.stdio_main"],
        cwd=str(_BACKEND), env=env, input=stdin,
        capture_output=True, text=True, timeout=120)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    responses = {}
    for ln in lines:
        obj = json.loads(ln)
        if obj.get("id") is not None:
            responses[obj["id"]] = obj
    assert 1 in responses and responses[1]["result"]["serverInfo"]["name"] == "oyster-security"
    assert 2 in responses and len(responses[2]["result"]["tools"]) >= 1
    assert 3 in responses
    tool_res = responses[3]["result"]
    assert tool_res["isError"] is False
    assert "total_sources" in json.loads(tool_res["content"][0]["text"])


# ── HTTP client ───────────────────────────────────────────────────────────────

def _client(monkeypatch):
    from mcp_gateway import http_app
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS",
                        {"tok-alice-abcdefghij": "alice@x", "tok-bob-abcdefghij": "bob@x"})
    return TestClient(http_app.create_app())


def _init(client, token):
    return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                     "params": {"clientInfo": {"name": "chatgpt", "version": "1"}}},
                       headers={"Authorization": f"Bearer {token}"})


def test_http_initialize_and_tool_call(monkeypatch):
    client = _client(monkeypatch)
    r = _init(client, "tok-alice-abcdefghij")
    assert r.status_code == 200
    sid = r.headers["Mcp-Session-Id"]
    hdrs = {"Authorization": "Bearer tok-alice-abcdefghij", "Mcp-Session-Id": sid}
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=hdrs)
    assert r.status_code == 200 and len(r.json()["result"]["tools"]) >= 1
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": "list_knowledge_sources", "arguments": {}}},
                    headers=hdrs)
    assert r.status_code == 200
    assert r.headers.get("Mcp-Correlation-Id", "").startswith("mcp_")


def test_http_sessions_are_isolated_between_clients(monkeypatch):
    client = _client(monkeypatch)
    a = _init(client, "tok-alice-abcdefghij").headers["Mcp-Session-Id"]
    # Bob cannot reuse Alice's session id.
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
                    headers={"Authorization": "Bearer tok-bob-abcdefghij", "Mcp-Session-Id": a})
    assert r.status_code == 404


def test_http_session_delete_then_reuse_is_rejected(monkeypatch):
    client = _client(monkeypatch)
    sid = _init(client, "tok-alice-abcdefghij").headers["Mcp-Session-Id"]
    hdrs = {"Authorization": "Bearer tok-alice-abcdefghij", "Mcp-Session-Id": sid}
    assert client.request("DELETE", "/mcp", headers=hdrs).status_code == 204
    r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "ping"}, headers=hdrs)
    assert r.status_code == 404


def test_http_get_returns_405(monkeypatch):
    client = _client(monkeypatch)
    r = client.get("/mcp", headers={"Authorization": "Bearer tok-alice-abcdefghij"})
    assert r.status_code == 405
