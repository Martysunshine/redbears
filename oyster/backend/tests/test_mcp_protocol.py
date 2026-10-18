"""MCP gateway — protocol conformance.

initialize / capabilities / tools / resources / prompts, valid + invalid
invocation, unknown method/tool, timeout, and bounded responses. Runs entirely
in-process against the shared protocol layer (no transport, no network).
"""

from __future__ import annotations

import json

import pytest

from mcp_gateway.core import catalogue, protocol
from mcp_gateway.core.identity import Identity


@pytest.fixture
def app_schema():
    from services import project_service, user_prefs
    from services.artifacts import store as art_store
    project_service.init_db()
    user_prefs.init_db()
    art_store.init_db()
    yield


def operator(sub="op-proto"):
    return Identity(oyster={"tier": "admin", "email": "op@x", "sub": sub},
                    transport="stdio", auth_method="local")


def member(sub="mem-proto"):
    return Identity(oyster={"tier": "user", "email": f"{sub}@x", "sub": sub},
                    transport="http", auth_method="supabase")


async def rpc(identity, method, params=None, mid=1):
    return await protocol.handle_rpc(identity, {"jsonrpc": "2.0", "id": mid,
                                                "method": method, "params": params or {}})


async def call_tool(identity, name, arguments=None):
    r = await rpc(identity, "tools/call", {"name": name, "arguments": arguments or {}}, mid=99)
    res = r["result"]
    return res, json.loads(res["content"][0]["text"])


async def test_initialize_reports_protocol_and_server():
    r = await rpc(operator(), "initialize", {"clientInfo": {"name": "c", "version": "1"}})
    result = r["result"]
    assert result["protocolVersion"] == protocol.PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "oyster-security"
    assert "tools" in result["capabilities"]
    assert "resources" in result["capabilities"]
    assert "prompts" in result["capabilities"]
    assert result.get("instructions")


async def test_tools_list_shapes_and_role_filter():
    op = await rpc(operator(), "tools/list")
    tools = op["result"]["tools"]
    assert len(tools) == len(catalogue.CATALOGUE)
    for t in tools:
        assert t["name"] and t["inputSchema"]["type"] == "object"
        assert "oyster.category" in t["annotations"]
    # A member never even sees operator-only scan tools.
    mem = await rpc(member(), "tools/list")
    mem_names = {t["name"] for t in mem["result"]["tools"]}
    assert "request_authorized_scan" not in mem_names
    assert "get_scan_status" not in mem_names
    assert "search_security_knowledge" in mem_names


async def test_resources_and_prompts_list():
    r = await rpc(operator(), "resources/list")
    uris = {x["uri"] for x in r["result"]["resources"]}
    assert "oyster://knowledge/sources" in uris
    p = await rpc(operator(), "prompts/list")
    names = {x["name"] for x in p["result"]["prompts"]}
    assert {"security_review", "explain_finding", "triage_cve"} <= names


async def test_prompts_get_fills_template():
    r = await rpc(operator(), "prompts/get",
                  {"name": "triage_cve", "arguments": {"cve_id": "CVE-2021-44228"}})
    text = r["result"]["messages"][0]["content"]["text"]
    assert "CVE-2021-44228" in text
    assert "chunk_id" in text  # grounding instruction present


async def test_valid_tool_call_returns_structured_result():
    res, data = await call_tool(operator(), "list_knowledge_sources", {})
    assert res["isError"] is False
    assert "structuredContent" in res
    assert "total_sources" in data
    assert res["_meta"]["oyster.correlationId"].startswith("mcp_")


async def test_invalid_schema_is_rejected():
    res, data = await call_tool(operator(), "search_security_knowledge", {"top_k": 5})  # missing query
    assert res["isError"] is True
    assert data["code"] == "invalid_params"


async def test_unknown_tool_is_error_result():
    res, data = await call_tool(operator(), "definitely_not_a_tool", {})
    assert res["isError"] is True
    assert data["code"] == "unknown_tool"


async def test_unknown_method_is_jsonrpc_error():
    r = await rpc(operator(), "totally/unknown")
    assert r["error"]["code"] == protocol.METHOD_NOT_FOUND


async def test_notification_returns_no_response():
    r = await protocol.handle_rpc(operator(),
                                  {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r is None


async def test_timeout_is_reported(monkeypatch):
    import asyncio
    spec = catalogue.by_name("list_knowledge_sources")

    async def _slow(identity, project_id, args):
        await asyncio.sleep(5)
        return {}

    monkeypatch.setattr(spec, "handler", _slow)
    monkeypatch.setattr(spec, "timeout_s", 0.05, raising=False)
    res, data = await call_tool(operator(), "list_knowledge_sources", {})
    assert res["isError"] is True
    assert data["code"] == "timeout"


async def test_response_is_bounded(monkeypatch):
    import config
    from mcp_gateway.core import dispatch
    spec = catalogue.by_name("list_knowledge_sources")

    async def _huge(identity, project_id, args):
        return {"blob": ["x" * 1000 for _ in range(1000)]}

    monkeypatch.setattr(spec, "handler", _huge)
    monkeypatch.setattr(config, "MCP_MAX_RESULT_BYTES", 2000)
    res, data = await call_tool(operator(), "list_knowledge_sources", {})
    assert res["isError"] is False
    assert data.get("_truncated") is True
    assert res["_meta"]["oyster.truncated"] is True
