"""MCP gateway — security boundary.

Covers the controls the gateway owns: secret redaction, path canonicalization
(traversal / absolute / symlink escape), SSRF classification, HTTP
authentication (no anonymous access), per-request project isolation, rate
limiting, origin validation, request-size limits, audit hygiene (no secret in
logs), and the hash-binding the governed-action pipeline relies on.

The deep approval lifecycle (replay / tamper / expired execution) is enforced
by the Execution Engine and covered by test_execution_lifecycle; here we verify
the gateway never executes and that approvals are bound to an exact proposal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import config
from mcp_gateway.core import protocol, security
from mcp_gateway.core.identity import Identity
from mcp_gateway.core.security import PathValidationError, canonical_relative_path


@pytest.fixture
def app_schema():
    from services import project_service, user_prefs
    from services.artifacts import store as art_store
    project_service.init_db()
    user_prefs.init_db()
    art_store.init_db()
    yield


def member(sub):
    return Identity(oyster={"tier": "user", "email": f"{sub}@x", "sub": sub},
                    transport="http", auth_method="supabase")


async def call_tool(identity, name, arguments=None):
    r = await protocol.handle_rpc(identity, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                            "params": {"name": name, "arguments": arguments or {}}})
    res = r["result"]
    return res, json.loads(res["content"][0]["text"])


# ── redaction ───────────────────────────────────────────────────────────────

def test_redaction_covers_common_secret_shapes():
    samples = [
        "AWS key AKIAIOSFODNN7EXAMPLE here",
        "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "Authorization: Bearer eyJhbGciOi.payloadpart.signaturepart",
        "DATABASE_PASSWORD=SuperSecret123!",
        "api_key = sk-abcdefghijklmnopqrstuvwxyz",
    ]
    for s in samples:
        out = security.redact_text(s)
        assert "REDACTED" in out
    assert "AKIAIOSFODNN7EXAMPLE" not in security.redact_text(samples[0])
    assert "SuperSecret123" not in security.redact_text(samples[3])


def test_redact_walks_nested_structures():
    obj = {"a": ["DB_SECRET=hunter2hunter2hunter2", {"b": "AKIAIOSFODNN7EXAMPLE"}]}
    out = security.redact(obj)
    flat = json.dumps(out)
    assert "hunter2" not in flat
    assert "AKIAIOSFODNN7EXAMPLE" not in flat


# ── path canonicalization ─────────────────────────────────────────────────────

def test_path_rejects_traversal_and_absolute(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.txt").write_text("hi")
    assert canonical_relative_path("ok.txt", root) == (root / "ok.txt").resolve()
    for bad in ["../etc/passwd", "/etc/passwd", "~/secret", "a/../../b", "\x00evil"]:
        with pytest.raises(PathValidationError):
            canonical_relative_path(bad, root)


def test_path_rejects_symlink_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "target.txt").write_text("secret")
    link = root / "link"
    link.symlink_to(outside)  # root/link -> outside
    with pytest.raises(PathValidationError):
        canonical_relative_path("link/target.txt", root)


# ── SSRF classification ───────────────────────────────────────────────────────

def test_ssrf_blocks_internal_targets():
    for bad in ["169.254.169.254", "http://169.254.169.254/latest/meta-data",
                "127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1", "http://foo.internal/",
                "::1", "ftp://example.com/x"]:
        internal, _ = security.classify_ssrf(bad)
        assert internal, f"expected {bad} to be refused"


def test_ssrf_allows_public_literal():
    internal, _ = security.classify_ssrf("93.184.216.34")  # example.com's IP range
    assert internal is False


# ── HTTP authentication (no anonymous access) ─────────────────────────────────

def _init_body():
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"clientInfo": {"name": "t", "version": "1"}}}


def test_http_rejects_anonymous_and_bad_tokens(monkeypatch):
    from mcp_gateway import http_app
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS", {"good-token-abcdefghij": "op@x"})
    client = TestClient(http_app.create_app())
    # no auth
    r = client.post("/mcp", json=_init_body())
    assert r.status_code == 401
    # malformed
    r = client.post("/mcp", json=_init_body(), headers={"Authorization": "Basic xyz"})
    assert r.status_code == 401
    # wrong bearer
    r = client.post("/mcp", json=_init_body(), headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    # valid static token
    r = client.post("/mcp", json=_init_body(), headers={"Authorization": "Bearer good-token-abcdefghij"})
    assert r.status_code == 200
    assert r.headers.get("Mcp-Session-Id")
    assert r.json()["result"]["serverInfo"]["name"] == "oyster-security"


def test_http_healthz_is_open_and_minimal():
    from mcp_gateway import http_app
    client = TestClient(http_app.create_app())
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert set(body.keys()) <= {"status", "protocol", "enabled"}  # nothing sensitive


def test_http_origin_validation(monkeypatch):
    from mcp_gateway import http_app
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS", {"good-token-abcdefghij": "op@x"})
    monkeypatch.setattr(config, "MCP_ALLOWED_ORIGINS", [])
    client = TestClient(http_app.create_app())
    hdrs = {"Authorization": "Bearer good-token-abcdefghij", "Origin": "https://evil.example"}
    r = client.post("/mcp", json=_init_body(), headers=hdrs)
    assert r.status_code == 403  # browser origin, not allow-listed


def test_http_rate_limit(monkeypatch):
    from mcp_gateway import http_app
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS", {"good-token-abcdefghij": "op@x"})
    monkeypatch.setattr(config, "MCP_RATE_LIMIT_PER_MIN", 2)
    client = TestClient(http_app.create_app())
    hdrs = {"Authorization": "Bearer good-token-abcdefghij"}
    codes = [client.post("/mcp", json={"jsonrpc": "2.0", "id": i, "method": "ping"},
                         headers=hdrs).status_code for i in range(3)]
    assert codes.count(429) >= 1


def test_http_request_size_limit(monkeypatch):
    from mcp_gateway import http_app
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS", {"good-token-abcdefghij": "op@x"})
    monkeypatch.setattr(config, "MCP_MAX_REQUEST_BYTES", 256)
    client = TestClient(http_app.create_app())
    big = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "x" * 4000}}
    r = client.post("/mcp", json=big, headers={"Authorization": "Bearer good-token-abcdefghij"})
    assert r.status_code == 413


# ── per-request project isolation ─────────────────────────────────────────────

async def test_cross_project_file_isolation(app_schema):
    from services import project_service
    from services.artifacts import store as art_store
    # Owner A's file, in A's personal workspace.
    project_service.ensure_project("u_iso-a", "A ws")
    project_service.set_owner("u_iso-a", "iso-a")
    art = art_store.create("u_iso-a", "notes.txt")
    art_store.update(art["id"], text="alpha content", index_status="indexed")

    # A can read it.
    res, data = await call_tool(member("iso-a"), "read_project_file", {"file_id": art["id"]})
    assert data["found"] is True and data["content"] == "alpha content"

    # B cannot — resolves to B's own workspace; the file is not there.
    res, data = await call_tool(member("iso-b"), "read_project_file", {"file_id": art["id"]})
    assert data["found"] is False

    # B's search sees none of A's files.
    res, data = await call_tool(member("iso-b"), "search_project_files", {"query": "alpha"})
    assert data["total"] == 0


# ── audit hygiene: no secret reaches the logs ─────────────────────────────────

async def test_secret_never_written_to_logs(app_schema):
    from services import project_service
    from services.artifacts import store as art_store
    secret = "DB_PASSWORD=TopSecretValue999"
    project_service.ensure_project("u_sec-a", "S ws")
    project_service.set_owner("u_sec-a", "sec-a")
    art = art_store.create("u_sec-a", "config.env")
    art_store.update(art["id"], text=secret, index_status="indexed")

    res, data = await call_tool(member("sec-a"), "read_project_file", {"file_id": art["id"]})
    assert "TopSecretValue999" not in json.dumps(data)  # redacted in the result

    # And nowhere in the audit / tool-call logs.
    logs_dir = Path(config.LOGS_DIR)
    for name in ("audit.log", "tool_calls.jsonl"):
        p = logs_dir / name
        if p.exists():
            assert "TopSecretValue999" not in p.read_text()


# ── governed pipeline: hash-bound, gateway never executes ─────────────────────

async def test_request_authorized_scan_never_executes(app_schema):
    op = Identity(oyster={"tier": "admin", "email": "op@x", "sub": "gov-op"},
                  transport="stdio", auth_method="local")
    res, data = await call_tool(op, "request_authorized_scan",
                                {"tool": "nmap", "action": "port_scan", "target": "scanme.example.org"})
    assert data.get("executed") is False
    assert data.get("status") in ("awaiting_approval", "blocked", "approved")
    assert data.get("proposal_id")


def test_approval_is_bound_to_exact_proposal_hash():
    from services.execution import service as exec_service
    h1 = exec_service._hash_proposal("nmap", "port_scan", ["a.example"], {"top_ports": 10})
    h2 = exec_service._hash_proposal("nmap", "port_scan", ["a.example"], {"top_ports": 20})
    assert h1 != h2  # tampering parameters changes the hash the approval binds to
    # order-independent for targets, deterministic for identical inputs
    assert h1 == exec_service._hash_proposal("nmap", "port_scan", ["a.example"], {"top_ports": 10})


# ── 2026-09-14 security review (HANDOFF_PRITIKA.md §3.2) — two confirmed gaps ──
#
# The gateway stays dark in production regardless of these tests; they cover
# code that is already merged but not yet network-reachable. See
# oyster/docs/AI_HANDOFF.md "MCP Gateway Security Review" for the full
# question-by-question audit these two fixes came out of.

from mcp_gateway.core.identity import resolve_http_identity  # noqa: E402


def test_static_token_allowlist_enforced_regardless_of_environment_label(monkeypatch):
    """Before the fix: a static token mapped to a non-allow-listed email was
    ONLY refused when config.ENVIRONMENT == "production" (and DISABLE_AUTH was
    False) — an operator who turned real auth on (DISABLE_AUTH=False) but left
    ENVIRONMENT at its "development" default (an easy, silent mistake, and the
    one HANDOFF_PRITIKA.md's Q9 asked about) got NO allow-list enforcement on
    this path at all, unlike the Supabase-JWT path just below it. Confirms the
    two paths now agree."""
    monkeypatch.setattr(config, "DISABLE_AUTH", False)
    monkeypatch.setattr(config, "ENVIRONMENT", "development")  # NOT "production"
    monkeypatch.setattr(config, "ADMIN_EMAILS", {"op@redorca.tech"})
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS",
                        {"not-allow-listed-token-123456": "outsider@example.com"})

    with pytest.raises(Exception) as exc_info:
        resolve_http_identity("Bearer not-allow-listed-token-123456")
    from mcp_gateway.core.identity import AuthError
    assert isinstance(exc_info.value, AuthError)
    assert exc_info.value.code == "forbidden"


def test_static_token_allowlist_still_enforced_in_production_too(monkeypatch):
    # The old ENVIRONMENT=="production" condition still worked for the case it
    # was written for — confirm the fix didn't just move the gap, it closed it.
    monkeypatch.setattr(config, "DISABLE_AUTH", False)
    monkeypatch.setattr(config, "ENVIRONMENT", "production")
    monkeypatch.setattr(config, "ADMIN_EMAILS", {"op@redorca.tech"})
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS",
                        {"not-allow-listed-token-123456": "outsider@example.com"})
    from mcp_gateway.core.identity import AuthError
    with pytest.raises(AuthError):
        resolve_http_identity("Bearer not-allow-listed-token-123456")


def test_static_token_allowlisted_email_still_authenticates(monkeypatch):
    # The fix must not turn into a blanket refusal — an allow-listed email on a
    # static token still authenticates, in any environment, whenever
    # DISABLE_AUTH is False.
    monkeypatch.setattr(config, "DISABLE_AUTH", False)
    monkeypatch.setattr(config, "ENVIRONMENT", "development")
    monkeypatch.setattr(config, "ADMIN_EMAILS", {"op@redorca.tech"})
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS",
                        {"good-token-123456789012": "op@redorca.tech"})
    identity = resolve_http_identity("Bearer good-token-123456789012")
    assert identity.email == "op@redorca.tech"
    assert identity.tier == "admin"


async def test_disabled_gateway_refuses_resources_read(monkeypatch):
    """Before the fix: resources/read and prompts/get never passed through
    dispatch.dispatch() (only tools/call does), so MCP_GATEWAY_ENABLED=False
    had NO effect on them — an operator who flipped the kill-switch off would
    still get real project names and knowledge-pack metadata back."""
    monkeypatch.setattr(config, "MCP_GATEWAY_ENABLED", False)
    identity = member("kill-switch-test")
    r = await protocol.handle_rpc(identity, {
        "jsonrpc": "2.0", "id": 1, "method": "resources/read",
        "params": {"uri": "oyster://knowledge/stats"},
    })
    assert "error" in r
    assert r["error"]["code"] == protocol.GATEWAY_DISABLED


async def test_disabled_gateway_refuses_prompts_get(monkeypatch):
    monkeypatch.setattr(config, "MCP_GATEWAY_ENABLED", False)
    identity = member("kill-switch-test-2")
    r = await protocol.handle_rpc(identity, {
        "jsonrpc": "2.0", "id": 1, "method": "prompts/get",
        "params": {"name": "security_review", "arguments": {"focus": "x"}},
    })
    assert "error" in r
    assert r["error"]["code"] == protocol.GATEWAY_DISABLED


async def test_disabled_gateway_still_answers_initialize_and_ping(monkeypatch):
    monkeypatch.setattr(config, "MCP_GATEWAY_ENABLED", False)
    identity = member("kill-switch-test-3")
    for method, params in (
        ("initialize", {"clientInfo": {"name": "t", "version": "1"}}),
        ("ping", {}),
    ):
        r = await protocol.handle_rpc(identity, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        assert "result" in r  # never gated by the kill-switch


async def test_enabled_gateway_resources_and_prompts_work_normally(app_schema):
    # Sanity check the fix didn't accidentally gate the happy path too.
    identity = member("kill-switch-enabled")
    r = await protocol.handle_rpc(identity, {
        "jsonrpc": "2.0", "id": 1, "method": "resources/read",
        "params": {"uri": "oyster://knowledge/stats"},
    })
    assert "result" in r
    r2 = await protocol.handle_rpc(identity, {
        "jsonrpc": "2.0", "id": 1, "method": "prompts/get",
        "params": {"name": "security_review", "arguments": {"focus": "x"}},
    })
    assert "result" in r2
