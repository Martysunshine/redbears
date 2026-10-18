"""MCP onboarding — installer + doctor building blocks.

Covers fresh install, existing-config merge, backup creation, idempotent repeat,
repair, uninstall, malformed-config recovery, paths with spaces, a missing
client, a missing Python environment, no-secret-leakage, and the doctor's
success/failure health checks. All file-based (Claude in file mode, no CLI, no
real HOME) so it is deterministic on any OS.
"""

from __future__ import annotations

import json

import pytest

from mcp_onboarding import core, environment, installer
from mcp_onboarding.clients import ClaudeCodeClient, VSCodeClient

SERVER = "oyster-security"


def claude(tmp_path, name="claude.json"):
    return ClaudeCodeClient(tmp_path / name, use_cli=False)


def read(path):
    return json.loads(path.read_text())


# ── fresh install / merge / backup / idempotent ──────────────────────────────

def test_fresh_install_creates_entry(tmp_path):
    c = claude(tmp_path)
    r = c.install()
    assert r.status == environment.PASS and r.changed
    data = read(c.config_path)
    assert SERVER in data["mcpServers"]
    assert data["mcpServers"][SERVER]["args"] == ["-m", "mcp_gateway.stdio_main"]


def test_merge_preserves_other_servers(tmp_path):
    p = tmp_path / "claude.json"
    p.write_text(json.dumps({"mcpServers": {"kling": {"command": "node", "args": ["x.js"]}},
                             "otherTopLevel": {"keep": True}}))
    c = ClaudeCodeClient(p, use_cli=False)
    c.install()
    data = read(p)
    assert set(data["mcpServers"]) == {"kling", SERVER}      # other server kept
    assert data["otherTopLevel"] == {"keep": True}           # unrelated keys kept


def test_backup_created_when_config_exists(tmp_path):
    p = tmp_path / "claude.json"
    p.write_text(json.dumps({"mcpServers": {"kling": {"command": "node"}}}))
    ClaudeCodeClient(p, use_cli=False).install()
    backups = list(tmp_path.glob("claude.json.bak.*"))
    assert len(backups) == 1
    assert "kling" in backups[0].read_text()


def test_repeated_install_is_idempotent(tmp_path):
    c = claude(tmp_path)
    c.install()
    r2 = c.install()
    assert r2.status == environment.PASS and r2.changed is False
    assert "already configured" in r2.detail
    data = read(c.config_path)
    assert list(data["mcpServers"]).count(SERVER) == 1  # exactly one entry


def test_repair_rewrites_a_broken_entry(tmp_path):
    p = tmp_path / "claude.json"
    p.write_text(json.dumps({"mcpServers": {SERVER: {"command": "WRONG", "args": []}}}))
    ClaudeCodeClient(p, use_cli=False).repair()
    entry = read(p)["mcpServers"][SERVER]
    assert entry["args"] == ["-m", "mcp_gateway.stdio_main"]
    assert entry["command"] != "WRONG"


def test_uninstall_removes_only_oyster(tmp_path):
    p = tmp_path / "claude.json"
    p.write_text(json.dumps({"mcpServers": {"kling": {"command": "node"}}}))
    c = ClaudeCodeClient(p, use_cli=False)
    c.install()
    r = c.uninstall()
    assert r.status == environment.PASS
    data = read(p)
    assert SERVER not in data["mcpServers"]
    assert "kling" in data["mcpServers"]


# ── malformed recovery / spaces ──────────────────────────────────────────────

def test_malformed_config_is_recovered_not_crashed(tmp_path):
    p = tmp_path / "claude.json"
    p.write_text("{ this is not valid json ]]")
    r = ClaudeCodeClient(p, use_cli=False).install()
    assert r.status == environment.PASS
    # A .corrupt copy was set aside, and a fresh valid config now has the entry.
    assert list(tmp_path.glob("claude.json.corrupt.*"))
    assert SERVER in read(p)["mcpServers"]


def test_paths_with_spaces_round_trip(tmp_path):
    spaced_dir = tmp_path / "dir with spaces"
    spaced_dir.mkdir()
    cfg = spaced_dir / "mcp.json"
    entry = core.server_entry(backend_dir="/Users/some one/Oyster Project/backend")
    data = {}
    core.merge_server(data, "mcpServers", SERVER, entry)
    core.write_json(cfg, data)
    back = read(cfg)
    assert back["mcpServers"][SERVER]["cwd"] == "/Users/some one/Oyster Project/backend"


# ── missing client / missing python env ──────────────────────────────────────

def test_missing_client_reports_action_not_fail(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "vscode_present", lambda: False)
    rep = installer.run("install", "vscode", vscode_config=tmp_path / "vscode-mcp.json")
    assert rep.ok is True  # not a software failure
    assert any(r.status == environment.ACTION and "not detected" in r.detail
               for r in rep.client_results)


def test_missing_python_env_is_flagged(monkeypatch):
    monkeypatch.setattr(core, "default_python", lambda: "/nonexistent/python")
    res = environment.check_python()
    assert res.status == environment.ACTION


# ── no secret leakage ────────────────────────────────────────────────────────

def test_no_secret_in_entry_or_report(tmp_path):
    from mcp_gateway.core import security as sec
    entry = core.server_entry(local_email="you@example.com")
    blob = json.dumps(entry)
    # Only an identity label + launch paths — nothing a redactor would touch.
    assert sec.redact_text(blob) == blob
    assert "env" in entry and set(entry["env"]) == {"OYSTER_MCP_LOCAL_EMAIL"}
    rep = installer.run("install", "claude", dry_run=True,
                        claude_config=tmp_path / "c.json", use_cli=False)
    assert sec.redact_text(rep.render()) == rep.render()


# ── doctor building blocks: success and failure states ───────────────────────

def test_doctor_checks_success_states():
    assert environment.check_gateway_import().status == environment.PASS
    assert environment.check_dependencies().status == environment.PASS
    assert environment.check_os().status == environment.PASS


def test_doctor_checks_failure_state(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def boom(name, *a, **k):
        if name == "fastapi":
            raise ImportError("simulated missing dep")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", boom)
    assert environment.check_dependencies().status == environment.FAIL


def test_client_config_validity_before_and_after_install(tmp_path):
    c = claude(tmp_path)
    ok, _ = c.validate_config()
    assert ok is False           # not configured yet
    c.install()
    ok, detail = c.validate_config()
    assert ok is True            # command + cwd exist (project venv/backend)


def test_installer_conclusion_mentions_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "vscode_present", lambda: True)
    rep = installer.run("install", "vscode", vscode_config=tmp_path / "v.json")
    assert "ready in VS Code" in rep.conclusion
