#!/usr/bin/env python3
"""Oyster MCP Doctor — one command that tells you if Oyster works in your AI client.

    python backend/scripts/mcp_doctor.py

Every check prints one of three results:

    PASS          — working
    ACTION NEEDED — a step you must take (e.g. run the installer, index the KB)
    FAIL          — a software problem to fix

It ends with a plain conclusion: "Oyster is ready in Claude Code" / "... in
VS Code", or the exact command to fix what is missing.

Safety: the knowledge checks read the real database READ-ONLY; the stateful
checks (Category-C gating, project isolation) run in a throwaway temporary
database in a child process, so the doctor never writes to your real data. No
secret is ever printed.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

PASS, ACTION, FAIL = "PASS", "ACTION NEEDED", "FAIL"
_BUF = io.StringIO()


def say(status: str, name: str, detail: str = "") -> None:
    line = f"{status:<13} {name}" + (f" — {detail}" if detail else "")
    print(line)
    _BUF.write(line + "\n")


def _temp_env() -> dict:
    d = Path(tempfile.mkdtemp(prefix="oyster_doctor_"))
    env = dict(os.environ)
    env.update({
        "OYSTER_DATA_DIR": str(d / "data"),
        "OYSTER_LOGS_DIR": str(d / "logs"),
        "OYSTER_MEMORY_DB": str(d / "data" / "memory.db"),
        "OYSTER_VECTOR_DB_DIR": str(d / "data" / "vector_db"),
    })
    return env


def _real_stdio_init(env: dict) -> tuple[bool, str]:
    """Spawn the actual stdio transport and confirm initialize + tools/list."""
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"clientInfo": {"name": "doctor", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    stdin = "\n".join(json.dumps(m) for m in msgs) + "\n"
    try:
        proc = subprocess.run([sys.executable, "-m", "mcp_gateway.stdio_main"],
                              cwd=str(_BACKEND), env=env, input=stdin,
                              capture_output=True, text=True, timeout=120)
    except Exception as exc:  # noqa: BLE001
        return False, f"stdio spawn failed: {exc}"
    got = {}
    for ln in proc.stdout.splitlines():
        if ln.strip():
            try:
                o = json.loads(ln)
                if o.get("id") is not None:
                    got[o["id"]] = o
            except json.JSONDecodeError:
                pass
    ok = (got.get(1, {}).get("result", {}).get("serverInfo", {}).get("name") == "oyster-security"
          and len(got.get(2, {}).get("result", {}).get("tools", [])) >= 1)
    return ok, (f"{len(got.get(2, {}).get('result', {}).get('tools', []))} tools over real stdio"
                if ok else "stdio transport did not return a valid initialize/tools response")


def main() -> int:
    print("Oyster MCP Doctor\n=================\n")

    # 1) Gateway imports (in-process).
    try:
        from mcp_gateway.core import protocol, catalogue
        say(PASS, "Gateway imports",
            f"{len(catalogue.CATALOGUE)} tools, protocol {protocol.PROTOCOL_VERSION}")
    except Exception as exc:  # noqa: BLE001
        say(FAIL, "Gateway imports", f"{type(exc).__name__}: {exc}")
        print("\nFAIL — the gateway could not be imported. Fix the backend environment first.")
        return 1

    # 2) Knowledge DB availability + real counts (read-only).
    from mcp_onboarding import environment as envmod
    chunks, packs = envmod.knowledge_counts()
    kb_ok = chunks is not None and chunks > 0
    say(PASS if kb_ok else ACTION, "Knowledge database",
        f"{chunks:,} indexed chunks across {packs} enabled packs" if kb_ok
        else "no readable indexed knowledge (index the KB or set OYSTER_MEMORY_DB)")

    # 3) Knowledge search with a real citation (in-process, read-only real DB).
    try:
        import asyncio
        from mcp_gateway.core.identity import Identity
        op = Identity(oyster={"tier": "admin", "email": "op@x", "sub": "doctor-op"},
                      transport="stdio", auth_method="local")
        data = asyncio.run(catalogue._h_search_security_knowledge(
            op, None, {"query": "log4j jndi remote code execution", "top_k": 3}))
        results = data.get("results") or []
        cited = bool(results) and all(r.get("chunk_id") for r in results)
        if data.get("insufficient_evidence"):
            say(ACTION, "Knowledge search + citation",
                "no results (empty index?) — search works but the KB has no matching content")
        elif cited:
            top = results[0]
            say(PASS, "Knowledge search + citation",
                f"top hit {top.get('knowledge_pack')} (source_url set: {bool(top.get('source_url'))})")
        else:
            say(FAIL, "Knowledge search + citation", "results lacked source citations")
    except Exception as exc:  # noqa: BLE001
        say(FAIL, "Knowledge search + citation", f"{type(exc).__name__}: {exc}")

    # 4) Real stdio transport initialization + tools/list (temp DB, child process).
    env = _temp_env()
    ok, detail = _real_stdio_init(env)
    say(PASS if ok else FAIL, "stdio transport init + tools/list", detail)

    # 5+6) Stateful gateway checks in an isolated temp DB (Category-C + isolation).
    try:
        proc = subprocess.run([sys.executable, "-m", "mcp_onboarding.selfcheck"],
                              cwd=str(_BACKEND), env=env, capture_output=True, text=True, timeout=180)
        payload = json.loads([l for l in proc.stdout.splitlines() if l.strip().startswith("{")][-1])
        rl = payload.get("resources_list", {})
        say(rl.get("status", FAIL), "resources/list", rl.get("detail", ""))
        cc = payload.get("category_c_gating", {})
        say(cc.get("status", FAIL), "Category-C approval gating", cc.get("detail", ""))
        pi = payload.get("project_isolation", {})
        say(pi.get("status", FAIL), "Project isolation", pi.get("detail", ""))
    except Exception as exc:  # noqa: BLE001
        say(FAIL, "Gateway self-check (Category-C + isolation)",
            f"{type(exc).__name__}: {(proc.stderr if 'proc' in dir() else exc)}"[:180])

    # 7) HTTP health + 8) anonymous rejection (in-process TestClient; no DB writes).
    try:
        from starlette.testclient import TestClient
        from mcp_gateway import http_app
        import config
        client = TestClient(http_app.create_app())
        h = client.get("/healthz")
        say(PASS if h.status_code == 200 else FAIL, "HTTP health endpoint",
            f"/healthz -> {h.status_code}" + ("" if config.MCP_GATEWAY_ENABLED else " (gateway disabled)"))
        a = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        say(PASS if a.status_code == 401 else FAIL, "HTTP anonymous rejection",
            f"unauthenticated POST /mcp -> {a.status_code} (expect 401)")
    except Exception as exc:  # noqa: BLE001
        say(FAIL, "HTTP transport", f"{type(exc).__name__}: {exc}")

    # 9+10) Client configuration validity.
    from mcp_onboarding.clients import ClaudeCodeClient, VSCodeClient
    claude = ClaudeCodeClient()
    vscode = VSCodeClient()
    claude_ok, cdetail = (claude.validate_config() if claude.detected()
                          else (False, "Claude Code not detected on this machine"))
    say(PASS if claude_ok else ACTION, "Claude Code configuration", cdetail)
    vscode_ok, vdetail = (vscode.validate_config() if vscode.detected()
                          else (False, "VS Code not detected on this machine"))
    say(PASS if vscode_ok else ACTION, "VS Code configuration", vdetail)

    # 11) No secrets printed.
    from mcp_gateway.core import security as sec
    buf = _BUF.getvalue()
    say(PASS if sec.redact_text(buf) == buf else FAIL, "No secrets printed",
        "diagnostic output contains no credential-shaped strings")

    # ---- Conclusion --------------------------------------------------------
    print("\n" + "-" * 60)
    text = _BUF.getvalue()
    if f"\n{FAIL}" in "\n" + text:
        print("FAIL — a software problem was found above. Fix the FAIL line(s), then re-run "
              "`python backend/scripts/mcp_doctor.py`.")
        return 1
    ready = []
    if claude.detected() and claude_ok:
        print("Oyster is ready in Claude Code — restart Claude Code and look for 'oyster-security'.")
        ready.append("claude")
    elif claude.detected():
        print("ACTION NEEDED — run: python backend/scripts/mcp_setup.py --client claude --install")
    if vscode.detected() and vscode_ok:
        print("Oyster is ready in VS Code — restart VS Code and look for 'oyster-security'.")
        ready.append("vscode")
    elif vscode.detected():
        print("ACTION NEEDED — run: python backend/scripts/mcp_setup.py --client vscode --install")
    if not (claude.detected() or vscode.detected()):
        print("ACTION NEEDED — no supported AI client detected. Install Claude Code or VS Code, "
              "then run: python backend/scripts/mcp_setup.py --client all --install")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
