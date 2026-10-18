"""Isolated gateway self-checks (run in a child process against a TEMP database).

The doctor spawns this with OYSTER_DATA_DIR/OYSTER_MEMORY_DB pointed at a
throwaway directory, so the stateful checks (Category-C gating, project
isolation) never write to the real knowledge/execution database. It initialises
a clean schema, exercises the gateway in-process, and prints one JSON line of
results. It is safe to run standalone for debugging.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))


def _init_schema() -> None:
    from services.knowledge import store as ks
    from services.execution import store as es
    from services import project_service, user_prefs
    from services.artifacts import store as art_store
    ks.init_db(); es.init_db(); project_service.init_db(); user_prefs.init_db(); art_store.init_db()


async def _run() -> dict:
    from mcp_gateway.core import protocol
    from mcp_gateway.core.identity import Identity
    results: dict[str, dict] = {}

    def op(sub="doc-op"):
        return Identity(oyster={"tier": "admin", "email": "op@x", "sub": sub},
                        transport="stdio", auth_method="local")

    def member(sub):
        return Identity(oyster={"tier": "user", "email": f"{sub}@x", "sub": sub},
                        transport="http", auth_method="supabase")

    async def call(identity, name, args):
        r = await protocol.handle_rpc(identity, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                                "params": {"name": name, "arguments": args}})
        res = r["result"]
        return res, json.loads(res["content"][0]["text"])

    # initialize
    r = await protocol.handle_rpc(op(), {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                        "params": {"clientInfo": {"name": "doctor", "version": "1"}}})
    ok = r.get("result", {}).get("serverInfo", {}).get("name") == "oyster-security"
    results["initialize"] = {"status": "PASS" if ok else "FAIL",
                             "detail": f"protocol {r.get('result', {}).get('protocolVersion')}"}

    # tools/list + resources/list
    r = await protocol.handle_rpc(op(), {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    n = len(r.get("result", {}).get("tools", []))
    results["tools_list"] = {"status": "PASS" if n >= 1 else "FAIL", "detail": f"{n} tools"}
    r = await protocol.handle_rpc(op(), {"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
    uris = {x["uri"] for x in r.get("result", {}).get("resources", [])}
    results["resources_list"] = {"status": "PASS" if "oyster://knowledge/sources" in uris else "FAIL",
                                 "detail": f"{len(uris)} resources"}

    # Category-C gating: operator scan must NOT execute; member must be denied.
    _, data = await call(op(), "request_authorized_scan",
                         {"tool": "nmap", "action": "port_scan", "target": "scanme.example.org"})
    op_gated = data.get("executed") is False and data.get("status") in ("blocked", "awaiting_approval", "approved")
    res_m, _ = await call(member("cat-c-mem"), "request_authorized_scan",
                          {"tool": "nmap", "action": "port_scan", "target": "x"})
    member_denied = res_m["isError"] is True
    results["category_c_gating"] = {
        "status": "PASS" if (op_gated and member_denied) else "FAIL",
        "detail": f"operator executed={data.get('executed')} status={data.get('status')}; "
                  f"member denied={member_denied}"}

    # Project isolation: B cannot read A's file, and does not see it in search.
    from services import project_service
    from services.artifacts import store as art_store
    project_service.ensure_project("u_iso-a", "A ws")
    project_service.set_owner("u_iso-a", "iso-a")
    art = art_store.create("u_iso-a", "secret_notes.txt")
    art_store.update(art["id"], text="alpha isolation content", index_status="indexed")
    _, a_read = await call(member("iso-a"), "read_project_file", {"file_id": art["id"]})
    _, b_read = await call(member("iso-b"), "read_project_file", {"file_id": art["id"]})
    _, b_search = await call(member("iso-b"), "search_project_files", {"query": "alpha"})
    isolated = a_read.get("found") is True and b_read.get("found") is False and b_search.get("total") == 0
    results["project_isolation"] = {
        "status": "PASS" if isolated else "FAIL",
        "detail": f"owner_read={a_read.get('found')} other_read={b_read.get('found')} "
                  f"other_search_hits={b_search.get('total')}"}
    return results


def main() -> int:
    _init_schema()
    results = asyncio.run(_run())
    print(json.dumps(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
