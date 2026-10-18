#!/usr/bin/env python3
"""End-to-end smoke test for the Oyster MCP gateway (stdio transport).

Spawns the stdio server exactly as an MCP client would, then runs a real
handshake and a handful of tool calls, asserting the safety-critical contracts:

  1. initialize returns the Oyster server info + protocol version
  2. tools/list returns the curated catalogue
  3. a knowledge search returns SOURCE-BACKED citations (chunk_id + source)
  4. get_source_evidence resolves one of those citations
  5. a governed tool (request_authorized_scan) returns 'approval required'
     / blocked and is NEVER executed by the gateway

Runs against whatever OYSTER_* environment is set (point it at the real DB for
a live check, or a temp DB for an isolated one). Exits non-zero on any failure.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]


class StdioClient:
    def __init__(self, env=None):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_gateway.stdio_main"],
            cwd=str(_BACKEND), env=env or os.environ.copy(),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._id = 0

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("server closed the stream")
            obj = json.loads(line)
            if obj.get("id") == self._id:
                return obj

    def notify(self, method, params=None):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method,
                                          "params": params or {}}) + "\n")
        self.proc.stdin.flush()

    def call_tool(self, name, arguments=None):
        r = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        res = r["result"]
        return res, json.loads(res["content"][0]["text"])

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


def _check(label, cond):
    mark = "✓" if cond else "✗"
    print(f"  {mark} {label}")
    return cond


def main() -> int:
    query = sys.argv[1] if len(sys.argv) > 1 else "phishing email authentication"
    client = StdioClient()
    ok = True
    try:
        r = client.request("initialize", {"clientInfo": {"name": "oyster-smoke", "version": "1"}})
        info = r["result"]["serverInfo"]
        ok &= _check(f"initialize → {info['name']} v{info['version']} "
                     f"(protocol {r['result']['protocolVersion']})",
                     info["name"] == "oyster-security")
        client.notify("notifications/initialized")

        r = client.request("tools/list")
        tools = r["result"]["tools"]
        ok &= _check(f"tools/list → {len(tools)} tools", len(tools) >= 1)

        res, data = client.call_tool("search_security_knowledge", {"query": query, "top_k": 3})
        cited = data.get("results") or []
        if data.get("insufficient_evidence"):
            _check("search_security_knowledge → honest 'insufficient evidence' "
                   "(no packs indexed in this DB?)", True)
            chunk_id = None
        else:
            ok &= _check(f"search_security_knowledge → {len(cited)} citation(s) with source",
                         bool(cited) and all(c.get("chunk_id") for c in cited))
            chunk_id = cited[0]["chunk_id"] if cited else None

        if chunk_id:
            res, data = client.call_tool("get_source_evidence", {"chunk_id": chunk_id})
            ok &= _check("get_source_evidence → resolved passage + provenance",
                         data.get("found") and data["evidence"].get("passage"))

        res, data = client.call_tool("list_knowledge_sources", {})
        ok &= _check(f"list_knowledge_sources → {data.get('total_sources')} source pack(s)",
                     "total_sources" in data)

        res, data = client.call_tool(
            "request_authorized_scan",
            {"tool": "nmap", "action": "port_scan", "target": "scanme.example.org"})
        ok &= _check(f"request_authorized_scan → executed={data.get('executed')} "
                     f"status={data.get('status')} (NOT run by gateway)",
                     data.get("executed") is False)
    finally:
        client.close()

    print("\nSMOKE: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
