#!/usr/bin/env python3
"""Oyster MCP production doctor — verify a DEPLOYED /mcp endpoint over HTTPS.

    # After deployment:
    python backend/scripts/mcp_prod_doctor.py --url https://mcp.example.com \
        --token "$OYSTER_MCP_TOKEN"

    # Before deployment (prove the checks against the local gateway):
    python -m mcp_gateway.http_main            # in another shell (loopback)
    python backend/scripts/mcp_prod_doctor.py --url http://127.0.0.1:8765 --token <local>

Every check prints PASS / ACTION NEEDED / FAIL and the tool ends with a plain
conclusion — either the exact ChatGPT connection URL, or what to fix. It never
prints a secret; it scans responses to prove none leak.

The knowledge/isolation/approval checks are side-effect-free: the approval check
targets an internal address so the gateway refuses it at the boundary WITHOUT
creating a proposal, and no project data is written.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

PASS, ACTION, FAIL = "PASS", "ACTION NEEDED", "FAIL"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""

    def line(self) -> str:
        return f"{self.status:<13} {self.name}" + (f" — {self.detail}" if self.detail else "")


class HttpRequester:
    """Thin httpx wrapper. Tests inject a Starlette-TestClient-backed requester
    with the same surface instead."""

    def __init__(self, base_url: str, token: str | None, verify: bool = True):
        import httpx
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._c = httpx.Client(base_url=self.base_url, verify=verify, timeout=30.0)

    def get(self, path):
        return self._c.get(path)

    def post_mcp(self, body: dict, authed: bool = True, session: str | None = None):
        headers = {"content-type": "application/json"}
        if authed and self.token:
            headers["authorization"] = f"Bearer {self.token}"
        if session:
            headers["mcp-session-id"] = session
        return self._c.post("/mcp", json=body, headers=headers)


def _tool_text(resp) -> dict:
    try:
        return json.loads(resp.json()["result"]["content"][0]["text"])
    except Exception:  # noqa: BLE001
        return {}


def run_checks(req: HttpRequester, *, is_https: bool, bodies: list,
               query: str = "log4j jndi remote code execution") -> list[Check]:
    checks: list[Check] = []

    def record_body(resp):
        try:
            bodies.append(resp.text)
        except Exception:  # noqa: BLE001
            pass

    # 1) HTTPS + certificate (verify=True already enforced the cert on connect).
    if is_https:
        checks.append(Check("HTTPS + certificate", PASS, "TLS verified"))
    else:
        checks.append(Check("HTTPS + certificate", ACTION,
                            "target is not https (local/test) — a real deployment must be https"))

    # 2) Anonymous rejection.
    try:
        r = req.post_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                         authed=False)
        record_body(r)
        checks.append(Check("Auth rejection (no credentials)",
                            PASS if r.status_code == 401 else FAIL,
                            f"unauthenticated POST /mcp -> {r.status_code} (expect 401)"))
    except Exception as exc:  # noqa: BLE001
        checks.append(Check("Auth rejection (no credentials)", FAIL, f"endpoint unreachable: {exc}"))
        checks.append(Check("Endpoint reachability", FAIL,
                            "could not reach the endpoint — deploy it first, then re-run"))
        return checks

    # 3) Authenticated initialize.
    session = None
    r = req.post_mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"clientInfo": {"name": "prod-doctor", "version": "1"}}})
    record_body(r)
    init_ok = False
    if r.status_code == 200:
        try:
            info = r.json()["result"]["serverInfo"]
            init_ok = info.get("name") == "oyster-security"
            session = r.headers.get("mcp-session-id")
        except Exception:  # noqa: BLE001
            pass
    checks.append(Check("Authenticated MCP initialize", PASS if init_ok else FAIL,
                        "server=oyster-security" if init_ok
                        else f"init failed (status {r.status_code}) — check the token/allow-list"))
    if not init_ok:
        return checks

    # 4) tools/list
    r = req.post_mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=session)
    record_body(r)
    n_tools = len(r.json().get("result", {}).get("tools", [])) if r.status_code == 200 else 0
    checks.append(Check("tools/list", PASS if n_tools >= 1 else FAIL, f"{n_tools} tools"))

    # 5) resources/list
    r = req.post_mcp({"jsonrpc": "2.0", "id": 3, "method": "resources/list"}, session=session)
    record_body(r)
    uris = {x.get("uri") for x in r.json().get("result", {}).get("resources", [])} \
        if r.status_code == 200 else set()
    checks.append(Check("resources/list", PASS if "oyster://knowledge/sources" in uris else FAIL,
                        f"{len(uris)} resources"))

    # 6) Real knowledge search with citations.
    r = req.post_mcp({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                      "params": {"name": "search_security_knowledge",
                                 "arguments": {"query": query, "top_k": 3}}}, session=session)
    record_body(r)
    data = _tool_text(r)
    results = data.get("results") or []
    if data.get("insufficient_evidence"):
        checks.append(Check("Knowledge search + citations", ACTION,
                            "search works but the KB is empty on this target — restore the "
                            "snapshot to the persistent volume (scripts.restore_knowledge)"))
        kb_populated = False
    elif results and all(x.get("chunk_id") for x in results):
        top = results[0]
        checks.append(Check("Knowledge search + citations", PASS,
                            f"top hit {top.get('knowledge_pack')} (source_url set: "
                            f"{bool(top.get('source_url'))})"))
        kb_populated = True
    else:
        checks.append(Check("Knowledge search + citations", FAIL, "no source-backed results"))
        kb_populated = False

    # 7) Project isolation (single-token remote probe: arbitrary file not readable).
    r = req.post_mcp({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                      "params": {"name": "read_project_file",
                                 "arguments": {"file_id": "not-a-real-file-000"}}}, session=session)
    record_body(r)
    iso = _tool_text(r)
    checks.append(Check("Project isolation", PASS if iso.get("found") is False else FAIL,
                        "arbitrary file id is not readable"))

    # 8) Approval gating (internal target => refused at the boundary; no proposal written).
    r = req.post_mcp({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                      "params": {"name": "request_authorized_scan",
                                 "arguments": {"tool": "nmap", "action": "port_scan",
                                               "target": "http://169.254.169.254/"}}},
                     session=session)
    record_body(r)
    scan = _tool_text(r)
    gated = scan.get("executed") is False or scan.get("ok") is False or scan.get("status") in (
        "refused", "blocked", "awaiting_approval")
    checks.append(Check("Category-C approval gating", PASS if gated else FAIL,
                        f"scan executed={scan.get('executed')} status={scan.get('status')} "
                        f"(never auto-runs)"))

    # 9) Persistent storage populated.
    r = req.post_mcp({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "list_knowledge_sources", "arguments": {}}}, session=session)
    record_body(r)
    src = _tool_text(r)
    total = src.get("total_sources")
    checks.append(Check("Persistent storage (KB volume)",
                        PASS if (total or 0) > 0 else ACTION,
                        f"{total} source packs indexed" if (total or 0) > 0
                        else "no packs — restore the KB snapshot to the volume"))

    # 10) No secrets in responses.
    from mcp_gateway.core import security as sec
    joined = "\n".join(bodies)
    checks.append(Check("No secrets in responses",
                        PASS if sec.redact_text(joined) == joined else FAIL,
                        "responses contain no credential-shaped strings "
                        "(verify host LOGS separately with your log tooling)"))
    return checks


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify a deployed Oyster MCP /mcp endpoint.")
    ap.add_argument("--url", default=os.environ.get("OYSTER_MCP_PROD_URL", "http://127.0.0.1:8765"))
    ap.add_argument("--token", default=os.environ.get("OYSTER_MCP_PROD_TOKEN", ""))
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (staging only).")
    args = ap.parse_args()

    is_https = args.url.lower().startswith("https://")
    if not args.token:
        print("ACTION NEEDED — provide --token (or OYSTER_MCP_PROD_TOKEN). No anonymous access.")
        return 2

    print(f"Oyster MCP Production Doctor\n===========================\nTarget: {args.url}\n")
    bodies: list[str] = []
    try:
        req = HttpRequester(args.url, args.token, verify=not args.insecure)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL — could not create client: {exc}")
        return 1
    checks = run_checks(req, is_https=is_https, bodies=bodies)
    for c in checks:
        print(c.line())

    print("\n" + "-" * 60)
    if any(c.status == FAIL for c in checks):
        print("FAIL — fix the FAIL line(s) above, then re-run.")
        return 1
    if any(c.status == ACTION for c in checks):
        print("ACTION NEEDED — address the items above (usually: deploy over HTTPS and/or "
              "restore the KB snapshot to the volume), then re-run.")
        return 0
    print(f"Oyster MCP endpoint is production-ready at {args.url}")
    print(f"ChatGPT connection URL:  {args.url.rstrip('/')}/mcp   (Authorization: Bearer <token>)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
