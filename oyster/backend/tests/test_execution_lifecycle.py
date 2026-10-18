"""End-to-end execution lifecycle against a local, safe HTTP fixture.

Drives the real pipeline: propose → (blocked before approval) → approve →
execute → evidence + audit. Also covers out-of-scope blocking, duplicate-run
prevention, approval binding, expiry, and project isolation. Uses only a
localhost http.server — never public infrastructure.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from services import project_service
from services.execution import service as ex, store


@pytest.fixture(scope="module")
def local_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Server", "OysterTestServer/1.0")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello from local fixture")

        def log_message(self, *args):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


@pytest.fixture
def project(local_server):
    project_service.init_db()
    store.init_db()
    url = f"http://127.0.0.1:{local_server}"
    proj = project_service.create_project(
        "Exec E2E", "isolated test project",
        scope={"engagement_name": "Exec E2E", "allowed_targets": [url]},
        activate=False,
    )
    return proj["id"], url


@pytest.mark.asyncio
async def test_full_authorized_flow(project):
    pid, url = project

    # 1. propose (class 2 http) → awaiting approval
    r = ex.create_proposal(tool_id="http", action_id="inspect", targets=[url + "/"],
                           objective="inspect fixture", project_id=pid)
    assert r["ok"] and r["proposal"]["status"] == "awaiting_approval"
    assert r["policy"]["decision"] == "requires_approval"
    prop_id = r["proposal"]["id"]

    # 2. execution before approval is refused
    blocked = await ex.start_execution(prop_id, project_id=pid)
    assert not blocked["ok"] and "approval required" in blocked["error"].lower()

    # 3. approve, then execute
    a = ex.approve_proposal(prop_id, project_id=pid)
    assert a["ok"]
    run = await ex.start_execution(prop_id, project_id=pid)
    assert run["ok"], run
    assert run["execution"]["status"] == "succeeded"
    assert run["execution"]["output_hash"]                       # chain-of-custody hash
    assert "200" in run["output"]["stdout"]
    assert run["evidence_ids"]                                    # evidence minted

    # 4. duplicate execution prevented
    dup = await ex.start_execution(prop_id, project_id=pid)
    assert not dup["ok"] and "already" in dup["error"].lower()

    # 5. finding from evidence (in-project) works
    f = ex.create_finding("HTTP endpoint reachable", "info", "Fixture responded 200.",
                          run["evidence_ids"][:1], project_id=pid)
    assert f["ok"]

    # 6. audit trail is complete
    events = {e["event"] for e in store.list_audit(pid)}
    assert {"proposal_created", "proposal_approved", "execution_started",
            "execution_completed", "finding_created"} <= events


@pytest.mark.asyncio
async def test_out_of_scope_blocked_but_still_planned(project):
    pid, _url = project
    r = ex.create_proposal(tool_id="http", action_id="inspect",
                           targets=["http://scanme.example.org/"], project_id=pid)
    assert r["ok"]                                # a proposal is still produced (safe plan)
    assert r["proposal"]["status"] == "blocked"
    assert r["policy"]["decision"] == "blocked"
    assert r["policy"]["unmatched_targets"] == ["http://scanme.example.org/"]
    # and it cannot be forced to run
    run = await ex.start_execution(r["proposal"]["id"], project_id=pid)
    assert not run["ok"]


@pytest.mark.asyncio
async def test_approval_binding_and_mutation(project):
    pid, url = project
    r = ex.create_proposal(tool_id="http", action_id="inspect", targets=[url + "/"], project_id=pid)
    prop_id = r["proposal"]["id"]
    ex.approve_proposal(prop_id, project_id=pid)
    # tamper with the stored proposal AFTER approval → hash mismatch → refused
    store.update_proposal(prop_id, {"parameters": {"method": "HEAD"}})
    run = await ex.start_execution(prop_id, project_id=pid)
    assert not run["ok"] and "re-approval" in run["error"].lower()


@pytest.mark.asyncio
async def test_expired_proposal_refused(project):
    pid, url = project
    r = ex.create_proposal(tool_id="http", action_id="inspect", targets=[url + "/"], project_id=pid)
    prop_id = r["proposal"]["id"]
    store.update_proposal(prop_id, {"expires_at": "2000-01-01T00:00:00+00:00"})
    assert not ex.approve_proposal(prop_id, project_id=pid)["ok"]
    run = await ex.start_execution(prop_id, project_id=pid)
    assert not run["ok"] and "expired" in run["error"].lower()


@pytest.mark.asyncio
async def test_project_isolation(project):
    pid, url = project
    r = ex.create_proposal(tool_id="http", action_id="inspect", targets=[url + "/"], project_id=pid)
    prop_id = r["proposal"]["id"]
    other = project_service.create_project("Other", activate=False)["id"]
    # another project cannot see or act on this proposal
    assert not ex.validate_proposal(prop_id, project_id=other)["ok"]
    assert not ex.approve_proposal(prop_id, project_id=other)["ok"]
    run = await ex.start_execution(prop_id, project_id=other)
    assert not run["ok"]


@pytest.mark.asyncio
async def test_finding_rejects_cross_project_evidence(project):
    pid, url = project
    r = ex.create_proposal(tool_id="http", action_id="inspect", targets=[url + "/"], project_id=pid)
    ex.approve_proposal(r["proposal"]["id"], project_id=pid)
    run = await ex.start_execution(r["proposal"]["id"], project_id=pid)
    other = project_service.create_project("Other2", activate=False)["id"]
    f = ex.create_finding("x", "info", "y", run["evidence_ids"][:1], project_id=other)
    assert not f["ok"] and "not found" in f["error"].lower()
