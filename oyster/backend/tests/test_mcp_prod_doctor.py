"""Production doctor — drive run_checks against an in-process HTTP gateway.

Uses a Starlette TestClient (a real ASGI round-trip, no network) with a temp DB
seeded with one knowledge pack, so every production check can be asserted
deterministically: anonymous rejection, authenticated initialize, tools/resources
listing, a source-backed knowledge answer, project isolation, approval gating,
persistent-storage presence, and no-secret-leakage.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import config

# Load the doctor script (scripts/ is not an importable package). Register it in
# sys.modules before exec so its @dataclass can resolve its own module.
_SPEC = importlib.util.spec_from_file_location(
    "mcp_prod_doctor", Path(config.BACKEND_DIR) / "scripts" / "mcp_prod_doctor.py")
prod_doctor = importlib.util.module_from_spec(_SPEC)
sys.modules["mcp_prod_doctor"] = prod_doctor
_SPEC.loader.exec_module(prod_doctor)

TOKEN = "prod-doctor-test-token-abcdefghij"


class _TCReq:
    """Requester with the same surface as HttpRequester, backed by TestClient."""

    def __init__(self, client: TestClient, token: str | None):
        self._c = client
        self.token = token

    def get(self, path):
        return self._c.get(path)

    def post_mcp(self, body, authed=True, session=None):
        headers = {"content-type": "application/json"}
        if authed and self.token:
            headers["authorization"] = f"Bearer {self.token}"
        if session:
            headers["mcp-session-id"] = session
        return self._c.post("/mcp", json=body, headers=headers)


@pytest.fixture
def seeded_app(fake_embedding, monkeypatch):
    from services import project_service, user_prefs
    from services.artifacts import store as art_store
    from services.execution import store as exec_store
    from services.knowledge import pack_service
    from mcp_gateway import http_app

    project_service.init_db(); user_prefs.init_db(); art_store.init_db(); exec_store.init_db()
    asyncio.run(pack_service.install("mitre-attack"))
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS", {TOKEN: "op@x"})
    return TestClient(http_app.create_app())


def _by_name(checks):
    return {c.name: c for c in checks}


def test_prod_doctor_all_checks_pass_over_authenticated_gateway(seeded_app):
    req = _TCReq(seeded_app, TOKEN)
    checks = prod_doctor.run_checks(req, is_https=False, bodies=[], query="technique")
    r = _by_name(checks)

    # is_https=False is honestly an ACTION (local target), not a hard failure.
    assert r["HTTPS + certificate"].status == prod_doctor.ACTION
    assert r["Auth rejection (no credentials)"].status == prod_doctor.PASS
    assert r["Authenticated MCP initialize"].status == prod_doctor.PASS
    assert r["tools/list"].status == prod_doctor.PASS
    assert r["resources/list"].status == prod_doctor.PASS
    assert r["Knowledge search + citations"].status == prod_doctor.PASS
    assert r["Project isolation"].status == prod_doctor.PASS
    assert r["Category-C approval gating"].status == prod_doctor.PASS
    assert r["Persistent storage (KB volume)"].status == prod_doctor.PASS
    assert r["No secrets in responses"].status == prod_doctor.PASS
    # No FAIL anywhere.
    assert not any(c.status == prod_doctor.FAIL for c in checks)


def test_prod_doctor_reports_failure_without_credentials(seeded_app):
    # A requester with no token: anonymous is rejected AND authed init cannot proceed.
    req = _TCReq(seeded_app, None)
    checks = prod_doctor.run_checks(req, is_https=False, bodies=[])
    r = _by_name(checks)
    assert r["Auth rejection (no credentials)"].status == prod_doctor.PASS
    assert r["Authenticated MCP initialize"].status == prod_doctor.FAIL


def test_prod_doctor_flags_empty_knowledge_base(monkeypatch):
    # No pack installed => search is honest 'insufficient evidence' => ACTION, not a fake PASS.
    from services import project_service, user_prefs
    from services.artifacts import store as art_store
    from services.execution import store as exec_store
    from mcp_gateway import http_app
    project_service.init_db(); user_prefs.init_db(); art_store.init_db(); exec_store.init_db()
    monkeypatch.setattr(config, "MCP_HTTP_STATIC_TOKENS", {TOKEN: "op@x"})
    req = _TCReq(TestClient(http_app.create_app()), TOKEN)
    checks = prod_doctor.run_checks(req, is_https=False, bodies=[], query="zzz-nonexistent-xyz")
    r = _by_name(checks)
    assert r["Knowledge search + citations"].status == prod_doctor.ACTION
    assert r["Persistent storage (KB volume)"].status == prod_doctor.ACTION
