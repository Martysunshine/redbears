"""Direct behavioural tests for the IDOR demo target — no network, no LLM.

Runs the full acceptance matrix against both modes via FastAPI's TestClient,
plus the auth (401), unknown-record (404) and patched-no-leak guarantees. These
must fail loudly if the target ever stops reproducing the flaw in vulnerable
mode, or starts leaking a record in patched mode.

    cd lab && python -m pytest -q
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lab import fixtures
from lab.app import create_app


def _client(mode: str) -> TestClient:
    return TestClient(create_app(mode))


def _auth(persona: str) -> dict:
    return {"Authorization": f"Bearer {fixtures.demo_token(persona)}"}


@pytest.fixture(params=["vulnerable", "patched"])
def mode(request) -> str:
    return request.param


# --- health -----------------------------------------------------------------

def test_health_reports_mode(mode):
    r = _client(mode).get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "mode": mode}


# --- same-owner access works in both modes ----------------------------------

@pytest.mark.parametrize("persona,record_id", [("alice", 101), ("bob", 202)])
def test_owner_reads_own_record(mode, persona, record_id):
    r = _client(mode).get(f"/api/records/{record_id}", headers=_auth(persona))
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == record_id
    assert body["owner"] == persona


# --- the flaw, and its patch ------------------------------------------------

def test_vulnerable_mode_allows_cross_user_read():
    # Bob, authenticated as himself, reads Alice's record 101: the IDOR.
    r = _client("vulnerable").get("/api/records/101", headers=_auth("bob"))
    assert r.status_code == 200
    assert r.json()["owner"] == "alice"


def test_patched_mode_denies_cross_user_read_without_leaking():
    r = _client("patched").get("/api/records/101", headers=_auth("bob"))
    assert r.status_code == 403
    # The 403 body must not contain the record or its owner.
    text = r.text.lower()
    assert "alice" not in text
    assert "demo record" not in text
    assert "owner" not in r.json()


# --- auth and unknown records (both modes) ----------------------------------

def test_missing_token_is_401(mode):
    assert _client(mode).get("/api/records/101").status_code == 401


def test_invalid_token_is_401(mode):
    r = _client(mode).get("/api/records/101", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_non_bearer_scheme_is_401(mode):
    r = _client(mode).get("/api/records/101", headers={"Authorization": "Basic YWxpY2U6eA=="})
    assert r.status_code == 401


def test_x_user_header_is_not_trusted_as_identity(mode):
    # Asserting an identity via a header (no bearer token) must not authenticate.
    r = _client(mode).get("/api/records/101", headers={"X-User": "alice"})
    assert r.status_code == 401


def test_unknown_record_is_404(mode):
    r = _client(mode).get("/api/records/999", headers=_auth("alice"))
    assert r.status_code == 404


# --- determinism ------------------------------------------------------------

def test_fixtures_identical_across_modes():
    vuln = _client("vulnerable").get("/api/records/101", headers=_auth("alice")).json()
    patched = _client("patched").get("/api/records/101", headers=_auth("alice")).json()
    assert vuln == patched


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        create_app("chaos")
