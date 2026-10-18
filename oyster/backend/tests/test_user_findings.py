"""Findings: per-user ownership, auto-title, and public-share security.

Runs against the temp DB the conftest redirects to; no user data is touched.
"""

from __future__ import annotations

import ast
import pathlib
from collections import Counter

import pytest

from services import user_findings_service as uf


def test_no_duplicate_model_names_in_schemas():
    """Two classes with the same name in schemas.py = the later one silently
    wins, and every route importing that name gets the WRONG model.

    This is not hypothetical: `FindingCreateRequest` was declared twice (once
    for findings, once by the Execution Engine, whose `title` is required), so
    POST /findings 422'd on a missing title for every single request. Python
    raises nothing for a duplicate class, so only a check like this catches it.
    """
    src = (pathlib.Path(__file__).resolve().parents[1] / "models" / "schemas.py").read_text(
        encoding="utf-8"
    )
    names = [n.name for n in ast.parse(src).body if isinstance(n, ast.ClassDef)]
    dupes = sorted(name for name, count in Counter(names).items() if count > 1)
    assert not dupes, f"duplicate class names in models/schemas.py: {dupes}"


def test_findings_router_uses_the_user_finding_models():
    """Guards the import itself: the router must bind the UserFinding* models,
    not the Execution Engine's similarly-named ones."""
    from models.schemas import UserFindingCreateRequest
    from routers import user_findings as router_mod

    assert router_mod.UserFindingCreateRequest is UserFindingCreateRequest
    # content-only must be valid — a required `title` here is the shadowing bug.
    assert UserFindingCreateRequest(content="hi").title is None


@pytest.fixture(autouse=True)
def fresh_findings():
    import sqlite3
    import config
    con = sqlite3.connect(str(config.MEMORY_DB))
    con.execute("DROP TABLE IF EXISTS user_findings")
    con.commit()
    con.close()
    uf.init_db()
    yield


def test_auto_title_from_first_meaningful_line():
    f = uf.create("alice", "u_alice", "# SQL injection in /login\nUNION SELECT ...")
    assert f["title"] == "SQL injection in /login"


def test_auto_title_truncates_long_lines():
    long = "x" * 200
    f = uf.create("alice", "u_alice", long)
    assert len(f["title"]) <= 60 and f["title"].endswith("…")


def test_auto_title_skips_noise_lines():
    f = uf.create("alice", "u_alice", "```\n> \nActual heading here\n")
    assert f["title"] == "Actual heading here"


def test_explicit_title_wins():
    f = uf.create("alice", "u_alice", "body", title="  My finding ")
    assert f["title"] == "My finding"


def test_ownership_isolation():
    f = uf.create("alice", "u_alice", "secret payload")
    assert uf.can_access(f["id"], "alice")
    assert not uf.can_access(f["id"], "bob")
    assert not uf.can_access(f["id"], None)
    assert not uf.can_access("nope", "alice")


def test_list_is_scoped_to_owner_and_project():
    uf.create("alice", "u_alice", "a1")
    uf.create("alice", "proj2", "a2")
    uf.create("bob", "u_bob", "b1")
    assert len(uf.list_by("alice")) == 2
    assert len(uf.list_by("alice", "u_alice")) == 1
    assert uf.list_by("bob", "u_alice") == []


def test_update_and_blank_title_rejected():
    f = uf.create("alice", "u_alice", "body")
    assert uf.update(f["id"], title="Renamed")["title"] == "Renamed"
    assert uf.update(f["id"], content="new body")["content"] == "new body"
    assert uf.update(f["id"], title="   ") is None   # blank title refused


def test_delete():
    f = uf.create("alice", "u_alice", "body")
    assert uf.delete(f["id"])
    assert uf.get(f["id"]) is None


def test_manual_evidence_style_finding_keeps_every_pentest_field():
    """The red-team Evidence logger was folded into findings — everything it
    recorded must still round-trip through the one store."""
    f = uf.create(
        "alice", "u_alice", "1. upload .php\n2. server accepts it",
        title="Unrestricted file upload", severity="critical",
        endpoint="/api/documents/upload", method="POST",
        notes="200 OK returned", recommended_fix="Validate MIME server-side",
    )
    assert f["severity"] == "critical"
    assert f["endpoint"] == "/api/documents/upload"
    assert f["method"] == "POST"
    assert f["notes"] == "200 OK returned"
    assert f["recommended_fix"] == "Validate MIME server-side"


def test_chat_captured_finding_defaults_to_info_with_empty_pentest_fields():
    f = uf.create("alice", "u_alice", "# SQLi in /login\nUNION SELECT")
    assert f["severity"] == "info"
    assert f["endpoint"] == "" and f["method"] == ""
    assert f["notes"] == "" and f["recommended_fix"] == ""


def test_severity_is_normalised_and_editable():
    f = uf.create("alice", "u_alice", "body", severity="NOT-A-SEVERITY")
    assert f["severity"] == "info"          # unknown never reaches the DB
    assert uf.update(f["id"], severity="high")["severity"] == "high"
    assert uf.update(f["id"], severity="")["severity"] == "info"


def test_pentest_fields_are_editable_after_the_fact():
    f = uf.create("alice", "u_alice", "body")
    up = uf.update(f["id"], endpoint="/x", method="GET", recommended_fix="patch it")
    assert up["endpoint"] == "/x" and up["method"] == "GET"
    assert up["recommended_fix"] == "patch it"


def test_in_report_flag_create_update_and_filter():
    plain = uf.create("alice", "u_alice", "just a finding")
    reported = uf.create("alice", "u_alice", "for the report", in_report=True)
    assert plain["in_report"] is False
    assert reported["in_report"] is True
    # filter
    assert {f["id"] for f in uf.list_by("alice", in_report=True)} == {reported["id"]}
    assert {f["id"] for f in uf.list_by("alice", in_report=False)} == {plain["id"]}
    assert len(uf.list_by("alice")) == 2          # no filter = all
    # toggle a plain finding into the report, and back out
    assert uf.update(plain["id"], in_report=True)["in_report"] is True
    assert len(uf.list_by("alice", in_report=True)) == 2
    assert uf.update(plain["id"], in_report=False)["in_report"] is False
    assert {f["id"] for f in uf.list_by("alice", in_report=True)} == {reported["id"]}


# --- public share security --------------------------------------------------

def test_share_returns_minimal_projection_only():
    f = uf.create("alice", "u_alice", "payload body",
                  title="Payload", conversation_id="c1", message_id="m1")
    tok = uf.set_share(f["id"])
    pub = uf.get_by_token(tok)
    assert pub["title"] == "Payload"
    assert pub["content"] == "payload body"
    # No identifying fields ever leak through the public projection.
    for leaked in ("user_id", "project_id", "conversation_id", "message_id", "id", "share_token"):
        assert leaked not in pub


def test_owner_payload_carries_token_but_public_never_does():
    """The token reaches only the OWNER (their list/get are ownership-gated), so
    they can rebuild their share URL after a reload — while the unauthenticated
    public projection (get_by_token) never includes it."""
    f = uf.create("alice", "u_alice", "body")
    tok = uf.set_share(f["id"])
    row = uf.list_by("alice")[0]
    assert row["shared"] is True
    assert row["share_token"] == tok            # owner sees their own token
    pub = uf.get_by_token(tok)
    assert "share_token" not in pub             # public projection never does


def test_revoked_token_404s():
    f = uf.create("alice", "u_alice", "body")
    tok = uf.set_share(f["id"])
    assert uf.get_by_token(tok) is not None
    uf.revoke_share(f["id"])
    assert uf.get_by_token(tok) is None


def test_regenerated_token_differs_and_invalidates_old():
    f = uf.create("alice", "u_alice", "body")
    tok1 = uf.set_share(f["id"])
    tok2 = uf.set_share(f["id"])
    assert tok1 != tok2
    assert uf.get_by_token(tok1) is None
    assert uf.get_by_token(tok2) is not None


def test_empty_and_unknown_tokens_never_match():
    uf.create("alice", "u_alice", "body")   # exists but unshared
    assert uf.get_by_token("") is None
    assert uf.get_by_token("unknowntoken") is None


def test_unshared_finding_is_never_publicly_readable():
    uf.create("alice", "u_alice", "private body")
    # No token exists, so nothing serves it. (share_token NULL, and get_by_token
    # refuses an empty token before querying.)
    assert uf.get_by_token("") is None


# ── category: report export usefulness (2026-10-14) ─────────────────────────
# "Make exported reports useful: include the finding, affected asset,
# supporting evidence, recommended remediation and unresolved questions. Do
# not invent missing details." (oyster/docs/AI_HANDOFF.md, same date.)

def test_export_includes_asset_evidence_excerpt_remediation_and_unresolved():
    f = uf.create(
        "alice", "u_alice",
        "SQL injection in /api/search allows unauthenticated data exfiltration.",
        title="SQL Injection in /api/search", severity="critical",
        affected_asset="web-app-03.acme.internal (10.50.2.17)",
        recommended_fix="Use parameterized queries; apply least-privilege DB accounts.",
        unresolved_questions="Whether the same pattern exists in the legacy /api/v1/search endpoint was not checked.",
        citations=[{"document": "security_report.txt",
                   "chunk": "The 'q' parameter is concatenated directly into a SQL WHERE clause without parameterization."}],
    )
    report = uf.format_report([f], "proj-1")
    assert "**Affected asset:** `web-app-03.acme.internal (10.50.2.17)`" in report
    assert "**Recommended fix:** Use parameterized queries; apply least-privilege DB accounts." in report
    assert "**Unresolved questions:**" in report and "legacy /api/v1/search" in report
    # Supporting evidence must show the actual passage, not just a citation
    # number — a reader can verify the claim without reopening the source.
    assert "**Supporting evidence:**" in report
    assert "concatenated directly into a SQL WHERE clause" in report


def test_export_never_invents_asset_or_unresolved_section_when_absent():
    f = uf.create("alice", "u_alice", "A finding with no asset or open questions recorded.")
    report = uf.format_report([f], "proj-1")
    assert "**Affected asset:**" not in report
    assert "**Unresolved questions:**" not in report
    # No citations recorded -> no fabricated "Supporting evidence" section either.
    assert "**Supporting evidence:**" not in report


def test_export_evidence_excerpt_is_truncated_not_fabricated():
    long_text = "A" * 500
    f = uf.create("alice", "u_alice", "finding body",
                 citations=[{"document": "doc.md", "chunk": long_text}])
    report = uf.format_report([f], "proj-1")
    assert "AAA…" in report  # truncated with ellipsis
    assert long_text not in report  # not dumped in full
    assert report.count("A" * 221) == 0  # excerpt capped, nothing padded past the cap


def test_citation_without_body_text_renders_no_fabricated_excerpt():
    f = uf.create("alice", "u_alice", "finding body",
                 citations=[{"document": "doc.md"}])  # no chunk/text field at all
    report = uf.format_report([f], "proj-1")
    assert "- [1]" in report  # the source label still renders
    assert "  > " not in report  # no excerpt line fabricated for a sourceless citation


def test_update_sets_affected_asset_and_unresolved_questions():
    f = uf.create("alice", "u_alice", "body")
    updated = uf.update(f["id"], affected_asset="db-02.internal",
                        unresolved_questions="Root cause not yet confirmed.")
    assert updated["affected_asset"] == "db-02.internal"
    assert updated["unresolved_questions"] == "Root cause not yet confirmed."
