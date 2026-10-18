from __future__ import annotations

from services import project_context, user_findings_service
from services.user_findings_service import format_report


ALICE = {"tier": "user", "sub": "alice", "email": "alice@example.test"}


def test_export_contains_only_curated_active_project_findings(monkeypatch):
    monkeypatch.setattr(project_context, "workspace_id", lambda identity: "u_alice")
    user_findings_service.init_db()
    included = user_findings_service.create(
        "alice", "u_alice", "SQL injection evidence", title="Injection", in_report=True,
        citations=[{"title": "OWASP", "url": "https://owasp.org/"}], severity="high",
    )
    user_findings_service.create("alice", "u_alice", "private scratch", in_report=False)
    user_findings_service.create("alice", "u_other", "other project", in_report=True)
    assert included["id"]
    report = format_report(user_findings_service.list_by("alice", "u_alice", True), "u_alice")
    assert "SQL injection evidence" in report
    assert "private scratch" not in report
    assert "other project" not in report
    assert "share_token" not in report
