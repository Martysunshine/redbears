"""The home-workspace re-filing of conversations runs exactly once per database.

Until 2026-09-14 conversation_service.init_db() re-ran two UPDATEs on every
boot that moved every owned conversation to ``u_<sub>``. A conversation belongs
to the project it was created in, and GET /conversations lists the caller's
current workspace — so a chat created inside another project vanished from
that project's sidebar after the next deploy. The fix is a marker row in
``schema_migrations`` (services/db.py ``run_once``). These tests pin:

  * a fresh database gets the marker,
  * rows that predate workspaces ARE moved, once,
  * rows created afterwards in another project are LEFT THERE by later boots,
  * ownerless rows are never touched,
  * the marker and the change land in one transaction.

Each test gets its own database file; nothing here touches the shared test DB.
"""
from __future__ import annotations

import sqlite3

import pytest

from services import conversation_service as cs
from services import db


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    path = tmp_path / "marker.db"
    monkeypatch.setattr(cs, "_DB_PATH", path)
    return path


def _raw(path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    return con


def _seed(path, conv_id: str, project_id: str, user_id, owner_tier) -> None:
    """Insert a conversation row directly, bypassing the service (which always
    files new rows correctly) — this is what an OLD database looks like."""
    with _raw(path) as con:
        con.execute(
            "INSERT INTO conversations (id, project_id, user_id, owner_tier, mode, title, "
            "pinned, created_at, updated_at) VALUES (?, ?, ?, ?, 'basic', 't', 0, 'x', 'x')",
            (conv_id, project_id, user_id, owner_tier),
        )


def _project_of(path, conv_id: str) -> str:
    with _raw(path) as con:
        return con.execute("SELECT project_id FROM conversations WHERE id = ?", (conv_id,)).fetchone()[0]


def _markers(path) -> dict[str, str]:
    with _raw(path) as con:
        return {r["name"]: r["applied_at"] for r in con.execute("SELECT * FROM schema_migrations")}


def test_fresh_database_records_the_marker(fresh_db):
    cs.init_db()
    marks = _markers(fresh_db)
    assert cs.HOME_WORKSPACE_MIGRATION in marks
    assert marks[cs.HOME_WORKSPACE_MIGRATION].startswith("20")   # an ISO timestamp


def test_pre_workspace_rows_are_moved_once(fresh_db):
    # Build the schema without the marker, the way an old image left it.
    cs.init_db()
    with _raw(fresh_db) as con:
        con.execute("DELETE FROM schema_migrations")
    _seed(fresh_db, "old-user", "operators-project", "sub-alice", "user")
    _seed(fresh_db, "old-admin", "Default Engagement", "sub-martin", "admin")
    _seed(fresh_db, "orphan", "operators-project", None, None)

    cs.init_db()                                        # the migrating boot
    assert _project_of(fresh_db, "old-user") == "u_sub-alice"
    assert _project_of(fresh_db, "old-admin") == "u_sub-martin"
    assert _project_of(fresh_db, "orphan") == "operators-project", "ownerless rows stay put"
    first = _markers(fresh_db)[cs.HOME_WORKSPACE_MIGRATION]

    cs.init_db()                                        # any later boot
    assert _markers(fresh_db)[cs.HOME_WORKSPACE_MIGRATION] == first, "marker must not be rewritten"


def test_rows_created_in_another_project_survive_later_boots(fresh_db):
    """The actual bug. After the marker exists, a conversation a user creates
    inside a project they made must still be there after the next deploy."""
    cs.init_db()
    conv = cs.create("proj-pentest-2026", "basic", "recon notes",
                     user_id="sub-bob", owner_tier="user")
    cs.add_message(conv["id"], "user", "hello")          # list_by hides empty shells
    admin_conv = cs.create("proj-shared-ops", "basic", "ops",
                           user_id="sub-martin", owner_tier="admin")

    for _ in range(3):                                  # three more boots
        cs.init_db()

    assert _project_of(fresh_db, conv["id"]) == "proj-pentest-2026"
    assert _project_of(fresh_db, admin_conv["id"]) == "proj-shared-ops"
    # And listing by that project still finds it — the workspace semantics —
    # while the home workspace does not, because it was never filed there.
    listed = cs.list_by("proj-pentest-2026", "basic", user_id="sub-bob")
    assert [c["id"] for c in listed] == [conv["id"]]
    assert cs.list_by("u_sub-bob", "basic", user_id="sub-bob") == []


def test_the_old_behaviour_would_have_moved_them(fresh_db):
    """Guards the guard: prove the rewrite still does what it did, so the
    marker is what protects the rows — not a no-op migration."""
    cs.init_db()
    conv = cs.create("proj-x", "basic", "t", user_id="sub-carol", owner_tier="user")
    with _raw(fresh_db) as con:
        cs._migrate_home_workspace(con)
    assert _project_of(fresh_db, conv["id"]) == "u_sub-carol"


def test_run_once_is_transactional_with_the_caller(tmp_path):
    """No commit inside run_once: if the caller rolls back, neither the change
    nor the marker survives, so a failed boot cannot leave a false marker."""
    path = tmp_path / "tx.db"
    con = db.connect(path)
    con.execute("CREATE TABLE t (v INTEGER)")
    con.commit()

    def apply(c):
        c.execute("INSERT INTO t VALUES (1)")

    assert db.run_once(con, "m1", apply) is True
    con.rollback()
    assert db.migration_applied(con, "m1") is False
    assert con.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0

    assert db.run_once(con, "m1", apply) is True
    con.commit()
    assert db.run_once(con, "m1", apply) is False          # recorded now
    assert con.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1
    con.close()


def test_run_once_does_not_mark_when_apply_raises(tmp_path):
    path = tmp_path / "raise.db"
    con = db.connect(path)

    def boom(_c):
        raise RuntimeError("migration exploded")

    with pytest.raises(RuntimeError):
        db.run_once(con, "m2", boom)
    assert db.migration_applied(con, "m2") is False
    con.close()
