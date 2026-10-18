"""Private projects: ownership isolation, the closed leak, and per-user active.

These are the tests standing guard over the fix for the real privacy bug — one
operator seeing every other account's private workspace (and their email) in the
project switcher, because ``list_projects`` returned every row. Everything here
runs against the temp DB the conftest redirects to; no user data is touched.
"""

from __future__ import annotations

import sqlite3

import pytest

import config
from services import (project_context as pc, project_service as ps,
                      user_prefs)


ALICE = {"tier": "user", "sub": "alice", "email": "alice@x.com"}
BOB = {"tier": "user", "sub": "bob", "email": "bob@x.com"}
ADMIN = {"tier": "admin", "sub": "adm", "email": "adm@x.com"}


@pytest.fixture
def seeded_legacy_db():
    """A DB shaped like production BEFORE owner_id existed: two user
    workspaces, a guest sandbox, the default engagement, and a legacy operator
    project — none with an owner. init_db() must backfill ownership from the id
    convention."""
    # Drop and recreate the pre-migration projects table (no owner_id column).
    con = sqlite3.connect(str(config.MEMORY_DB))
    con.execute("DROP TABLE IF EXISTS projects")
    con.execute("DROP TABLE IF EXISTS user_prefs")
    con.execute("DROP TABLE IF EXISTS user_findings")
    con.execute(
        "CREATE TABLE projects (id TEXT PRIMARY KEY, name TEXT, description TEXT DEFAULT '', "
        "status TEXT DEFAULT 'active', scope TEXT DEFAULT '{}', is_active INTEGER DEFAULT 0, "
        "created_at TEXT, updated_at TEXT)"
    )
    for rid, name, active in [
        ("u_alice", "Workspace — alice@x.com", 0),
        ("u_bob", "Workspace — bob@x.com", 0),
        ("anon_deadbeef", "Attachments — guest", 0),
        ("default", "Default Engagement", 1),
        ("abc123legacy", "Legacy Op Project", 0),
    ]:
        con.execute(
            "INSERT INTO projects (id,name,description,status,scope,is_active,created_at,updated_at) "
            "VALUES (?,?,'','active','{}',?,'t','t')",
            (rid, name, active),
        )
    con.commit()
    con.close()
    ps.init_db()
    user_prefs.init_db()
    yield


def test_backfill_from_id_convention(seeded_legacy_db):
    assert ps.owner_of("u_alice") == "alice"
    assert ps.owner_of("u_bob") == "bob"
    assert ps.owner_of("anon_deadbeef") is None      # guest sandbox, never owned
    assert ps.owner_of("default") is None            # shared bucket
    assert ps.owner_of("abc123legacy") is None       # shared bucket


def test_backfill_is_idempotent(seeded_legacy_db):
    ps.init_db()
    ps.init_db()
    assert ps.owner_of("u_alice") == "alice"


def test_user_sees_only_their_own(seeded_legacy_db):
    assert [p["id"] for p in ps.list_projects_for(ALICE)] == ["u_alice"]
    assert [p["id"] for p in ps.list_projects_for(BOB)] == ["u_bob"]


def test_nobody_sees_the_default_engagement_or_legacy_projects(seeded_legacy_db):
    """Clean slate: every account — admins included — sees ONLY what it owns.
    "Default Engagement", pre-account operator projects and guest sandboxes are
    unowned, so they are listed for nobody and cannot be inherited."""
    for who in (ALICE, BOB, ADMIN):
        seen = [p["id"] for p in ps.list_projects_for(who)]
        for hidden in ("default", "abc123legacy", "anon_deadbeef"):
            assert hidden not in seen, f"{hidden} visible to {who['sub']}"
    assert [p["id"] for p in ps.list_projects_for(ADMIN)] == []   # admin owns nothing yet


def test_default_engagement_is_unreachable_not_merely_unlisted(seeded_legacy_db):
    """Hiding a project the app can still resolve into would be theatre — the
    pointer must be refused too, so no route can land a caller in it."""
    assert not ps.is_visible_to(ADMIN, "default")
    assert not ps.can_manage(ADMIN, "default")
    user_prefs.set_active_project_id("adm", "default")
    assert pc.workspace_id(ADMIN) == "u_adm"      # stale/forbidden pointer ignored
    user_prefs.clear_active_project("adm")


def test_a_brand_new_account_starts_clean(seeded_legacy_db):
    newbie = {"tier": "user", "sub": "newbie", "email": "new@x.com"}
    assert pc.workspace_id(newbie) == "u_newbie"
    assert [p["id"] for p in ps.list_projects_for(newbie)] == ["u_newbie"]


def test_can_manage_respects_ownership(seeded_legacy_db):
    assert ps.can_manage(ALICE, "u_alice")
    assert not ps.can_manage(ALICE, "u_bob")
    assert not ps.can_manage(ADMIN, "u_alice")     # admin can't touch a user workspace
    assert not ps.can_manage(ADMIN, "default")     # nor the unowned legacy ones


def test_create_is_owned_and_private(seeded_legacy_db):
    p = ps.create_project("Alice Proj", owner_id="alice", activate=False)
    assert ps.owner_of(p["id"]) == "alice"
    # Bob cannot see or manage it.
    assert p["id"] not in [x["id"] for x in ps.list_projects_for(BOB)]
    assert not ps.can_manage(BOB, p["id"])
    # A user-created project must NOT flip the global operator pointer.
    assert ps.get_active_project_id() == "default"


def test_per_user_active_pointer_resolution(seeded_legacy_db):
    p = ps.create_project("Alice Proj", owner_id="alice", activate=False)
    user_prefs.set_active_project_id("alice", p["id"])
    assert pc.workspace_id(ALICE) == p["id"]          # alice's own choice
    assert pc.workspace_id(BOB) == "u_bob"            # no choice -> home workspace
    assert pc.workspace_id(ADMIN) == "u_adm"          # admins land in their own too


def test_stale_pointer_is_ignored(seeded_legacy_db):
    user_prefs.set_active_project_id("alice", "does_not_exist")
    # A pointer to a missing/invisible project must never be trusted.
    assert pc.workspace_id(ALICE) == "u_alice"


def test_workspace_for_path_never_lands_in_another_users_project(seeded_legacy_db):
    # Alice addressing bob's project by path resolves to HER workspace, not bob's.
    assert pc.workspace_for_path(ALICE, "u_bob") != "u_bob"
    # Addressing her own is honoured.
    p = ps.create_project("Mine", owner_id="alice", activate=False)
    assert pc.workspace_for_path(ALICE, p["id"]) == p["id"]


def test_delete_pointer_fallback(seeded_legacy_db):
    p = ps.create_project("Temp", owner_id="alice", activate=False)
    user_prefs.set_active_project_id("alice", p["id"])
    assert ps.delete_project(p["id"])
    user_prefs.clear_active_project("alice")
    assert pc.workspace_id(ALICE) == "u_alice"


def test_home_and_default_are_undeletable(seeded_legacy_db):
    for protected in ("u_alice", "default"):
        with pytest.raises(ValueError):
            ps.delete_project(protected)


def test_force_delete_bypasses_guard_for_account_erasure(seeded_legacy_db):
    """Account deletion must be able to remove a home workspace — the one
    legitimate force=True caller (services/account_deletion.py)."""
    assert ps.delete_project("u_alice", force=True)
    assert ps.get_project("u_alice") is None
