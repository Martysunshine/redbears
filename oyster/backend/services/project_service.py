"""Project System — the aggregate root for Oyster (Local Alpha).

Every engagement is a *project*. A project owns its scope, and (as later slices
land) its memory, findings, documents, artifacts, timeline and tool history are
all keyed by ``project_id``.

Local Alpha keeps this self-contained: projects live in the existing SQLite
database (``config.MEMORY_DB``) — no Postgres, no external services. A single
``default`` project is auto-created on init so every pre-existing global
endpoint keeps working exactly as before (its data belongs to ``default``).

Scope bridge
------------
The active project's scope is mirrored into the legacy global scope file
(``scope_service``) whenever a project is activated or its scope is updated.
This means every existing scope-gated endpoint (``/redteam/*``, ``/code/review``)
keeps reading scope the way it always has — it just now reflects the *active
project*. No endpoint had to change.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from threading import Lock

import config
from services import db

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()

DEFAULT_PROJECT_ID = "default"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pid() -> str:
    return str(uuid.uuid4())[:12]


def _conn() -> sqlite3.Connection:
    # Shared helper — the point is WAL (enabled once in main.py), which stops
    # readers and the writer from blocking each other on this shared file.
    # See services/db.py.
    return db.connect(_DB_PATH)


# ---------------------------------------------------------------------------
# Schema + migrations
# ---------------------------------------------------------------------------

def _column_exists(con: sqlite3.Connection, table: str, column: str) -> bool:
    rows = con.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def init_db() -> None:
    """Create project tables, backfill ``project_id`` onto memory tables, and
    guarantee a ``default`` project exists. Idempotent."""
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                description  TEXT NOT NULL DEFAULT '',
                status       TEXT NOT NULL DEFAULT 'active',
                scope        TEXT NOT NULL DEFAULT '{}',
                is_active    INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_events (
                id          TEXT PRIMARY KEY,
                project_id  TEXT NOT NULL,
                ts          TEXT NOT NULL,
                actor       TEXT NOT NULL DEFAULT 'system',
                kind        TEXT NOT NULL,
                summary     TEXT NOT NULL DEFAULT '',
                ref_type    TEXT,
                ref_id      TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_evt_project ON project_events(project_id);
            """
        )

        # Backfill project_id onto the memory tables so all memory becomes
        # project-scoped without dropping any existing rows (default -> 'default').
        for table in ("memories", "scan_results", "attack_surface"):
            if _table_exists(con, table) and not _column_exists(con, table, "project_id"):
                con.execute(
                    f"ALTER TABLE {table} ADD COLUMN project_id TEXT NOT NULL DEFAULT '{DEFAULT_PROJECT_ID}'"
                )

        # Ownership. The projects table was born without an owner because Oyster
        # was single-operator; ownership was faked by the id convention
        # (u_<sub> = a user's workspace, anon_<hash> = a guest sandbox,
        # everything else = a shared operator project). That convention leaked:
        # list_projects() returned every row, so any operator saw every user's
        # private workspace (and their email in the name). owner_id makes
        # ownership explicit and queryable. Idempotent: the column is added once,
        # then backfilled from the id convention exactly once (the WHERE guards
        # make a second run a no-op).
        if not _column_exists(con, "projects", "owner_id"):
            con.execute("ALTER TABLE projects ADD COLUMN owner_id TEXT")
            # u_<sub> personal workspace -> owned by that sub.
            con.execute(
                "UPDATE projects SET owner_id = substr(id, 3) "
                "WHERE substr(id, 1, 2) = 'u_' AND (owner_id IS NULL OR owner_id = '')"
            )
            # anon_<hash> guest sandboxes and the shared operator projects
            # (default + legacy random ids) stay owner_id NULL on purpose:
            # anon sandboxes are never listed or managed; the shared bucket is
            # visible to admins only (see _visible_where).
        con.execute("CREATE INDEX IF NOT EXISTS idx_proj_owner ON projects(owner_id)")

        # Ensure a default project exists and is active if nothing else is.
        row = con.execute("SELECT COUNT(*) AS n FROM projects").fetchone()
        if row["n"] == 0:
            now = _ts()
            con.execute(
                "INSERT INTO projects (id,name,description,status,scope,is_active,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    DEFAULT_PROJECT_ID,
                    "Default Engagement",
                    "Auto-created default project. Existing global data belongs here.",
                    "active",
                    "{}",
                    1,
                    now,
                    now,
                ),
            )
        con.commit()
        con.close()

    # Seed the default project's scope from whatever the global scope file holds,
    # so the bridge is consistent from the first boot.
    try:
        from services import scope_service

        active = get_active_project()
        if active and not json.loads(active["scope"] or "{}"):
            existing = scope_service.load_scope()
            if existing and any(existing.get(k) for k in ("domains", "ip_ranges", "allowed_targets", "engagement_name")):
                _write_scope(active["id"], existing)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _row_to_project(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["scope"] = json.loads(d.get("scope") or "{}")
    except Exception:
        d["scope"] = {}
    d["is_active"] = bool(d.get("is_active"))
    return d


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_projects() -> list[dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()
    return [_row_to_project(r) for r in rows]


# ---------------------------------------------------------------------------
# Ownership + visibility
# ---------------------------------------------------------------------------
#
# owner_id makes "whose project is this?" explicit. Two module-level helpers
# keep the tier/sub extraction in one place; the SQL clause is shared by
# list_projects_for and can_manage so visibility and manageability can never
# drift apart.

def _sub(identity: dict | None) -> str:
    """The immutable per-account id an owned project is keyed by. Matches the
    id project_context mints for a personal workspace (``u_<sub>``)."""
    if not identity:
        return ""
    return identity.get("sub") or identity.get("email") or ""


def _visible_where(identity: dict | None) -> tuple[str, list]:
    """SQL WHERE fragment (without the leading WHERE) selecting the projects a
    caller may see, plus its params.

    **Everyone — admins included — sees only what they own.** There is no
    shared bucket and no inherited history: a new account starts on a clean
    slate with its own workspace and whatever it creates. The legacy rows
    (``default`` / "Default Engagement", pre-account operator projects, and the
    ``anon_*`` guest sandboxes) all have no owner, so they are never listed for
    anybody — they stay in the database only because internal fallbacks still
    reference ``default``, and because deleting other people's old chats is not
    ours to do.
    """
    return ("owner_id IS NOT NULL AND owner_id = ?", [_sub(identity)])


def list_projects_for(identity: dict) -> list[dict]:
    """Projects visible to this caller — replaces the unfiltered list_projects
    on the HTTP surface so one account can never enumerate another's."""
    where, params = _visible_where(identity)
    with _conn() as con:
        rows = con.execute(
            f"SELECT * FROM projects WHERE {where} ORDER BY updated_at DESC", params
        ).fetchall()
    return [_row_to_project(r) for r in rows]


def owner_of(project_id: str) -> str | None:
    with _conn() as con:
        row = con.execute("SELECT owner_id FROM projects WHERE id = ?", (project_id,)).fetchone()
    return (row["owner_id"] if row else None)


def set_owner(project_id: str, owner_id: str) -> None:
    """Stamp ownership on a project. Used to claim a home workspace whose row
    was created by ensure_project (INSERT OR IGNORE, which doesn't set owner)."""
    with _lock:
        con = _conn()
        con.execute("UPDATE projects SET owner_id = ? WHERE id = ?", (owner_id or None, project_id))
        con.commit()
        con.close()


def is_visible_to(identity: dict, project_id: str) -> bool:
    """Whether this caller may READ the project (list/get/activate/land-in)."""
    where, params = _visible_where(identity)
    with _conn() as con:
        row = con.execute(
            f"SELECT 1 FROM projects WHERE id = ? AND {where}", [project_id, *params]
        ).fetchone()
    return row is not None


def can_manage(identity: dict, project_id: str) -> bool:
    """Whether this caller may PATCH/DELETE the project. Same rule as
    visibility today (you manage what you own; admins also manage the shared
    bucket), kept as its own function so the two can diverge later without
    hunting callers."""
    return is_visible_to(identity, project_id)


def get_project(project_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    return _row_to_project(row) if row else None


def ensure_project(project_id: str, name: str, description: str = "") -> dict:
    """Create a project under a CALLER-DERIVED id, or return the existing one.

    Unlike create_project (which mints a random id and activates), this exists
    for the per-caller artifact sandboxes in services/artifact_scope.py: the id
    must be derivable from the identity so the same visitor always lands back
    in their own space. Never activates — the operators' active project must
    not be swapped out by a stranger uploading a file.
    """
    existing = get_project(project_id)
    if existing:
        return existing
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT OR IGNORE INTO projects (id,name,description,status,scope,is_active,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (project_id, name, description, "active", json.dumps({}), 0, now, now),
        )
        con.commit()
        con.close()
    return get_project(project_id)


def create_project(name: str, description: str = "", scope: dict | None = None,
                   activate: bool = True, owner_id: str | None = None) -> dict:
    """Create a project with a random id.

    ``activate`` flips the GLOBAL active pointer (``is_active``) and should only
    be True for operator-created projects — a user's per-account active project
    lives in ``user_prefs`` and must never move the shared operator pointer.
    ``owner_id`` stamps ownership so the project is visible only to its owner
    (and, for the shared bucket, to admins when left NULL).
    """
    now = _ts()
    pid = _pid()
    with _lock:
        con = _conn()
        if activate:
            con.execute("UPDATE projects SET is_active = 0")
        con.execute(
            "INSERT INTO projects (id,name,description,status,scope,is_active,owner_id,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (pid, name, description, "active", json.dumps(scope or {}),
             1 if activate else 0, owner_id or None, now, now),
        )
        con.commit()
        con.close()
    add_event(pid, "project_created", actor="user", summary=f"Project '{name}' created")
    if activate:
        _sync_active_scope_to_file(pid)
    return get_project(pid)


def update_project(project_id: str, *, name: str | None = None,
                   description: str | None = None, status: str | None = None) -> dict | None:
    if get_project(project_id) is None:
        return None
    sets, params = [], []
    if name is not None:
        sets.append("name = ?"); params.append(name)
    if description is not None:
        sets.append("description = ?"); params.append(description)
    if status is not None:
        sets.append("status = ?"); params.append(status)
    if sets:
        sets.append("updated_at = ?"); params.append(_ts())
        params.append(project_id)
        with _lock:
            con = _conn()
            con.execute(f"UPDATE projects SET {', '.join(sets)} WHERE id = ?", params)
            con.commit()
            con.close()
    return get_project(project_id)


def delete_project(project_id: str, *, force: bool = False) -> bool:
    """Delete a project and cascade its project-scoped data.

    The two guards below protect against a user deleting a project they still
    need. ``force=True`` bypasses them for the ONE legitimate caller that must
    remove a home workspace: account erasure (services/account_deletion.py),
    which is destroying the whole account, not just tidying the switcher.
    """
    if not force and project_id == DEFAULT_PROJECT_ID:
        raise ValueError("The default project cannot be deleted.")
    # A user's personal home workspace (u_<sub>) is the fallback every account
    # lands in and is auto-recreated on next use — deleting it would orphan the
    # per-user active pointer and instantly reappear, so refuse it outright
    # (unless we are erasing the whole account).
    if not force and project_id[:2] == "u_":
        raise ValueError("Your personal workspace cannot be deleted.")
    proj = get_project(project_id)
    if proj is None:
        return False
    with _lock:
        con = _conn()
        con.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        con.execute("DELETE FROM project_events WHERE project_id = ?", (project_id,))
        # Cascade every project-scoped table that lives in this same SQLite
        # database, so a deleted project leaves nothing behind that a later
        # id-collision could resurface. All guarded by _table_exists so a fresh
        # DB (or one missing an optional subsystem) never errors.
        for table in ("memories", "scan_results", "attack_surface",
                      "artifacts", "user_memories", "user_findings"):
            if _table_exists(con, table) and _column_exists(con, table, "project_id"):
                con.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
        # conversation_messages has no project_id — delete via its parent.
        if _table_exists(con, "conversations"):
            con.execute(
                "DELETE FROM conversation_messages WHERE conversation_id IN "
                "(SELECT id FROM conversations WHERE project_id = ?)",
                (project_id,),
            )
            con.execute("DELETE FROM conversations WHERE project_id = ?", (project_id,))
        con.commit()
        con.close()
    # Best-effort: remove the project's uploaded files from disk. Vector-store
    # chunks are keyed by this random project id and can never resurface (ids
    # are uuids), so they are left to be reclaimed rather than blocking the
    # delete on an async Chroma call from this sync path.
    try:
        import shutil

        art_dir = config.ARTIFACTS_DIR / project_id
        if art_dir.exists():
            shutil.rmtree(art_dir, ignore_errors=True)
    except Exception:
        pass
    # If we deleted the global active project, fall back to default.
    if proj["is_active"]:
        set_active_project(DEFAULT_PROJECT_ID)
    return True


# ---------------------------------------------------------------------------
# Active project
# ---------------------------------------------------------------------------

def get_active_project() -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM projects WHERE is_active = 1 LIMIT 1").fetchone()
        if row is None:
            row = con.execute("SELECT * FROM projects ORDER BY created_at LIMIT 1").fetchone()
    return _row_to_project(row) if row else None


def get_active_project_id() -> str:
    proj = get_active_project()
    return proj["id"] if proj else DEFAULT_PROJECT_ID


def set_active_project(project_id: str) -> dict | None:
    if get_project(project_id) is None:
        return None
    with _lock:
        con = _conn()
        con.execute("UPDATE projects SET is_active = 0")
        con.execute("UPDATE projects SET is_active = 1, updated_at = ? WHERE id = ?", (_ts(), project_id))
        con.commit()
        con.close()
    _sync_active_scope_to_file(project_id)
    add_event(project_id, "project_activated", actor="user", summary="Project activated")
    return get_project(project_id)


# ---------------------------------------------------------------------------
# Scope bridge (project scope <-> legacy global scope file)
# ---------------------------------------------------------------------------

def _write_scope(project_id: str, scope: dict) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE projects SET scope = ?, updated_at = ? WHERE id = ?",
            (json.dumps(scope or {}), _ts(), project_id),
        )
        con.commit()
        con.close()


def set_scope(project_id: str, scope: dict) -> dict | None:
    """Persist scope onto a project. If it's the active project, mirror it into
    the global scope file so existing scope-gated endpoints see it immediately."""
    if get_project(project_id) is None:
        return None
    _write_scope(project_id, scope)
    if get_active_project_id() == project_id:
        _sync_active_scope_to_file(project_id)
    add_event(project_id, "scope_updated", actor="user", summary="Engagement scope updated")
    return get_project(project_id)


def _sync_active_scope_to_file(project_id: str) -> None:
    """Write the project's stored scope into the legacy global scope file."""
    proj = get_project(project_id)
    if proj is None:
        return
    try:
        from services import scope_service

        scope_service.save_scope(proj["scope"] or {})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def add_event(project_id: str, kind: str, *, actor: str = "system",
              summary: str = "", ref_type: str | None = None, ref_id: str | None = None) -> dict:
    eid = _pid()
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO project_events (id,project_id,ts,actor,kind,summary,ref_type,ref_id) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (eid, project_id, now, actor, kind, summary, ref_type, ref_id),
        )
        con.commit()
        con.close()
    return {"id": eid, "project_id": project_id, "ts": now, "kind": kind}


def get_timeline(project_id: str, limit: int = 100) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM project_events WHERE project_id = ? ORDER BY ts DESC LIMIT ?",
            (project_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
