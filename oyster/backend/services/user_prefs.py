"""Per-account preferences — currently just "which project am I working in?".

Oyster's ``projects.is_active`` is a SINGLE global pointer, built when the app
had one operator. It still drives the admin-only shared surfaces (documents,
rag, execution). But now every signed-in account can create and switch between
its own private projects, and one account switching project must not move
another account (least of all the operators). So each account gets its OWN
active-project pointer, stored here, keyed by the Supabase subject id.

This is deliberately a separate tiny table rather than a column on ``projects``:
the pointer is a property of the USER, not of any one project, and storing it
server-side (not in the browser) means it follows the account across devices.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from threading import Lock

import config
from services import db

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    # Shared helper — the point is WAL (enabled once in main.py), which stops
    # readers and the writer from blocking each other on this shared file.
    # See services/db.py.
    return db.connect(_DB_PATH)


def init_db() -> None:
    with _lock:
        con = _conn()
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS user_prefs (
                user_id           TEXT PRIMARY KEY,
                active_project_id TEXT,
                updated_at        TEXT NOT NULL
            )
            """
        )
        con.commit()
        con.close()


def get_active_project_id(user_id: str) -> str | None:
    """The caller's chosen active project, or None if they've never set one."""
    if not user_id:
        return None
    with _conn() as con:
        row = con.execute(
            "SELECT active_project_id FROM user_prefs WHERE user_id = ?", (user_id,)
        ).fetchone()
    return row["active_project_id"] if row and row["active_project_id"] else None


def set_active_project_id(user_id: str, project_id: str) -> None:
    if not user_id:
        return
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO user_prefs (user_id, active_project_id, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET active_project_id = excluded.active_project_id, "
            "updated_at = excluded.updated_at",
            (user_id, project_id, now),
        )
        con.commit()
        con.close()


def clear_active_project(user_id: str) -> None:
    """Forget the caller's active project (e.g. after they delete it), so
    resolution falls back to their personal workspace."""
    if not user_id:
        return
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE user_prefs SET active_project_id = NULL, updated_at = ? WHERE user_id = ?",
            (_ts(), user_id),
        )
        con.commit()
        con.close()
