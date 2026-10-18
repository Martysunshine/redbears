"""Long-term memory persistence — SQLite (encrypted content) + settings.

Distinct from ``backend/memory/`` (the agent's session-scoped scan/attack-surface
scratchpad). This table holds durable, project-scoped facts/preferences/
decisions/instructions extracted from conversations (or added manually), with
provenance, status (active/pending/rejected/superseded/conflicting/deleted),
and a supersede chain so updates never silently destroy history.

Isolation model: Oyster has no multi-user auth (single local operator). "Tenant
isolation" is implemented at the ``project_id`` boundary — the same aggregate
root every other subsystem (artifacts, conversations, scope, findings) already
uses. A query for project A's memories can never return project B's rows.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from threading import Lock

import config
from services import db

from . import crypto

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()

VALID_TYPES = ("fact", "preference", "decision", "instruction", "project_detail")
VALID_STATUS = ("active", "pending", "rejected", "superseded", "conflicting", "deleted")


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())[:12]


def _conn() -> sqlite3.Connection:
    # Shared helper — the point is WAL (enabled once in main.py), which stops
    # readers and the writer from blocking each other on this shared file.
    # See services/db.py.
    return db.connect(_DB_PATH)


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS user_memories (
                id                  TEXT PRIMARY KEY,
                project_id          TEXT NOT NULL,
                type                TEXT NOT NULL,
                subject             TEXT NOT NULL,
                content_enc         TEXT NOT NULL,
                status              TEXT NOT NULL DEFAULT 'active',
                confidence          REAL NOT NULL DEFAULT 0.8,
                source              TEXT NOT NULL DEFAULT 'manual',
                origin_conversation_id TEXT,
                origin_message_id  TEXT,
                supersedes_id       TEXT,
                conflict_group      TEXT,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL,
                deleted_at          TEXT
            );
            CREATE TABLE IF NOT EXISTS user_memory_settings (
                project_id          TEXT PRIMARY KEY,
                memory_enabled       INTEGER NOT NULL DEFAULT 1,
                auto_save            INTEGER NOT NULL DEFAULT 1,
                ask_before_saving    INTEGER NOT NULL DEFAULT 0,
                updated_at           TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_um_project ON user_memories(project_id, status);
            CREATE INDEX IF NOT EXISTS idx_um_subject ON user_memories(project_id, subject);
            CREATE INDEX IF NOT EXISTS idx_um_conflict ON user_memories(conflict_group);
            """
        )
        con.commit()
        con.close()


def _row_to_dict(row: sqlite3.Row, reveal: bool = True) -> dict:
    d = dict(row)
    enc = d.pop("content_enc")
    d["content"] = crypto.decrypt(enc) if reveal else None
    return d


# ---------------------------------------------------------------------------
# Settings (per project — the isolation/tenant boundary in this single-operator app)
# ---------------------------------------------------------------------------

_DEFAULT_SETTINGS = {"memory_enabled": True, "auto_save": True, "ask_before_saving": False}


def get_settings(project_id: str) -> dict:
    with _conn() as con:
        row = con.execute("SELECT * FROM user_memory_settings WHERE project_id = ?",
                          (project_id,)).fetchone()
    if row is None:
        return {"project_id": project_id, **_DEFAULT_SETTINGS, "updated_at": None}
    d = dict(row)
    for k in ("memory_enabled", "auto_save", "ask_before_saving"):
        d[k] = bool(d[k])
    return d


def set_settings(project_id: str, **fields) -> dict:
    current = get_settings(project_id)
    current.update({k: v for k, v in fields.items() if v is not None and k in _DEFAULT_SETTINGS})
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO user_memory_settings (project_id,memory_enabled,auto_save,"
            "ask_before_saving,updated_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(project_id) DO UPDATE SET memory_enabled=excluded.memory_enabled,"
            "auto_save=excluded.auto_save,ask_before_saving=excluded.ask_before_saving,"
            "updated_at=excluded.updated_at",
            (project_id, int(current["memory_enabled"]), int(current["auto_save"]),
             int(current["ask_before_saving"]), now),
        )
        con.commit()
        con.close()
    return get_settings(project_id)


# ---------------------------------------------------------------------------
# Memory CRUD
# ---------------------------------------------------------------------------

def insert_memory(
    project_id: str, type_: str, subject: str, content: str, *,
    status: str = "active", confidence: float = 0.8, source: str = "manual",
    origin_conversation_id: str | None = None, origin_message_id: str | None = None,
    supersedes_id: str | None = None, conflict_group: str | None = None,
) -> dict:
    mid = _id()
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO user_memories (id,project_id,type,subject,content_enc,status,"
            "confidence,source,origin_conversation_id,origin_message_id,supersedes_id,"
            "conflict_group,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mid, project_id, type_, subject, crypto.encrypt(content), status, confidence,
             source, origin_conversation_id, origin_message_id, supersedes_id,
             conflict_group, now, now),
        )
        con.commit()
        con.close()
    return get_memory(mid)


def get_memory(memory_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM user_memories WHERE id = ?", (memory_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_memories(project_id: str, *, status: str | list[str] | None = "active",
                  type_: str | None = None, limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM user_memories WHERE project_id = ?"
    params: list = [project_id]
    if status:
        statuses = [status] if isinstance(status, str) else list(status)
        sql += f" AND status IN ({','.join('?' * len(statuses))})"
        params.extend(statuses)
    if type_:
        sql += " AND type = ?"
        params.append(type_)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def search_memories_text(project_id: str, query: str, status: str = "active", limit: int = 50) -> list[dict]:
    """Lexical fallback search (decrypts to filter — SQLite can't index ciphertext)."""
    candidates = list_memories(project_id, status=status, limit=2000)
    q = query.lower()
    hits = [m for m in candidates if q in m["content"].lower() or q in m["subject"].lower()]
    return hits[:limit]


def update_memory(memory_id: str, *, content: str | None = None, subject: str | None = None,
                  status: str | None = None, type_: str | None = None,
                  conflict_group: str | None = None) -> dict | None:
    existing = get_memory(memory_id)
    if existing is None:
        return None
    now = _ts()
    sets, params = ["updated_at = ?"], [now]
    if content is not None:
        sets.append("content_enc = ?")
        params.append(crypto.encrypt(content))
    if subject is not None:
        sets.append("subject = ?")
        params.append(subject)
    if status is not None:
        sets.append("status = ?")
        params.append(status)
        if status == "deleted":
            sets.append("deleted_at = ?")
            params.append(now)
    if type_ is not None:
        sets.append("type = ?")
        params.append(type_)
    if conflict_group is not None:
        sets.append("conflict_group = ?")
        params.append(conflict_group)
    params.append(memory_id)
    with _lock:
        con = _conn()
        con.execute(f"UPDATE user_memories SET {', '.join(sets)} WHERE id = ?", params)
        con.commit()
        con.close()
    return get_memory(memory_id)


def delete_memory(memory_id: str, hard: bool = False) -> bool:
    existing = get_memory(memory_id)
    if existing is None:
        return False
    with _lock:
        con = _conn()
        if hard:
            con.execute("DELETE FROM user_memories WHERE id = ?", (memory_id,))
        else:
            con.execute("UPDATE user_memories SET status='deleted', deleted_at=?, updated_at=? WHERE id = ?",
                        (_ts(), _ts(), memory_id))
        con.commit()
        con.close()
    return True


def delete_all_for_project(project_id: str, hard: bool = True) -> int:
    with _lock:
        con = _conn()
        if hard:
            n = con.execute("DELETE FROM user_memories WHERE project_id = ?", (project_id,)).rowcount
        else:
            now = _ts()
            n = con.execute(
                "UPDATE user_memories SET status='deleted', deleted_at=?, updated_at=? WHERE project_id = ? AND status != 'deleted'",
                (now, now, project_id),
            ).rowcount
        con.commit()
        con.close()
    return n


def conflict_group_members(project_id: str, conflict_group: str) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM user_memories WHERE project_id = ? AND conflict_group = ?",
            (project_id, conflict_group),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def list_conflicts(project_id: str) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT DISTINCT conflict_group FROM user_memories WHERE project_id = ? "
            "AND status = 'conflicting' AND conflict_group IS NOT NULL", (project_id,)
        ).fetchall()
    groups = []
    for r in rows:
        members = list_memories(project_id, status="conflicting", limit=200)
        members = [m for m in members if m["conflict_group"] == r["conflict_group"]]
        groups.append({"conflict_group": r["conflict_group"], "members": members})
    return groups


def export_all(project_id: str) -> dict:
    with _conn() as con:
        rows = con.execute("SELECT * FROM user_memories WHERE project_id = ? ORDER BY created_at",
                          (project_id,)).fetchall()
    return {
        "project_id": project_id,
        "exported_at": _ts(),
        "memories": [_row_to_dict(r) for r in rows],
        "settings": get_settings(project_id),
    }


def stats(project_id: str) -> dict:
    with _conn() as con:
        rows = con.execute(
            "SELECT status, COUNT(*) as n FROM user_memories WHERE project_id = ? GROUP BY status",
            (project_id,),
        ).fetchall()
    return {r["status"]: r["n"] for r in rows}
