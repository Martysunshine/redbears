"""Artifact records — durable, project-scoped (SQLite, same DB as projects)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from threading import Lock

import config

_DB_PATH = config.MEMORY_DB
_lock = Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())[:12]


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


# Columns added after the original text-only schema shipped. Added idempotently
# via ALTER TABLE so existing databases upgrade in place (no data loss).
_MIGRATIONS: list[tuple[str, str]] = [
    ("original_filename", "TEXT"),
    ("analysis_status", "TEXT NOT NULL DEFAULT 'pending'"),  # pending|ok|skipped|failed
    ("storage_path", "TEXT"),
    ("thumbnail_path", "TEXT"),
    ("metadata", "TEXT"),  # JSON blob: dimensions, EXIF, duration, frames, transcript…
]


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id             TEXT PRIMARY KEY,
                project_id     TEXT NOT NULL,
                conversation_id TEXT,
                kind           TEXT NOT NULL DEFAULT 'file',   -- file | note | image | video
                filename       TEXT NOT NULL,
                relative_path  TEXT,
                mime           TEXT,
                sha256         TEXT,
                size           INTEGER DEFAULT 0,
                status         TEXT NOT NULL DEFAULT 'processing', -- see status states below
                extract_status TEXT NOT NULL DEFAULT 'pending',    -- pending | ok | failed
                index_status   TEXT NOT NULL DEFAULT 'pending',    -- pending | indexed | failed | skipped
                chunk_count    INTEGER DEFAULT 0,
                error          TEXT,
                text           TEXT,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_art_project ON artifacts(project_id);
            CREATE INDEX IF NOT EXISTS idx_art_sha ON artifacts(project_id, sha256);
            """
        )
        existing = {r["name"] for r in con.execute("PRAGMA table_info(artifacts)").fetchall()}
        for col, decl in _MIGRATIONS:
            if col not in existing:
                con.execute(f"ALTER TABLE artifacts ADD COLUMN {col} {decl}")
        con.commit()
        con.close()


# What an API caller may see. storage_path and thumbnail_path are ABSOLUTE
# server filesystem paths; they used to be in this projection, and therefore in
# every artifact listing — which anonymous visitors can read. They are private
# now: the file/thumbnail routes fetch them with ``with_paths=True`` after
# ownership is established, and nothing else needs them.
_PUBLIC = (
    "id, project_id, conversation_id, kind, filename, original_filename, relative_path, "
    "mime, sha256, size, status, extract_status, index_status, analysis_status, chunk_count, "
    "error, metadata, created_at, updated_at"
)
_PRIVATE_PATHS = ", storage_path, thumbnail_path"


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    if "metadata" in d:
        raw = d.get("metadata")
        try:
            d["metadata"] = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            d["metadata"] = {}
    return d


def create(project_id: str, filename: str, *, kind: str = "file", mime: str | None = None,
           sha256: str | None = None, size: int = 0, relative_path: str | None = None,
           conversation_id: str | None = None, original_filename: str | None = None,
           storage_path: str | None = None, status: str = "processing") -> dict:
    aid = _id()
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO artifacts (id,project_id,conversation_id,kind,filename,original_filename,"
            "relative_path,mime,sha256,size,status,extract_status,index_status,analysis_status,"
            "chunk_count,storage_path,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending','pending','pending',0,?,?,?)",
            (aid, project_id, conversation_id, kind, filename, original_filename or filename,
             relative_path, mime, sha256, size, status, storage_path, now, now),
        )
        con.commit()
        con.close()
    return get(aid)


def update(artifact_id: str, **fields) -> None:
    if not fields:
        return
    if "metadata" in fields and not isinstance(fields["metadata"], (str, type(None))):
        fields["metadata"] = json.dumps(fields["metadata"])
    fields["updated_at"] = _ts()
    sets = ", ".join(f"{k} = ?" for k in fields)
    with _lock:
        con = _conn()
        con.execute(f"UPDATE artifacts SET {sets} WHERE id = ?", (*fields.values(), artifact_id))
        con.commit()
        con.close()


def get(artifact_id: str, *, with_text: bool = False, with_paths: bool = False) -> dict | None:
    cols = _PUBLIC + (", text" if with_text else "") + (_PRIVATE_PATHS if with_paths else "")
    with _conn() as con:
        r = con.execute(f"SELECT {cols} FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    return _row(r) if r else None


def find_by_sha(project_id: str, sha256: str) -> dict | None:
    with _conn() as con:
        r = con.execute(
            f"SELECT {_PUBLIC} FROM artifacts WHERE project_id = ? AND sha256 = ? AND status = 'ready' LIMIT 1",
            (project_id, sha256),
        ).fetchone()
    return _row(r) if r else None


def list_for_project(project_id: str) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            f"SELECT {_PUBLIC} FROM artifacts WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ).fetchall()
    return [_row(r) for r in rows]


def delete(artifact_id: str) -> bool:
    with _lock:
        con = _conn()
        cur = con.execute("DELETE FROM artifacts WHERE id = ?", (artifact_id,))
        con.commit()
        deleted = cur.rowcount > 0
        con.close()
    return deleted
