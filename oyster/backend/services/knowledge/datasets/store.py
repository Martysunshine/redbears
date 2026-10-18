"""SQLite persistence for Dataset RAG: installed datasets, per-row provenance
(for citation + cross-dataset dedup), and import job history."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from threading import Lock

import config

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS installed_datasets (
                dataset_id      TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                hf_dataset_id   TEXT,
                commit_sha      TEXT,
                row_count       INTEGER NOT NULL DEFAULT 0,
                rows_blocked_sensitive INTEGER NOT NULL DEFAULT 0,
                rows_deduped    INTEGER NOT NULL DEFAULT 0,
                chunk_count     INTEGER NOT NULL DEFAULT 0,
                licence         TEXT,
                installed_at    TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                enabled         INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS dataset_chunks (
                id              TEXT PRIMARY KEY,
                dataset_id      TEXT NOT NULL,
                row_index       INTEGER NOT NULL,
                content_hash    TEXT NOT NULL,
                source_url      TEXT,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_import_jobs (
                id              TEXT PRIMARY KEY,
                dataset_id      TEXT NOT NULL,
                status          TEXT NOT NULL,
                rows_fetched    INTEGER NOT NULL DEFAULT 0,
                rows_deduped    INTEGER NOT NULL DEFAULT 0,
                rows_blocked_sensitive INTEGER NOT NULL DEFAULT 0,
                chunks          INTEGER NOT NULL DEFAULT 0,
                error           TEXT,
                started_at      TEXT NOT NULL,
                finished_at     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_dc_dataset ON dataset_chunks(dataset_id);
            CREATE INDEX IF NOT EXISTS idx_dc_hash ON dataset_chunks(content_hash);
            CREATE INDEX IF NOT EXISTS idx_dj_dataset ON dataset_import_jobs(dataset_id, started_at DESC);
            """
        )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Installed datasets
# ---------------------------------------------------------------------------

def installed_map() -> dict[str, dict]:
    with _conn() as con:
        rows = con.execute("SELECT * FROM installed_datasets").fetchall()
    return {r["dataset_id"]: dict(r) for r in rows}


def is_installed(dataset_id: str) -> bool:
    return dataset_id in installed_map()


def upsert_installed(dataset_id: str, *, name: str, hf_dataset_id: str | None, commit_sha: str | None,
                     row_count: int, rows_blocked_sensitive: int, rows_deduped: int,
                     chunk_count: int, licence: str | None) -> None:
    now = _ts()
    prev = installed_map().get(dataset_id)
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO installed_datasets (dataset_id,name,hf_dataset_id,commit_sha,row_count,"
            "rows_blocked_sensitive,rows_deduped,chunk_count,licence,installed_at,updated_at,enabled) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(dataset_id) DO UPDATE SET name=excluded.name,hf_dataset_id=excluded.hf_dataset_id,"
            "commit_sha=excluded.commit_sha,row_count=excluded.row_count,"
            "rows_blocked_sensitive=excluded.rows_blocked_sensitive,rows_deduped=excluded.rows_deduped,"
            "chunk_count=excluded.chunk_count,licence=excluded.licence,updated_at=excluded.updated_at",
            (dataset_id, name, hf_dataset_id, commit_sha, row_count, rows_blocked_sensitive,
             rows_deduped, chunk_count, licence, now, now, 1 if prev is None else prev["enabled"]),
        )
        con.commit()
        con.close()


def set_enabled(dataset_id: str, enabled: bool) -> bool:
    if not is_installed(dataset_id):
        return False
    with _lock:
        con = _conn()
        con.execute("UPDATE installed_datasets SET enabled=?, updated_at=? WHERE dataset_id=?",
                    (1 if enabled else 0, _ts(), dataset_id))
        con.commit()
        con.close()
    return True


def delete_installed(dataset_id: str) -> bool:
    if not is_installed(dataset_id):
        return False
    with _lock:
        con = _conn()
        con.execute("DELETE FROM installed_datasets WHERE dataset_id=?", (dataset_id,))
        con.execute("DELETE FROM dataset_chunks WHERE dataset_id=?", (dataset_id,))
        con.commit()
        con.close()
    return True


# ---------------------------------------------------------------------------
# Chunk provenance / cross-dataset dedup
# ---------------------------------------------------------------------------

def hash_exists(content_hash: str) -> bool:
    """Global (cross-dataset) dedup check — catches verbatim overlap between
    e.g. Fenrir and Trendyol without needing semantic similarity."""
    with _conn() as con:
        row = con.execute("SELECT 1 FROM dataset_chunks WHERE content_hash = ? LIMIT 1",
                          (content_hash,)).fetchone()
    return row is not None


def insert_chunk_records(dataset_id: str, records: list[dict]) -> None:
    if not records:
        return
    now = _ts()
    with _lock:
        con = _conn()
        con.executemany(
            "INSERT OR IGNORE INTO dataset_chunks (id,dataset_id,row_index,content_hash,source_url,created_at) "
            "VALUES (?,?,?,?,?,?)",
            [(r["id"], dataset_id, r["row_index"], r["content_hash"], r.get("source_url"), now)
             for r in records],
        )
        con.commit()
        con.close()


def get_chunk(chunk_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM dataset_chunks WHERE id = ?", (chunk_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Import jobs
# ---------------------------------------------------------------------------

def start_job(dataset_id: str) -> str:
    job_id = f"dsjob-{uuid.uuid4().hex[:10]}"
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO dataset_import_jobs (id,dataset_id,status,started_at) VALUES (?,?,?,?)",
            (job_id, dataset_id, "running", _ts()),
        )
        con.commit()
        con.close()
    return job_id


def finish_job(job_id: str, status: str, **fields) -> None:
    sets, params = ["status = ?", "finished_at = ?"], [status, _ts()]
    for k in ("rows_fetched", "rows_deduped", "rows_blocked_sensitive", "chunks", "error"):
        if k in fields:
            sets.append(f"{k} = ?")
            params.append(fields[k])
    params.append(job_id)
    with _lock:
        con = _conn()
        con.execute(f"UPDATE dataset_import_jobs SET {', '.join(sets)} WHERE id = ?", params)
        con.commit()
        con.close()


def list_jobs(dataset_id: str | None = None) -> list[dict]:
    sql = "SELECT * FROM dataset_import_jobs"
    params: list = []
    if dataset_id:
        sql += " WHERE dataset_id = ?"
        params.append(dataset_id)
    sql += " ORDER BY started_at DESC LIMIT 50"
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]
