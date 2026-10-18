"""SQLite persistence for the training pipeline: consent, dataset snapshots,
jobs, and versioned adapters. Completely separate tables from RAG/memory —
this pipeline is disabled by default and only ever touches a project that has
explicitly opted in (``training_consent.allowed``)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
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


@contextmanager
def _conn_ctx():
    """Read-path connection that is actually closed afterwards.

    ``with sqlite3.connect(...) as con`` commits or rolls back the transaction —
    it does NOT close the connection. Write paths here already call
    ``con.close()`` explicitly; the read paths did not, so they leaned on
    refcounting to clean up. That is fine in practice under CPython but leaks
    whenever an exception keeps the frame alive, and ``get_consent`` sits on the
    ordinary ``/settings`` request path. This makes reads match writes.
    """
    con = _conn()
    try:
        yield con
    finally:
        con.close()


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS training_consent (
                project_id      TEXT PRIMARY KEY,
                allowed         INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS training_datasets (
                id                  TEXT PRIMARY KEY,
                project_id          TEXT NOT NULL,
                version             TEXT NOT NULL,
                example_count       INTEGER NOT NULL,
                train_count         INTEGER NOT NULL,
                val_count           INTEGER NOT NULL,
                test_count          INTEGER NOT NULL,
                excluded_sensitive  INTEGER NOT NULL DEFAULT 0,
                excluded_duplicate  INTEGER NOT NULL DEFAULT 0,
                manifest_path       TEXT NOT NULL,
                notes               TEXT NOT NULL DEFAULT '',
                created_at          TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS training_jobs (
                id              TEXT PRIMARY KEY,
                project_id      TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                base_model      TEXT NOT NULL,
                status          TEXT NOT NULL,
                config          TEXT NOT NULL DEFAULT '{}',
                error           TEXT,
                started_at      TEXT NOT NULL,
                finished_at     TEXT
            );
            CREATE TABLE IF NOT EXISTS training_adapters (
                id                  TEXT PRIMARY KEY,
                project_id          TEXT NOT NULL,
                job_id              TEXT NOT NULL,
                version             INTEGER NOT NULL,
                base_model          TEXT NOT NULL,
                adapter_path        TEXT,
                eval_metrics        TEXT NOT NULL DEFAULT '{}',
                safety_eval         TEXT NOT NULL DEFAULT '{}',
                approved_for_deploy INTEGER NOT NULL DEFAULT 0,
                approval_notes      TEXT NOT NULL DEFAULT '',
                active              INTEGER NOT NULL DEFAULT 0,
                rollback_of         TEXT,
                created_at          TEXT NOT NULL,
                approved_at         TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_td_project ON training_datasets(project_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_tj_project ON training_jobs(project_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_ta_project ON training_adapters(project_id, version DESC);
            """
        )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------

def get_consent(project_id: str) -> dict:
    with _conn_ctx() as con:
        row = con.execute("SELECT * FROM training_consent WHERE project_id = ?", (project_id,)).fetchone()
    if row is None:
        return {"project_id": project_id, "allowed": False, "updated_at": None}
    d = dict(row)
    d["allowed"] = bool(d["allowed"])
    return d


def set_consent(project_id: str, allowed: bool) -> dict:
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO training_consent (project_id,allowed,updated_at) VALUES (?,?,?) "
            "ON CONFLICT(project_id) DO UPDATE SET allowed=excluded.allowed,updated_at=excluded.updated_at",
            (project_id, int(allowed), now),
        )
        con.commit()
        con.close()
    return get_consent(project_id)


# ---------------------------------------------------------------------------
# Dataset snapshots
# ---------------------------------------------------------------------------

def create_dataset(project_id: str, version: str, *, example_count: int, train_count: int,
                   val_count: int, test_count: int, excluded_sensitive: int,
                   excluded_duplicate: int, manifest_path: str, notes: str = "") -> dict:
    did = f"tds-{uuid.uuid4().hex[:10]}"
    now = _ts()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO training_datasets (id,project_id,version,example_count,train_count,"
            "val_count,test_count,excluded_sensitive,excluded_duplicate,manifest_path,notes,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (did, project_id, version, example_count, train_count, val_count, test_count,
             excluded_sensitive, excluded_duplicate, manifest_path, notes, now),
        )
        con.commit()
        con.close()
    return get_dataset(project_id, version)


def get_dataset(project_id: str, version: str) -> dict | None:
    with _conn_ctx() as con:
        row = con.execute("SELECT * FROM training_datasets WHERE project_id = ? AND version = ?",
                          (project_id, version)).fetchone()
    return dict(row) if row else None


def list_datasets(project_id: str) -> list[dict]:
    with _conn_ctx() as con:
        rows = con.execute("SELECT * FROM training_datasets WHERE project_id = ? ORDER BY created_at DESC",
                          (project_id,)).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def create_job(project_id: str, dataset_version: str, base_model: str, config_: dict) -> str:
    job_id = f"tjob-{uuid.uuid4().hex[:10]}"
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO training_jobs (id,project_id,dataset_version,base_model,status,config,started_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (job_id, project_id, dataset_version, base_model, "queued", json.dumps(config_), _ts()),
        )
        con.commit()
        con.close()
    return job_id


def update_job(job_id: str, *, status: str | None = None, error: str | None = None,
              finished: bool = False) -> None:
    sets, params = [], []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if error is not None:
        sets.append("error = ?")
        params.append(error)
    if finished:
        sets.append("finished_at = ?")
        params.append(_ts())
    if not sets:
        return
    params.append(job_id)
    with _lock:
        con = _conn()
        con.execute(f"UPDATE training_jobs SET {', '.join(sets)} WHERE id = ?", params)
        con.commit()
        con.close()


def get_job(job_id: str) -> dict | None:
    with _conn_ctx() as con:
        row = con.execute("SELECT * FROM training_jobs WHERE id = ?", (job_id,)).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["config"] = json.loads(d["config"])
    return d


_LIVE_STATUSES = ("queued", "running")


def active_job() -> dict | None:
    """The job currently entitled to the box, across all projects.

    Deliberately global rather than per-project: the constraint being protected
    is one machine's RAM, and two concurrent runs would each load a full base
    model. Ordered OLDEST-first so it doubles as a race resolver — two starts
    that interleave both see the same winner, so exactly one proceeds.
    """
    with _conn_ctx() as con:
        row = con.execute(
            f"SELECT * FROM training_jobs WHERE status IN ({','.join('?' * len(_LIVE_STATUSES))}) "
            "ORDER BY started_at ASC LIMIT 1", _LIVE_STATUSES).fetchone()
    return dict(row) if row else None


def reap_orphaned_jobs() -> int:
    """Close out jobs that were still live when the process last stopped.

    Training now runs in a child process, so a job left at "queued"/"running" at
    startup is definitionally dead — its worker died with the previous process.
    Without this, a crashed run stays "running" forever and (with the
    concurrency guard above) would block every future job. Returns the count.
    """
    with _lock:
        con = _conn()
        cur = con.execute(
            f"UPDATE training_jobs SET status = 'interrupted', error = ?, finished_at = ? "
            f"WHERE status IN ({','.join('?' * len(_LIVE_STATUSES))})",
            ("Server restarted while this job was running; the worker did not survive.",
             _ts(), *_LIVE_STATUSES),
        )
        con.commit()
        count = cur.rowcount
        con.close()
    return count


def list_jobs(project_id: str) -> list[dict]:
    with _conn_ctx() as con:
        rows = con.execute("SELECT * FROM training_jobs WHERE project_id = ? ORDER BY started_at DESC",
                          (project_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["config"] = json.loads(d["config"])
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Adapters (versioned, approval-gated, single active pointer per project)
# ---------------------------------------------------------------------------

def create_adapter(project_id: str, job_id: str, adapter_id: str, base_model: str,
                   adapter_path: str | None, eval_metrics: dict, safety_eval: dict) -> dict:
    existing = list_adapters(project_id)
    version = (max((a["version"] for a in existing), default=0)) + 1
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO training_adapters (id,project_id,job_id,version,base_model,adapter_path,"
            "eval_metrics,safety_eval,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (adapter_id, project_id, job_id, version, base_model, adapter_path,
             json.dumps(eval_metrics), json.dumps(safety_eval), _ts()),
        )
        con.commit()
        con.close()
    return get_adapter(adapter_id)


def _adapter_row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["eval_metrics"] = json.loads(d["eval_metrics"])
    d["safety_eval"] = json.loads(d["safety_eval"])
    d["approved_for_deploy"] = bool(d["approved_for_deploy"])
    d["active"] = bool(d["active"])
    return d


def get_adapter(adapter_id: str) -> dict | None:
    with _conn_ctx() as con:
        row = con.execute("SELECT * FROM training_adapters WHERE id = ?", (adapter_id,)).fetchone()
    return _adapter_row_to_dict(row) if row else None


def list_adapters(project_id: str) -> list[dict]:
    with _conn_ctx() as con:
        rows = con.execute("SELECT * FROM training_adapters WHERE project_id = ? ORDER BY version DESC",
                          (project_id,)).fetchall()
    return [_adapter_row_to_dict(r) for r in rows]


def approve_adapter(adapter_id: str, notes: str = "") -> dict | None:
    if get_adapter(adapter_id) is None:
        return None
    with _lock:
        con = _conn()
        con.execute("UPDATE training_adapters SET approved_for_deploy=1, approval_notes=?, approved_at=? WHERE id=?",
                    (notes, _ts(), adapter_id))
        con.commit()
        con.close()
    return get_adapter(adapter_id)


def set_active_adapter(project_id: str, adapter_id: str) -> dict | None:
    adapter = get_adapter(adapter_id)
    if adapter is None or adapter["project_id"] != project_id:
        return None
    with _lock:
        con = _conn()
        con.execute("UPDATE training_adapters SET active=0 WHERE project_id=?", (project_id,))
        con.execute("UPDATE training_adapters SET active=1 WHERE id=?", (adapter_id,))
        con.commit()
        con.close()
    return get_adapter(adapter_id)


def get_active_adapter(project_id: str) -> dict | None:
    with _conn_ctx() as con:
        row = con.execute("SELECT * FROM training_adapters WHERE project_id = ? AND active = 1",
                          (project_id,)).fetchone()
    return _adapter_row_to_dict(row) if row else None
