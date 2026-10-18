"""SQLite persistence for the Execution Engine.

All tables live in the existing project-scoped database (``config.MEMORY_DB``)
so Local Alpha stays self-contained — no Postgres, no queues. Every table is
created with ``CREATE TABLE IF NOT EXISTS`` and every column addition goes
through an idempotent ``ALTER`` guard, so ``init_db()`` is safe to run on an
existing database without touching or dropping any user data.

Tables
------
- ``execution_proposals``  a typed, immutable-after-approval action proposal
- ``policy_decisions``     the deterministic allow/block/approval decision
- ``approvals``            human approval bound to one proposal (+ its hash)
- ``tool_executions``      a real run of an approved proposal
- ``execution_outputs``    captured stdout/stderr + hashes + parsed observations
- ``exec_evidence``        chain-of-custody evidence records
- ``exec_findings``        findings synthesised from evidence
- ``cleanup_records``      cleanup tracking for executions that need it
- ``exec_audit``           structured, project-scoped audit trail
- ``tool_settings``        per-project enable/disable of a tool
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from threading import Lock

import config

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _table_exists(con: sqlite3.Connection, table: str) -> bool:
    return con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None


def _column_exists(con: sqlite3.Connection, table: str, column: str) -> bool:
    return any(r["name"] == column for r in con.execute(f"PRAGMA table_info({table})").fetchall())


def init_db() -> None:
    """Create execution tables + indexes. Idempotent."""
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS execution_proposals (
                id                   TEXT PRIMARY KEY,
                project_id           TEXT NOT NULL,
                conversation_id      TEXT,
                requested_by         TEXT NOT NULL DEFAULT 'local-user',
                objective            TEXT NOT NULL DEFAULT '',
                tool_id              TEXT NOT NULL,
                action_id            TEXT NOT NULL,
                targets              TEXT NOT NULL DEFAULT '[]',
                parameters           TEXT NOT NULL DEFAULT '{}',
                generated_command    TEXT NOT NULL DEFAULT '',
                sanitized_command    TEXT NOT NULL DEFAULT '',
                risk_level           TEXT NOT NULL DEFAULT 'unknown',
                execution_class      INTEGER NOT NULL DEFAULT 0,
                scope_decision       TEXT NOT NULL DEFAULT 'unknown',
                approval_requirement TEXT NOT NULL DEFAULT 'none',
                expected_outputs     TEXT NOT NULL DEFAULT '[]',
                timeout_seconds      INTEGER NOT NULL DEFAULT 30,
                network_required     INTEGER NOT NULL DEFAULT 0,
                cleanup_required     INTEGER NOT NULL DEFAULT 0,
                proposal_hash        TEXT NOT NULL DEFAULT '',
                status               TEXT NOT NULL DEFAULT 'proposed',
                created_at           TEXT NOT NULL,
                expires_at           TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_decisions (
                id                   TEXT PRIMARY KEY,
                proposal_id          TEXT NOT NULL,
                project_id           TEXT NOT NULL,
                decision             TEXT NOT NULL,
                reasons              TEXT NOT NULL DEFAULT '[]',
                matched_scope_entries TEXT NOT NULL DEFAULT '[]',
                unmatched_targets    TEXT NOT NULL DEFAULT '[]',
                prohibited_conditions TEXT NOT NULL DEFAULT '[]',
                approval_required    INTEGER NOT NULL DEFAULT 0,
                allowed_parameters   TEXT NOT NULL DEFAULT '{}',
                parameter_constraints TEXT NOT NULL DEFAULT '{}',
                maximum_runtime      INTEGER NOT NULL DEFAULT 30,
                maximum_output_size  INTEGER NOT NULL DEFAULT 1048576,
                created_at           TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approvals (
                id            TEXT PRIMARY KEY,
                proposal_id   TEXT NOT NULL,
                project_id    TEXT NOT NULL,
                decision      TEXT NOT NULL,
                approved_by   TEXT NOT NULL DEFAULT 'local-user',
                proposal_hash TEXT NOT NULL DEFAULT '',
                note          TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL,
                expires_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tool_executions (
                id                 TEXT PRIMARY KEY,
                proposal_id        TEXT NOT NULL,
                project_id         TEXT NOT NULL,
                tool_id            TEXT NOT NULL,
                action_id          TEXT NOT NULL,
                target             TEXT NOT NULL DEFAULT '',
                sanitized_command  TEXT NOT NULL DEFAULT '',
                status             TEXT NOT NULL DEFAULT 'queued',
                started_at         TEXT,
                completed_at       TEXT,
                exit_code          INTEGER,
                tool_version       TEXT,
                output_hash        TEXT,
                timeout_state      TEXT NOT NULL DEFAULT 'none',
                cancellation_state TEXT NOT NULL DEFAULT 'none',
                cleanup_state      TEXT NOT NULL DEFAULT 'none',
                error_summary      TEXT,
                created_at         TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_outputs (
                id            TEXT PRIMARY KEY,
                execution_id  TEXT NOT NULL,
                project_id    TEXT NOT NULL,
                stdout        TEXT NOT NULL DEFAULT '',
                stderr        TEXT NOT NULL DEFAULT '',
                stdout_hash   TEXT NOT NULL DEFAULT '',
                truncated     INTEGER NOT NULL DEFAULT 0,
                parsed        TEXT NOT NULL DEFAULT '{}',
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exec_evidence (
                id            TEXT PRIMARY KEY,
                project_id    TEXT NOT NULL,
                execution_id  TEXT,
                tool_id       TEXT NOT NULL DEFAULT '',
                target        TEXT NOT NULL DEFAULT '',
                title         TEXT NOT NULL DEFAULT '',
                observation   TEXT NOT NULL DEFAULT '',
                content_hash  TEXT NOT NULL DEFAULT '',
                metadata      TEXT NOT NULL DEFAULT '{}',
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS exec_findings (
                id            TEXT PRIMARY KEY,
                project_id    TEXT NOT NULL,
                title         TEXT NOT NULL DEFAULT '',
                severity      TEXT NOT NULL DEFAULT 'info',
                summary       TEXT NOT NULL DEFAULT '',
                evidence_ids  TEXT NOT NULL DEFAULT '[]',
                recommendation TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cleanup_records (
                id            TEXT PRIMARY KEY,
                execution_id  TEXT NOT NULL,
                project_id    TEXT NOT NULL,
                state         TEXT NOT NULL DEFAULT 'pending',
                detail        TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL,
                completed_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS exec_audit (
                id           TEXT PRIMARY KEY,
                project_id   TEXT NOT NULL,
                ts           TEXT NOT NULL,
                actor        TEXT NOT NULL DEFAULT 'system',
                event        TEXT NOT NULL,
                proposal_id  TEXT,
                execution_id TEXT,
                detail       TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS tool_settings (
                project_id  TEXT NOT NULL,
                tool_id     TEXT NOT NULL,
                enabled     INTEGER NOT NULL DEFAULT 1,
                updated_at  TEXT NOT NULL,
                PRIMARY KEY (project_id, tool_id)
            );

            CREATE INDEX IF NOT EXISTS idx_prop_project ON execution_proposals(project_id);
            CREATE INDEX IF NOT EXISTS idx_exec_project ON tool_executions(project_id);
            CREATE INDEX IF NOT EXISTS idx_exec_proposal ON tool_executions(proposal_id);
            CREATE INDEX IF NOT EXISTS idx_out_exec ON execution_outputs(execution_id);
            CREATE INDEX IF NOT EXISTS idx_ev_project ON exec_evidence(project_id);
            CREATE INDEX IF NOT EXISTS idx_audit_project ON exec_audit(project_id);
            """
        )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Generic row helpers
# ---------------------------------------------------------------------------

_JSON_FIELDS = {
    "targets", "parameters", "expected_outputs", "reasons", "matched_scope_entries",
    "unmatched_targets", "prohibited_conditions", "allowed_parameters",
    "parameter_constraints", "parsed", "metadata", "evidence_ids", "detail",
}


def _decode(row: sqlite3.Row) -> dict:
    d = dict(row)
    for k in list(d.keys()):
        if k in _JSON_FIELDS and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except Exception:
                pass
    for k in ("network_required", "cleanup_required", "approval_required", "truncated", "enabled"):
        if k in d and d[k] is not None:
            d[k] = bool(d[k])
    return d


def _insert(table: str, data: dict) -> None:
    cols = ", ".join(data.keys())
    ph = ", ".join("?" for _ in data)
    vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in data.values()]
    with _lock:
        con = _conn()
        con.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", vals)
        con.commit()
        con.close()


def _update(table: str, id_: str, data: dict, id_col: str = "id") -> None:
    sets = ", ".join(f"{k} = ?" for k in data)
    vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in data.values()]
    vals.append(id_)
    with _lock:
        con = _conn()
        con.execute(f"UPDATE {table} SET {sets} WHERE {id_col} = ?", vals)
        con.commit()
        con.close()


def _get(table: str, id_: str, id_col: str = "id") -> dict | None:
    with _conn() as con:
        row = con.execute(f"SELECT * FROM {table} WHERE {id_col} = ?", (id_,)).fetchone()
    return _decode(row) if row else None


def _query(table: str, where: str = "", params: tuple = (), order: str = "", limit: int | None = None) -> list[dict]:
    sql = f"SELECT * FROM {table}"
    if where:
        sql += f" WHERE {where}"
    if order:
        sql += f" ORDER BY {order}"
    if limit is not None:
        sql += f" LIMIT {int(limit)}"
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [_decode(r) for r in rows]


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------

def insert_proposal(data: dict) -> dict:
    _insert("execution_proposals", data)
    return _get("execution_proposals", data["id"])


def get_proposal(pid: str) -> dict | None:
    return _get("execution_proposals", pid)


def update_proposal(pid: str, data: dict) -> None:
    _update("execution_proposals", pid, data)


def list_proposals(project_id: str, limit: int = 100) -> list[dict]:
    return _query("execution_proposals", "project_id = ?", (project_id,),
                  "created_at DESC", limit)


# ---------------------------------------------------------------------------
# Policy decisions
# ---------------------------------------------------------------------------

def insert_policy(data: dict) -> dict:
    _insert("policy_decisions", data)
    return _get("policy_decisions", data["id"])


def get_policy_for_proposal(proposal_id: str) -> dict | None:
    rows = _query("policy_decisions", "proposal_id = ?", (proposal_id,), "created_at DESC", 1)
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------

def insert_approval(data: dict) -> dict:
    _insert("approvals", data)
    return _get("approvals", data["id"])


def get_latest_approval(proposal_id: str) -> dict | None:
    rows = _query("approvals", "proposal_id = ?", (proposal_id,), "created_at DESC", 1)
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Executions + outputs
# ---------------------------------------------------------------------------

def insert_execution(data: dict) -> dict:
    _insert("tool_executions", data)
    return _get("tool_executions", data["id"])


def get_execution(eid: str) -> dict | None:
    return _get("tool_executions", eid)


def update_execution(eid: str, data: dict) -> None:
    _update("tool_executions", eid, data)


def list_executions(project_id: str, limit: int = 100) -> list[dict]:
    return _query("tool_executions", "project_id = ?", (project_id,), "created_at DESC", limit)


def executions_for_proposal(proposal_id: str) -> list[dict]:
    return _query("tool_executions", "proposal_id = ?", (proposal_id,), "created_at DESC")


def insert_output(data: dict) -> dict:
    _insert("execution_outputs", data)
    return _get("execution_outputs", data["id"])


def get_output_for_execution(execution_id: str) -> dict | None:
    rows = _query("execution_outputs", "execution_id = ?", (execution_id,), "created_at DESC", 1)
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Evidence + findings
# ---------------------------------------------------------------------------

def insert_evidence(data: dict) -> dict:
    _insert("exec_evidence", data)
    return _get("exec_evidence", data["id"])


def get_evidence(eid: str) -> dict | None:
    return _get("exec_evidence", eid)


def list_evidence(project_id: str, limit: int = 200) -> list[dict]:
    return _query("exec_evidence", "project_id = ?", (project_id,), "created_at DESC", limit)


def insert_finding(data: dict) -> dict:
    _insert("exec_findings", data)
    return _get("exec_findings", data["id"])


def list_findings(project_id: str, limit: int = 200) -> list[dict]:
    return _query("exec_findings", "project_id = ?", (project_id,), "created_at DESC", limit)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def insert_cleanup(data: dict) -> dict:
    _insert("cleanup_records", data)
    return _get("cleanup_records", data["id"])


def update_cleanup(cid: str, data: dict) -> None:
    _update("cleanup_records", cid, data)


def get_cleanup_for_execution(execution_id: str) -> dict | None:
    rows = _query("cleanup_records", "execution_id = ?", (execution_id,), "created_at DESC", 1)
    return rows[0] if rows else None


# ---------------------------------------------------------------------------
# Audit (structured, project-scoped — complements the JSONL audit log)
# ---------------------------------------------------------------------------

def audit(project_id: str, event: str, *, actor: str = "system",
          proposal_id: str | None = None, execution_id: str | None = None,
          detail: dict | None = None) -> dict:
    row = {
        "id": new_id("aud"),
        "project_id": project_id,
        "ts": now_ts(),
        "actor": actor,
        "event": event,
        "proposal_id": proposal_id,
        "execution_id": execution_id,
        "detail": detail or {},
    }
    _insert("exec_audit", row)
    return row


def list_audit(project_id: str, limit: int = 200) -> list[dict]:
    return _query("exec_audit", "project_id = ?", (project_id,), "ts DESC", limit)


# ---------------------------------------------------------------------------
# Per-project tool enable/disable
# ---------------------------------------------------------------------------

def set_tool_enabled(project_id: str, tool_id: str, enabled: bool) -> None:
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO tool_settings (project_id, tool_id, enabled, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(project_id, tool_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at",
            (project_id, tool_id, 1 if enabled else 0, now_ts()),
        )
        con.commit()
        con.close()


def is_tool_enabled(project_id: str, tool_id: str) -> bool:
    with _conn() as con:
        row = con.execute(
            "SELECT enabled FROM tool_settings WHERE project_id=? AND tool_id=?",
            (project_id, tool_id),
        ).fetchone()
    return bool(row["enabled"]) if row else True  # enabled by default
