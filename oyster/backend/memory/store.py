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


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS memories (
                id          TEXT PRIMARY KEY,
                type        TEXT NOT NULL,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                tags        TEXT NOT NULL DEFAULT '[]',
                session_id  TEXT,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_results (
                id          TEXT PRIMARY KEY,
                target      TEXT NOT NULL,
                tool        TEXT NOT NULL,
                result      TEXT NOT NULL,
                session_id  TEXT,
                created_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attack_surface (
                id              TEXT PRIMARY KEY,
                target          TEXT NOT NULL,
                component_type  TEXT NOT NULL,
                detail          TEXT NOT NULL,
                severity        TEXT NOT NULL DEFAULT 'info',
                session_id      TEXT,
                discovered_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mem_type ON memories(type);
            CREATE INDEX IF NOT EXISTS idx_mem_key  ON memories(key);
            CREATE INDEX IF NOT EXISTS idx_scan_tgt ON scan_results(target);
            CREATE INDEX IF NOT EXISTS idx_surf_tgt ON attack_surface(target);
        """)
        con.commit()
        con.close()


def store_memory(
    type: str,
    key: str,
    value: str,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    now = _ts()
    mid = str(uuid.uuid4())[:8]
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO memories (id,type,key,value,tags,session_id,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (mid, type, key, value, json.dumps(tags or []), session_id, now, now),
        )
        con.commit()
        con.close()
    return {"id": mid, "type": type, "key": key, "created_at": now}


def recall_memories(
    query: str | None = None,
    type: str | None = None,
    session_id: str | None = None,
    limit: int = 20,
) -> list[dict]:
    sql = "SELECT * FROM memories WHERE 1=1"
    params: list = []
    if type:
        sql += " AND type = ?"
        params.append(type)
    if session_id:
        sql += " AND session_id = ?"
        params.append(session_id)
    if query:
        sql += " AND (key LIKE ? OR value LIKE ?)"
        params.extend([f"%{query}%", f"%{query}%"])
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def store_scan_result(
    target: str,
    tool: str,
    result: dict,
    session_id: str | None = None,
) -> dict:
    now = _ts()
    sid = str(uuid.uuid4())[:8]
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO scan_results (id,target,tool,result,session_id,created_at) VALUES (?,?,?,?,?,?)",
            (sid, target, tool, json.dumps(result), session_id, now),
        )
        con.commit()
        con.close()
    return {"id": sid, "target": target, "tool": tool, "created_at": now}


def get_scan_history(target: str, limit: int = 10) -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM scan_results WHERE target = ? ORDER BY created_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        try:
            d["result"] = json.loads(d["result"])
        except Exception:
            pass
        results.append(d)
    return results


def store_attack_surface(
    target: str,
    component_type: str,
    detail: str,
    severity: str = "info",
    session_id: str | None = None,
) -> dict:
    now = _ts()
    aid = str(uuid.uuid4())[:8]
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO attack_surface "
            "(id,target,component_type,detail,severity,session_id,discovered_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (aid, target, component_type, detail, severity, session_id, now),
        )
        con.commit()
        con.close()
    return {"id": aid, "target": target, "component_type": component_type, "severity": severity, "discovered_at": now}


def get_attack_surface(target: str | None = None) -> list[dict]:
    sql = "SELECT * FROM attack_surface WHERE 1=1"
    params: list = []
    if target:
        sql += " AND target = ?"
        params.append(target)
    sql += " ORDER BY discovered_at DESC"
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def clear_session(session_id: str) -> int:
    with _lock:
        con = _conn()
        n = con.execute("DELETE FROM memories WHERE session_id = ?", (session_id,)).rowcount
        n += con.execute("DELETE FROM scan_results WHERE session_id = ?", (session_id,)).rowcount
        n += con.execute("DELETE FROM attack_surface WHERE session_id = ?", (session_id,)).rowcount
        con.commit()
        con.close()
    return n


def get_stats() -> dict:
    with _conn() as con:
        memories = con.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        scans = con.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
        surface = con.execute("SELECT COUNT(*) FROM attack_surface").fetchone()[0]
    return {"memories": memories, "scans": scans, "attack_surface_entries": surface}
