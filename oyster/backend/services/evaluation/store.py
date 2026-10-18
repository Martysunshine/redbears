"""SQLite persistence for evaluation runs (in the existing memory.db)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from threading import Lock

import config

_DB_PATH = config.MEMORY_DB
_lock = Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout = 30000")
    return c


def init_db() -> None:
    with _lock:
        con = conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS eval_runs (
                id          TEXT PRIMARY KEY,
                suite_id    TEXT NOT NULL,
                title       TEXT,
                top_k       INTEGER,
                case_count  INTEGER DEFAULT 0,
                passed      INTEGER DEFAULT 0,
                metrics     TEXT,
                status      TEXT DEFAULT 'completed',
                started_at  TEXT NOT NULL,
                finished_at TEXT
            );

            CREATE TABLE IF NOT EXISTS eval_results (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id    TEXT NOT NULL,
                case_id   TEXT NOT NULL,
                query     TEXT,
                passed    INTEGER DEFAULT 0,
                pack_hit  INTEGER DEFAULT 0,
                source_hit INTEGER DEFAULT 0,
                first_hit_rank INTEGER,
                result_count INTEGER DEFAULT 0,
                citation_present INTEGER DEFAULT 0,
                detail    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_eval_results_run ON eval_results(run_id);
            """
        )
        con.commit()
        con.close()


def save_run(run: dict, results: list[dict]) -> None:
    with _lock:
        con = conn()
        con.execute(
            "INSERT OR REPLACE INTO eval_runs "
            "(id,suite_id,title,top_k,case_count,passed,metrics,status,started_at,finished_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run["id"], run["suite_id"], run.get("title"), run.get("top_k"),
             run.get("case_count", 0), run.get("passed", 0),
             json.dumps(run.get("metrics", {}), sort_keys=True),
             run.get("status", "completed"), run.get("started_at", _ts()),
             run.get("finished_at", _ts())),
        )
        for r in results:
            con.execute(
                "INSERT INTO eval_results "
                "(run_id,case_id,query,passed,pack_hit,source_hit,first_hit_rank,"
                " result_count,citation_present,detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (run["id"], r["case_id"], r.get("query"), int(r.get("passed", False)),
                 int(r.get("pack_hit", False)), int(r.get("source_hit", False)),
                 r.get("first_hit_rank"), r.get("result_count", 0),
                 int(r.get("citation_present", False)),
                 json.dumps(r.get("detail", {}), sort_keys=True)),
            )
        con.commit()
        con.close()


def get_run(run_id: str) -> dict | None:
    with conn() as con:
        row = con.execute("SELECT * FROM eval_runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["metrics"] = json.loads(d.get("metrics") or "{}")
        results = con.execute(
            "SELECT * FROM eval_results WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    d["results"] = [_result_row(r) for r in results]
    return d


def list_runs(limit: int = 50) -> list[dict]:
    with conn() as con:
        rows = con.execute(
            "SELECT id,suite_id,title,top_k,case_count,passed,metrics,started_at,finished_at "
            "FROM eval_runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["metrics"] = json.loads(d.get("metrics") or "{}")
        out.append(d)
    return out


def _result_row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["detail"] = json.loads(d.get("detail") or "{}")
    for k in ("passed", "pack_hit", "source_hit", "citation_present"):
        d[k] = bool(d.get(k))
    return d
