"""SQLite persistence for the cross-source knowledge graph.

Lives in the same project-scoped ``memory.db`` (no new infra). The graph is a
derived artefact: every rebuild fully replaces the node/edge/inconsistency rows
inside one transaction, so reads never see a half-built graph.
"""

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
        # kg_nodes/kg_edges are a fully-derived artefact (rebuilt wholesale by
        # graph.builder.build()) — a pre-V5 table missing the generated
        # source/ecosystem/package columns is safe to drop rather than migrate
        # in place; the next build() call repopulates it from scratch anyway.
        existing_cols = {r[1] for r in con.execute("PRAGMA table_info(kg_nodes)")}
        if existing_cols and "ecosystem" not in existing_cols:
            con.executescript(
                "DROP TABLE IF EXISTS kg_nodes; DROP TABLE IF EXISTS kg_edges; "
                "DROP TABLE IF EXISTS kg_inconsistencies; DROP TABLE IF EXISTS kg_build_runs;"
            )
            con.commit()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS kg_nodes (
                node_id   TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                label     TEXT,
                attrs     TEXT,
                updated_at TEXT NOT NULL,
                source    TEXT GENERATED ALWAYS AS (json_extract(attrs, '$.source')) VIRTUAL,
                ecosystem TEXT GENERATED ALWAYS AS (json_extract(attrs, '$.ecosystem')) VIRTUAL,
                package   TEXT GENERATED ALWAYS AS (json_extract(attrs, '$.package')) VIRTUAL
            );
            CREATE INDEX IF NOT EXISTS idx_kg_nodes_type ON kg_nodes(node_type);
            CREATE INDEX IF NOT EXISTS idx_kg_nodes_source ON kg_nodes(source);
            CREATE INDEX IF NOT EXISTS idx_kg_nodes_ecosystem ON kg_nodes(ecosystem);
            CREATE INDEX IF NOT EXISTS idx_kg_nodes_package ON kg_nodes(package);

            CREATE TABLE IF NOT EXISTS kg_edges (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                src       TEXT NOT NULL,
                dst       TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                attrs     TEXT,
                UNIQUE(src, dst, edge_type)
            );
            CREATE INDEX IF NOT EXISTS idx_kg_edges_src ON kg_edges(src);
            CREATE INDEX IF NOT EXISTS idx_kg_edges_dst ON kg_edges(dst);
            CREATE INDEX IF NOT EXISTS idx_kg_edges_type ON kg_edges(edge_type);
            CREATE INDEX IF NOT EXISTS idx_kg_edges_src_type ON kg_edges(src, edge_type);
            CREATE INDEX IF NOT EXISTS idx_kg_edges_dst_type ON kg_edges(dst, edge_type);

            CREATE TABLE IF NOT EXISTS kg_inconsistencies (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                kind      TEXT NOT NULL,
                subject   TEXT,
                detail    TEXT,
                severity  TEXT DEFAULT 'info',
                attrs     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_kg_incons_kind ON kg_inconsistencies(kind);

            CREATE TABLE IF NOT EXISTS kg_build_runs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at    TEXT NOT NULL,
                finished_at   TEXT,
                node_count    INTEGER DEFAULT 0,
                edge_count    INTEGER DEFAULT 0,
                inconsistency_count INTEGER DEFAULT 0,
                stats         TEXT
            );
            """
        )
        con.commit()
        con.close()


def replace_graph(nodes: list[dict], edges: list[dict],
                  inconsistencies: list[dict], stats: dict) -> int:
    """Atomically swap in a freshly-built graph. Returns the build-run id."""
    with _lock:
        con = conn()
        try:
            con.execute("BEGIN")
            con.execute("DELETE FROM kg_nodes")
            con.execute("DELETE FROM kg_edges")
            con.execute("DELETE FROM kg_inconsistencies")
            now = _ts()
            for n in nodes:
                con.execute(
                    "INSERT OR REPLACE INTO kg_nodes (node_id,node_type,label,attrs,updated_at) "
                    "VALUES (?,?,?,?,?)",
                    (n["node_id"], n["node_type"], n.get("label"),
                     json.dumps(n.get("attrs", {}), sort_keys=True), now),
                )
            for e in edges:
                con.execute(
                    "INSERT OR IGNORE INTO kg_edges (src,dst,edge_type,attrs) VALUES (?,?,?,?)",
                    (e["src"], e["dst"], e["edge_type"],
                     json.dumps(e.get("attrs", {}), sort_keys=True)),
                )
            for inc in inconsistencies:
                con.execute(
                    "INSERT INTO kg_inconsistencies (kind,subject,detail,severity,attrs) "
                    "VALUES (?,?,?,?,?)",
                    (inc["kind"], inc.get("subject"), inc.get("detail"),
                     inc.get("severity", "info"), json.dumps(inc.get("attrs", {}), sort_keys=True)),
                )
            cur = con.execute(
                "INSERT INTO kg_build_runs "
                "(started_at,finished_at,node_count,edge_count,inconsistency_count,stats) "
                "VALUES (?,?,?,?,?,?)",
                (now, _ts(), len(nodes), len(edges), len(inconsistencies),
                 json.dumps(stats, sort_keys=True)),
            )
            run_id = cur.lastrowid
            con.commit()
            return int(run_id)
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()


def get_node(node_id: str) -> dict | None:
    with conn() as con:
        row = con.execute("SELECT * FROM kg_nodes WHERE node_id=?", (node_id,)).fetchone()
    return _row_node(row) if row else None


def edges_from(node_id: str) -> list[dict]:
    with conn() as con:
        rows = con.execute("SELECT * FROM kg_edges WHERE src=?", (node_id,)).fetchall()
    return [_row_edge(r) for r in rows]


def edges_to(node_id: str) -> list[dict]:
    with conn() as con:
        rows = con.execute("SELECT * FROM kg_edges WHERE dst=?", (node_id,)).fetchall()
    return [_row_edge(r) for r in rows]


def latest_run() -> dict | None:
    with conn() as con:
        row = con.execute(
            "SELECT * FROM kg_build_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return None
    d = dict(row)
    d["stats"] = json.loads(d.get("stats") or "{}")
    return d


def counts_by_type() -> dict[str, int]:
    with conn() as con:
        rows = con.execute(
            "SELECT node_type, COUNT(*) c FROM kg_nodes GROUP BY node_type").fetchall()
    return {r["node_type"]: r["c"] for r in rows}


def edge_counts_by_type() -> dict[str, int]:
    with conn() as con:
        rows = con.execute(
            "SELECT edge_type, COUNT(*) c FROM kg_edges GROUP BY edge_type").fetchall()
    return {r["edge_type"]: r["c"] for r in rows}


def list_inconsistencies(kind: str | None = None, limit: int = 500) -> list[dict]:
    with conn() as con:
        if kind:
            rows = con.execute(
                "SELECT * FROM kg_inconsistencies WHERE kind=? ORDER BY id LIMIT ?",
                (kind, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM kg_inconsistencies ORDER BY id LIMIT ?", (limit,)).fetchall()
    return [_row_incons(r) for r in rows]


def inconsistency_counts() -> dict[str, int]:
    with conn() as con:
        rows = con.execute(
            "SELECT kind, COUNT(*) c FROM kg_inconsistencies GROUP BY kind").fetchall()
    return {r["kind"]: r["c"] for r in rows}


def dangling_edges(limit: int = 50) -> list[dict]:
    """Read-only, post-hoc structural check: edges whose src or dst does not
    exist as a node. ``builder.build()`` already guarantees this can never
    happen (it drops any such edge, recorded as a ``dangling_edge_dropped``
    inconsistency, before the atomic swap) — this is the independent proof
    that the invariant actually holds in what's stored, not just in the
    builder's intent."""
    with conn() as con:
        rows = con.execute(
            """SELECT e.src, e.dst, e.edge_type FROM kg_edges e
               WHERE NOT EXISTS (SELECT 1 FROM kg_nodes n WHERE n.node_id = e.src)
                  OR NOT EXISTS (SELECT 1 FROM kg_nodes n WHERE n.node_id = e.dst)
               LIMIT ?""", (limit,)).fetchall()
    return [dict(r) for r in rows]


def _row_node(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["attrs"] = json.loads(d.get("attrs") or "{}")
    return d


def _row_edge(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["attrs"] = json.loads(d.get("attrs") or "{}")
    return d


def _row_incons(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["attrs"] = json.loads(d.get("attrs") or "{}")
    return d
