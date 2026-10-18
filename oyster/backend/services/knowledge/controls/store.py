"""SQLite persistence for structured NIST control-catalog knowledge.

Same shape as ``services.knowledge.vulnerabilities.store`` (CWE/CAPEC): one
row per addressable element (CSF function/category/subcategory, SP 800-53
control/enhancement, SSDF practice/task), refreshed whole-catalog per sync,
diffed per-record by content hash so an unchanged upstream re-sync writes
nothing. Reuses the shared ``memory.db`` connection helper — no new infra.

``control_records`` is deliberately framework-agnostic (one table, a
``framework`` column) rather than one table per framework: every NIST OSCAL
catalog shares the same real shape (id / class / parent / statement /
guidance / examples), and a shared table is what lets exact-identifier
lookup and cross-framework relationship queries stay simple.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from threading import Lock

from services.knowledge import store as kb_store

_lock = Lock()

conn = kb_store.conn


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_obj(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def init_db() -> None:
    with _lock:
        con = conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS control_records (
                framework       TEXT NOT NULL,
                control_id      TEXT NOT NULL,
                parent_id       TEXT,
                class           TEXT,
                title           TEXT,
                statement       TEXT,
                guidance        TEXT,
                examples_json   TEXT,
                external_refs_json TEXT,
                source_url      TEXT,
                source_title    TEXT,
                publisher       TEXT,
                version         TEXT,
                published_date  TEXT,
                content_hash    TEXT,
                retrieved_at    TEXT,
                created_at      TEXT,
                updated_at      TEXT,
                PRIMARY KEY (framework, control_id)
            );
            CREATE INDEX IF NOT EXISTS idx_control_parent ON control_records(framework, parent_id);
            CREATE INDEX IF NOT EXISTS idx_control_class ON control_records(framework, class);

            CREATE TABLE IF NOT EXISTS control_links (
                framework           TEXT NOT NULL,
                control_id          TEXT NOT NULL,
                rel                 TEXT NOT NULL,
                target_framework    TEXT,
                target_control_id   TEXT,
                note                TEXT,
                PRIMARY KEY (framework, control_id, rel, target_framework, target_control_id, note)
            );
            CREATE INDEX IF NOT EXISTS idx_clink_control ON control_links(framework, control_id);
            CREATE INDEX IF NOT EXISTS idx_clink_target ON control_links(target_framework, target_control_id);

            CREATE TABLE IF NOT EXISTS control_sync_state (
                framework     TEXT PRIMARY KEY,
                last_synced_at TEXT,
                version       TEXT,
                record_count  INTEGER,
                link_count    INTEGER,
                source_url    TEXT
            );
            """
        )
        con.commit()
        con.close()


def upsert_control(rec: dict) -> bool:
    """Insert/update one control record. Returns True if the row actually changed."""
    fields = ("framework", "control_id", "parent_id", "class", "title", "statement",
              "guidance", "examples_json", "external_refs_json", "source_url",
              "source_title", "publisher", "version", "published_date")
    payload = {k: rec.get(k) for k in fields}
    chash = _hash_obj(payload)

    with _lock:
        con = conn()
        cur = con.execute(
            "SELECT content_hash FROM control_records WHERE framework=? AND control_id=?",
            (rec["framework"], rec["control_id"]),
        )
        row = cur.fetchone()
        now = _ts()
        if row is None:
            con.execute(
                """INSERT INTO control_records
                   (framework, control_id, parent_id, class, title, statement, guidance,
                    examples_json, external_refs_json, source_url, source_title, publisher,
                    version, published_date, content_hash, retrieved_at, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rec["framework"], rec["control_id"], rec.get("parent_id"), rec.get("class"),
                 rec.get("title"), rec.get("statement"), rec.get("guidance"),
                 rec.get("examples_json"), rec.get("external_refs_json"), rec.get("source_url"),
                 rec.get("source_title"), rec.get("publisher"), rec.get("version"),
                 rec.get("published_date"), chash, now, now, now),
            )
            con.commit()
            con.close()
            return True
        changed = row["content_hash"] != chash
        if changed:
            con.execute(
                """UPDATE control_records SET
                     parent_id=?, class=?, title=?, statement=?, guidance=?,
                     examples_json=?, external_refs_json=?, source_url=?, source_title=?,
                     publisher=?, version=?, published_date=?, content_hash=?, retrieved_at=?, updated_at=?
                   WHERE framework=? AND control_id=?""",
                (rec.get("parent_id"), rec.get("class"), rec.get("title"), rec.get("statement"),
                 rec.get("guidance"), rec.get("examples_json"), rec.get("external_refs_json"),
                 rec.get("source_url"), rec.get("source_title"), rec.get("publisher"),
                 rec.get("version"), rec.get("published_date"), chash, now, now,
                 rec["framework"], rec["control_id"]),
            )
            con.commit()
        con.close()
        return changed


def replace_links(framework: str, control_id: str, links: list[dict]) -> None:
    with _lock:
        con = conn()
        con.execute("DELETE FROM control_links WHERE framework=? AND control_id=?",
                    (framework, control_id))
        for link in links:
            con.execute(
                """INSERT OR IGNORE INTO control_links
                   (framework, control_id, rel, target_framework, target_control_id, note)
                   VALUES (?,?,?,?,?,?)""",
                (framework, control_id, link.get("rel"), link.get("target_framework"),
                 link.get("target_control_id"), link.get("note")),
            )
        con.commit()
        con.close()


def record_sync(framework: str, version: str | None, record_count: int, link_count: int,
                source_url: str) -> None:
    with _lock:
        con = conn()
        con.execute(
            """INSERT INTO control_sync_state (framework, last_synced_at, version, record_count, link_count, source_url)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(framework) DO UPDATE SET
                 last_synced_at=excluded.last_synced_at, version=excluded.version,
                 record_count=excluded.record_count, link_count=excluded.link_count,
                 source_url=excluded.source_url""",
            (framework, _ts(), version, record_count, link_count, source_url),
        )
        con.commit()
        con.close()


def get_control(framework: str, control_id: str) -> dict | None:
    con = conn()
    cur = con.execute(
        "SELECT * FROM control_records WHERE framework=? AND UPPER(control_id)=UPPER(?)",
        (framework, control_id),
    )
    row = cur.fetchone()
    con.close()
    if row is None:
        return None
    rec = dict(row)
    for jf in ("examples_json", "external_refs_json"):
        raw = rec.pop(jf, None)
        rec[jf[:-5]] = json.loads(raw) if raw else []
    return rec


def find_control_any_framework(control_id: str) -> dict | None:
    """Exact-id lookup without knowing the framework up front (router use)."""
    con = conn()
    cur = con.execute(
        "SELECT * FROM control_records WHERE UPPER(control_id)=UPPER(?) LIMIT 1",
        (control_id,),
    )
    row = cur.fetchone()
    con.close()
    if row is None:
        return None
    return get_control(row["framework"], control_id)


def get_links(framework: str, control_id: str) -> list[dict]:
    con = conn()
    cur = con.execute(
        "SELECT rel, target_framework, target_control_id, note FROM control_links "
        "WHERE framework=? AND control_id=?",
        (framework, control_id),
    )
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows

def get_children(framework: str, control_id: str) -> list[dict]:
    con = conn()
    cur = con.execute(
        "SELECT control_id, title, class FROM control_records WHERE framework=? AND parent_id=? "
        "ORDER BY control_id",
        (framework, control_id),
    )
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


def search_controls(framework: str | None, query: str, limit: int = 20) -> list[dict]:
    """Deterministic LIKE search over title/statement — never semantic, never fabricated."""
    con = conn()
    like = f"%{query}%"
    if framework:
        cur = con.execute(
            "SELECT framework, control_id, class, title FROM control_records "
            "WHERE framework=? AND (title LIKE ? OR statement LIKE ?) LIMIT ?",
            (framework, like, like, limit),
        )
    else:
        cur = con.execute(
            "SELECT framework, control_id, class, title FROM control_records "
            "WHERE title LIKE ? OR statement LIKE ? LIMIT ?",
            (like, like, limit),
        )
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


def counts() -> dict:
    con = conn()
    cur = con.execute("SELECT framework, COUNT(*) c FROM control_records GROUP BY framework")
    by_fw = {r["framework"]: r["c"] for r in cur.fetchall()}
    cur = con.execute("SELECT COUNT(*) c FROM control_links")
    links = cur.fetchone()["c"]
    con.close()
    return {"by_framework": by_fw, "total_records": sum(by_fw.values()), "total_links": links}
