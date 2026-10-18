"""SQLite persistence for GHSA (GitHub Security Advisories) and OSV (Open
Source Vulnerabilities) structured records.

Two source connectors (``sources/ghsa.py``, ``sources/osv.py``) both parse
the shared OSV JSON schema (``sources/osv_schema.py``) but land in separate
table families here — ``ghsa_*`` and ``osv_*`` — because the router and
answer layer treat "look up a GHSA id" and "look up an OSV id" as distinct
exact-identifier kinds (see ``security_router.py``).

Deduplication: OSV.dev re-publishes GitHub's own GHSA advisories verbatim
under their original GHSA id (GHSA is one of OSV's aggregated source
databases). The OSV sync (``sync_osv_ecosystem``) skips any record whose own
id is GHSA-shaped — that advisory already lives in ``ghsa_*`` from the GHSA
connector, so storing it again under ``osv_*`` would be a conflicting
duplicate of the same real-world advisory, not new information.

Every write is idempotent (content-hash gated), matching the pattern used
throughout ``vulnerabilities/store.py``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from threading import Lock

from services.knowledge import store as kb_store

from .sources.osv_schema import OsvRecord

_lock = Lock()
conn = kb_store.conn


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_record(rec: OsvRecord) -> str:
    payload = {"summary": rec.summary, "details": rec.details, "modified": rec.modified,
              "withdrawn": rec.withdrawn, "severity_vector": rec.severity_vector,
              "aliases": sorted(rec.aliases), "cwe_ids": rec.cwe_ids,
              "affected": [(a.ecosystem, a.package, a.introduced, a.fixed, a.last_affected)
                          for a in rec.affected]}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def init_db() -> None:
    with _lock:
        con = conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS ghsa_advisories (
                ghsa_id           TEXT PRIMARY KEY,
                schema_version    TEXT,
                summary           TEXT,
                details           TEXT,
                published         TEXT,
                modified          TEXT,
                withdrawn         TEXT,
                severity_vector   TEXT,
                severity_type     TEXT,
                database_severity TEXT,
                source_url        TEXT,
                content_hash      TEXT,
                retrieved_at      TEXT
            );
            CREATE TABLE IF NOT EXISTS ghsa_aliases (
                ghsa_id TEXT NOT NULL, alias TEXT NOT NULL, PRIMARY KEY (ghsa_id, alias)
            );
            CREATE INDEX IF NOT EXISTS idx_ghsa_alias ON ghsa_aliases(alias);
            CREATE TABLE IF NOT EXISTS ghsa_cwe_links (
                ghsa_id TEXT NOT NULL, cwe_id TEXT NOT NULL, PRIMARY KEY (ghsa_id, cwe_id)
            );
            CREATE TABLE IF NOT EXISTS ghsa_affected (
                ghsa_id TEXT NOT NULL, ecosystem TEXT, package TEXT,
                introduced TEXT, fixed TEXT, last_affected TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ghsa_affected_pkg ON ghsa_affected(ecosystem, package);
            CREATE INDEX IF NOT EXISTS idx_ghsa_affected_id ON ghsa_affected(ghsa_id);

            CREATE TABLE IF NOT EXISTS osv_records (
                osv_id            TEXT PRIMARY KEY,
                ecosystem_source  TEXT,
                schema_version    TEXT,
                summary           TEXT,
                details           TEXT,
                published         TEXT,
                modified          TEXT,
                withdrawn         TEXT,
                severity_vector   TEXT,
                severity_type     TEXT,
                database_severity TEXT,
                source_url        TEXT,
                content_hash      TEXT,
                retrieved_at      TEXT
            );
            CREATE TABLE IF NOT EXISTS osv_aliases (
                osv_id TEXT NOT NULL, alias TEXT NOT NULL, PRIMARY KEY (osv_id, alias)
            );
            CREATE INDEX IF NOT EXISTS idx_osv_alias ON osv_aliases(alias);
            CREATE TABLE IF NOT EXISTS osv_cwe_links (
                osv_id TEXT NOT NULL, cwe_id TEXT NOT NULL, PRIMARY KEY (osv_id, cwe_id)
            );
            CREATE TABLE IF NOT EXISTS osv_affected (
                osv_id TEXT NOT NULL, ecosystem TEXT, package TEXT,
                introduced TEXT, fixed TEXT, last_affected TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_osv_affected_pkg ON osv_affected(ecosystem, package);
            CREATE INDEX IF NOT EXISTS idx_osv_affected_id ON osv_affected(osv_id);

            CREATE TABLE IF NOT EXISTS ghsa_osv_sync_state (
                source_id           TEXT PRIMARY KEY,
                last_synced_at      TEXT,
                cursor               TEXT,
                last_status         TEXT,
                last_error          TEXT,
                records_seen_total  INTEGER DEFAULT 0
            );
            """
        )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Shared upsert machinery (table-name parameterized; called by the GHSA/OSV
# specific wrappers below so the SQL lives in exactly one place).
# ---------------------------------------------------------------------------

def _upsert(prefix: str, record_id_col: str, rec: OsvRecord, *, extra_cols: dict,
           source_url: str | None) -> str:
    chash = _hash_record(rec)
    table = f"{prefix}_records" if prefix == "osv" else "ghsa_advisories"
    alias_table, cwe_table, affected_table = f"{prefix}_aliases", f"{prefix}_cwe_links", f"{prefix}_affected"
    with _lock:
        con = conn()
        row = con.execute(f"SELECT content_hash FROM {table} WHERE {record_id_col}=?",
                          (rec.record_id,)).fetchone()
        if row is not None and row["content_hash"] == chash:
            con.close()
            return "unchanged"
        status = "updated" if row is not None else "added"
        now = _ts()
        cols = [record_id_col, "schema_version", "summary", "details", "published", "modified",
               "withdrawn", "severity_vector", "severity_type", "database_severity",
               "source_url", "content_hash", "retrieved_at"] + list(extra_cols.keys())
        vals = [rec.record_id, rec.schema_version, rec.summary, rec.details, rec.published,
                rec.modified, rec.withdrawn, rec.severity_vector, rec.severity_type,
                rec.database_severity, source_url, chash, now] + list(extra_cols.values())
        placeholders = ",".join("?" * len(cols))
        update_clause = ",".join(f"{c}=excluded.{c}" for c in cols if c != record_id_col)
        con.execute(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT({record_id_col}) DO UPDATE SET {update_clause}",
            vals,
        )
        con.execute(f"DELETE FROM {alias_table} WHERE {record_id_col}=?", (rec.record_id,))
        for a in rec.aliases:
            con.execute(f"INSERT OR IGNORE INTO {alias_table} ({record_id_col}, alias) VALUES (?,?)",
                       (rec.record_id, a))
        con.execute(f"DELETE FROM {cwe_table} WHERE {record_id_col}=?", (rec.record_id,))
        for c in rec.cwe_ids:
            con.execute(f"INSERT OR IGNORE INTO {cwe_table} ({record_id_col}, cwe_id) VALUES (?,?)",
                       (rec.record_id, c))
        con.execute(f"DELETE FROM {affected_table} WHERE {record_id_col}=?", (rec.record_id,))
        for a in rec.affected:
            con.execute(
                f"INSERT INTO {affected_table} ({record_id_col}, ecosystem, package, introduced, "
                f"fixed, last_affected) VALUES (?,?,?,?,?,?)",
                (rec.record_id, a.ecosystem, a.package, a.introduced, a.fixed, a.last_affected),
            )
        con.commit()
        con.close()
        return status


def _get(prefix: str, record_id_col: str, record_id: str) -> dict | None:
    table = "osv_records" if prefix == "osv" else "ghsa_advisories"
    con = conn()
    row = con.execute(f"SELECT * FROM {table} WHERE {record_id_col}=?", (record_id,)).fetchone()
    if row is None:
        con.close()
        return None
    rec = dict(row)
    rec["aliases"] = [r["alias"] for r in con.execute(
        f"SELECT alias FROM {prefix}_aliases WHERE {record_id_col}=?", (record_id,)).fetchall()]
    rec["cwe_ids"] = [r["cwe_id"] for r in con.execute(
        f"SELECT cwe_id FROM {prefix}_cwe_links WHERE {record_id_col}=?", (record_id,)).fetchall()]
    rec["affected"] = [dict(r) for r in con.execute(
        f"SELECT ecosystem, package, introduced, fixed, last_affected FROM {prefix}_affected "
        f"WHERE {record_id_col}=?", (record_id,)).fetchall()]
    con.close()
    rec["is_withdrawn"] = rec.get("withdrawn") is not None
    return rec


def _get_many(prefix: str, record_id_col: str, record_ids: list[str]) -> list[dict]:
    """Same shape as calling ``_get`` once per id, but batches the 4
    lookups (main row + aliases + cwe_ids + affected) into 4 queries total
    instead of 4*N — a package with hundreds of matching advisories (a
    popular library like tensorflow or magento) was previously an N+1 query
    pattern slow enough to risk the structured-lookup latency gate."""
    if not record_ids:
        return []
    table = "osv_records" if prefix == "osv" else "ghsa_advisories"
    placeholders = ",".join("?" * len(record_ids))
    con = conn()
    main_rows = {
        r[record_id_col]: dict(r) for r in con.execute(
            f"SELECT * FROM {table} WHERE {record_id_col} IN ({placeholders})", record_ids
        ).fetchall()
    }
    aliases: dict[str, list[str]] = {}
    for r in con.execute(
        f"SELECT {record_id_col}, alias FROM {prefix}_aliases WHERE {record_id_col} IN ({placeholders})",
        record_ids,
    ).fetchall():
        aliases.setdefault(r[record_id_col], []).append(r["alias"])
    cwe_ids: dict[str, list[str]] = {}
    for r in con.execute(
        f"SELECT {record_id_col}, cwe_id FROM {prefix}_cwe_links WHERE {record_id_col} IN ({placeholders})",
        record_ids,
    ).fetchall():
        cwe_ids.setdefault(r[record_id_col], []).append(r["cwe_id"])
    affected: dict[str, list[dict]] = {}
    for r in con.execute(
        f"SELECT {record_id_col}, ecosystem, package, introduced, fixed, last_affected "
        f"FROM {prefix}_affected WHERE {record_id_col} IN ({placeholders})", record_ids,
    ).fetchall():
        d = dict(r)
        rid = d.pop(record_id_col)
        affected.setdefault(rid, []).append(d)
    con.close()

    out = []
    for rid in record_ids:
        rec = main_rows.get(rid)
        if rec is None:
            continue
        rec["aliases"] = aliases.get(rid, [])
        rec["cwe_ids"] = cwe_ids.get(rid, [])
        rec["affected"] = affected.get(rid, [])
        rec["is_withdrawn"] = rec.get("withdrawn") is not None
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# GHSA
# ---------------------------------------------------------------------------

def upsert_ghsa(rec: OsvRecord, *, source_url: str | None = None) -> str:
    return _upsert("ghsa", "ghsa_id", rec, extra_cols={}, source_url=source_url)


def get_ghsa(ghsa_id: str) -> dict | None:
    return _get("ghsa", "ghsa_id", ghsa_id.upper())


def find_ghsa_by_alias(alias: str) -> list[dict]:
    """e.g. every GHSA advisory that names a given CVE as an alias."""
    con = conn()
    rows = con.execute("SELECT ghsa_id FROM ghsa_aliases WHERE alias=?", (alias.upper(),)).fetchall()
    con.close()
    return [get_ghsa(r["ghsa_id"]) for r in rows if get_ghsa(r["ghsa_id"])]


def search_ghsa_by_package(ecosystem: str, package: str) -> list[dict]:
    con = conn()
    rows = con.execute(
        "SELECT DISTINCT ghsa_id FROM ghsa_affected WHERE ecosystem=? AND package=?",
        (ecosystem, package),
    ).fetchall()
    con.close()
    return _get_many("ghsa", "ghsa_id", [r["ghsa_id"] for r in rows])


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

def upsert_osv(rec: OsvRecord, *, ecosystem_source: str, source_url: str | None = None) -> str:
    return _upsert("osv", "osv_id", rec, extra_cols={"ecosystem_source": ecosystem_source},
                   source_url=source_url)


def get_osv(osv_id: str) -> dict | None:
    return _get("osv", "osv_id", osv_id.upper())


def find_osv_by_alias(alias: str) -> list[dict]:
    con = conn()
    rows = con.execute("SELECT osv_id FROM osv_aliases WHERE alias=?", (alias.upper(),)).fetchall()
    con.close()
    return [get_osv(r["osv_id"]) for r in rows if get_osv(r["osv_id"])]


def search_osv_by_package(ecosystem: str, package: str) -> list[dict]:
    con = conn()
    rows = con.execute(
        "SELECT DISTINCT osv_id FROM osv_affected WHERE ecosystem=? AND package=?",
        (ecosystem, package),
    ).fetchall()
    con.close()
    return _get_many("osv", "osv_id", [r["osv_id"] for r in rows])


# ---------------------------------------------------------------------------
# Sync-state checkpoints (mirrors vulnerabilities/store.py's pattern)
# ---------------------------------------------------------------------------

def get_sync_state(source_id: str) -> dict | None:
    con = conn()
    row = con.execute("SELECT * FROM ghsa_osv_sync_state WHERE source_id=?", (source_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def set_sync_state(source_id: str, *, cursor: str | None = None, status: str | None = None,
                   error: str | None = None, records_seen_delta: int = 0) -> None:
    with _lock:
        con = conn()
        existing = con.execute("SELECT records_seen_total FROM ghsa_osv_sync_state WHERE source_id=?",
                               (source_id,)).fetchone()
        total = (existing["records_seen_total"] if existing else 0) + records_seen_delta
        con.execute(
            """INSERT INTO ghsa_osv_sync_state (source_id, last_synced_at, cursor, last_status,
                                                last_error, records_seen_total)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(source_id) DO UPDATE SET
                 last_synced_at=excluded.last_synced_at,
                 cursor=COALESCE(excluded.cursor, ghsa_osv_sync_state.cursor),
                 last_status=excluded.last_status, last_error=excluded.last_error,
                 records_seen_total=excluded.records_seen_total""",
            (source_id, _ts(), cursor, status, error, total),
        )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------

def counts() -> dict:
    con = conn()
    ghsa_total = con.execute("SELECT COUNT(*) c FROM ghsa_advisories").fetchone()["c"]
    ghsa_withdrawn = con.execute("SELECT COUNT(*) c FROM ghsa_advisories WHERE withdrawn IS NOT NULL").fetchone()["c"]
    ghsa_with_cve = con.execute("SELECT COUNT(DISTINCT ghsa_id) c FROM ghsa_aliases WHERE alias LIKE 'CVE-%'").fetchone()["c"]
    osv_by_ecosystem = con.execute(
        "SELECT ecosystem_source, COUNT(*) c FROM osv_records GROUP BY ecosystem_source"
    ).fetchall()
    osv_total = con.execute("SELECT COUNT(*) c FROM osv_records").fetchone()["c"]
    osv_withdrawn = con.execute("SELECT COUNT(*) c FROM osv_records WHERE withdrawn IS NOT NULL").fetchone()["c"]
    con.close()
    return {
        "ghsa_total": ghsa_total, "ghsa_withdrawn": ghsa_withdrawn, "ghsa_with_cve_alias": ghsa_with_cve,
        "osv_total": osv_total, "osv_withdrawn": osv_withdrawn,
        "osv_by_ecosystem_source": {r["ecosystem_source"]: r["c"] for r in osv_by_ecosystem},
    }
