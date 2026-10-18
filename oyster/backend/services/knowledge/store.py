"""SQLite persistence for the Knowledge Service.

Owns three concerns, all in the existing project-scoped ``memory.db`` (no new
infra):

1. ``knowledge_packs`` — install state + full machine-readable metadata
   (enabled flag, checksum, licence, risk, freshness, update status). Extended
   from the original 8-column table via idempotent ``ALTER TABLE`` migrations so
   existing installs are preserved.
2. ``knowledge_chunks`` (+ ``knowledge_chunks_fts`` FTS5) — per-chunk provenance
   and the lexical half of hybrid retrieval. This is also the source-of-truth
   for citation resolution (full passage + metadata), independent of Chroma.
3. ``knowledge_pack_updates`` — append-only update/version history for the
   manual update + rollback workflow.

FTS5 is used when the runtime's sqlite is compiled with it (it almost always
is); otherwise lexical search degrades to a ``LIKE`` scan so the system still
works offline on any sqlite build.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from threading import RLock

import config

_DB_PATH = config.MEMORY_DB
# RLock, not Lock: fts_available() takes this lock and is itself called from
# inside delete_chunks()/replace_chunks() while THEY already hold it — a plain
# Lock would deadlock a thread against itself the first time _fts_ok is still
# unset. RLock permits the same thread to re-enter; a second, different
# thread still blocks exactly as before.
_lock = RLock()
_fts_ok: bool | None = None  # detected once at init


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    # A concurrent writer (another sync job, a live request) holding the
    # write lock should make this connection wait and retry internally
    # rather than fail immediately with "database is locked" — several
    # independent sync pipelines can legitimately run at the same time.
    c.execute("PRAGMA busy_timeout = 30000")
    return c


# Idempotent column additions for the pre-existing knowledge_packs table.
_PACK_COLUMNS = [
    ("enabled", "INTEGER DEFAULT 1"),
    ("content_checksum", "TEXT"),
    ("licence", "TEXT"),
    ("attribution", "TEXT"),
    ("risk_classification", "TEXT DEFAULT 'informational'"),
    ("security_domain", "TEXT"),
    ("source_urls", "TEXT"),          # JSON array
    ("trust_level", "TEXT DEFAULT 'community'"),
    ("retrieved_at", "TEXT"),
    ("last_reviewed_at", "TEXT"),
    ("freshness_policy", "TEXT"),
    ("installation_status", "TEXT DEFAULT 'installed'"),
    ("update_status", "TEXT DEFAULT 'current'"),
    # 'markdown' (default, existing packs) vs 'vulnerability_feed' (KEV/NVD/
    # EPSS/CWE/CAPEC) — lets those sources show up in the existing pack
    # list/enable/disable UI with truthful per-source chunk counts.
    ("pack_kind", "TEXT DEFAULT 'markdown'"),
]

# Idempotent column additions for the pre-existing knowledge_chunks table —
# nullable exact-identifier columns so a CVE/CWE/CAPEC lookup is a plain
# indexed SELECT, never a vector/FTS search.
_CHUNK_COLUMNS = [
    ("cve_id", "TEXT"),
    ("cwe_id", "TEXT"),
    ("capec_id", "TEXT"),
]


def _detect_fts(con: sqlite3.Connection) -> bool:
    try:
        con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x)")
        con.execute("DROP TABLE IF EXISTS _fts_probe")
        return True
    except sqlite3.OperationalError:
        return False


def fts_available() -> bool:
    """Whether this sqlite build has FTS5 — detected once, then cached for the
    process (``_fts_ok``).

    2026-09-14: found via a real ingestion run where every FTS write silently
    no-op'd for an entire process's lifetime, with no error anywhere. Root
    cause — this check used to run the create/drop probe outside ``_lock``,
    unlike every other function here that touches ``_fts_ok`` or the FTS
    table. Two callers racing the very first check (plausible: connector
    install fans out embedding/IO work across threads, and
    ``pack_service.uninstall()`` → ``rag_service.delete_pack_async`` also
    hops to a worker thread) could run ``_detect_fts``'s CREATE/DROP DDL on
    two separate connections against the same on-disk file at once; SQLite
    can raise ``OperationalError`` for concurrent schema changes even though
    each statement is individually ``IF (NOT) EXISTS``-guarded. That
    transient error was indistinguishable from "FTS5 not compiled in" and got
    cached as ``False`` forever, silently degrading every later
    ``replace_chunks``/``delete_chunks`` call in that process to a
    canonical-storage-only write with no error. Fixed by taking the same
    ``_lock`` every other FTS-table-touching function already uses, so only
    one caller per process ever runs the probe.
    """
    global _fts_ok
    if _fts_ok is None:
        with _lock:
            if _fts_ok is None:  # re-check: another thread may have won the race
                with conn() as c:
                    _fts_ok = _detect_fts(c)
    return _fts_ok


def init_db() -> None:
    global _fts_ok
    with _lock:
        con = conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS knowledge_packs (
                pack_id      TEXT PRIMARY KEY,
                version      TEXT NOT NULL,
                title        TEXT,
                domain       TEXT,
                doc_count    INTEGER DEFAULT 0,
                chunk_count  INTEGER DEFAULT 0,
                installed_at TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_chunks (
                id           TEXT PRIMARY KEY,
                pack_id      TEXT NOT NULL,
                pack_version TEXT,
                doc_id       TEXT,
                document     TEXT,
                source_type  TEXT DEFAULT 'built_in',
                title        TEXT,
                publisher    TEXT,
                canonical_url TEXT,
                licence      TEXT,
                trust_level  TEXT,
                risk_level   TEXT,
                domain       TEXT,
                section      TEXT,
                chunk_index  INTEGER,
                content_hash TEXT,
                content      TEXT,
                created_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_kchunks_pack ON knowledge_chunks(pack_id);
            CREATE INDEX IF NOT EXISTS idx_kchunks_domain ON knowledge_chunks(domain);

            CREATE TABLE IF NOT EXISTS knowledge_pack_updates (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                pack_id       TEXT NOT NULL,
                action        TEXT NOT NULL,
                from_version  TEXT,
                to_version    TEXT,
                from_checksum TEXT,
                to_checksum   TEXT,
                note          TEXT,
                at            TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS knowledge_import_jobs (
                id            TEXT PRIMARY KEY,
                connector_id  TEXT NOT NULL,
                pack_id       TEXT,
                status        TEXT NOT NULL,
                ref           TEXT,
                doc_count     INTEGER DEFAULT 0,
                chunk_count   INTEGER DEFAULT 0,
                injection_findings INTEGER DEFAULT 0,
                licence       TEXT,
                disposition   TEXT,
                error         TEXT,
                detail        TEXT,
                started_at    TEXT NOT NULL,
                finished_at   TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_import_jobs_conn ON knowledge_import_jobs(connector_id);
            """
        )
        # Idempotent ALTERs for the extended pack metadata.
        existing = {r[1] for r in con.execute("PRAGMA table_info(knowledge_packs)")}
        for col, decl in _PACK_COLUMNS:
            if col not in existing:
                con.execute(f"ALTER TABLE knowledge_packs ADD COLUMN {col} {decl}")

        # Idempotent ALTERs for the exact-identifier chunk columns.
        chunk_existing = {r[1] for r in con.execute("PRAGMA table_info(knowledge_chunks)")}
        for col, decl in _CHUNK_COLUMNS:
            if col not in chunk_existing:
                con.execute(f"ALTER TABLE knowledge_chunks ADD COLUMN {col} {decl}")
        con.execute("CREATE INDEX IF NOT EXISTS idx_kchunks_cve ON knowledge_chunks(cve_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_kchunks_cwe ON knowledge_chunks(cwe_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_kchunks_capec ON knowledge_chunks(capec_id)")

        _fts_ok = _detect_fts(con)
        if _fts_ok:
            con.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_chunks_fts "
                "USING fts5(chunk_id UNINDEXED, pack_id UNINDEXED, content, "
                "tokenize='porter unicode61')"
            )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Chunk provenance (write during install, read for lexical search + citations)
# ---------------------------------------------------------------------------

def replace_chunks(pack_id: str, chunks: list[dict]) -> None:
    """Atomically replace all provenance rows for a pack."""
    with _lock:
        con = conn()
        con.execute("DELETE FROM knowledge_chunks WHERE pack_id = ?", (pack_id,))
        if fts_available():
            con.execute("DELETE FROM knowledge_chunks_fts WHERE pack_id = ?", (pack_id,))
        now = _ts()
        for ch in chunks:
            con.execute(
                "INSERT OR REPLACE INTO knowledge_chunks "
                "(id,pack_id,pack_version,doc_id,document,source_type,title,publisher,"
                " canonical_url,licence,trust_level,risk_level,domain,section,chunk_index,"
                " content_hash,content,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ch["id"], pack_id, ch.get("pack_version"), ch.get("doc_id"),
                    ch.get("document"), ch.get("source_type", "built_in"), ch.get("title"),
                    ch.get("publisher"), ch.get("canonical_url"), ch.get("licence"),
                    ch.get("trust_level"), ch.get("risk_level"), ch.get("domain"),
                    ch.get("section"), ch.get("chunk_index"), ch.get("content_hash"),
                    ch.get("content"), now,
                ),
            )
            if fts_available():
                con.execute(
                    "INSERT INTO knowledge_chunks_fts (chunk_id,pack_id,content) VALUES (?,?,?)",
                    (ch["id"], pack_id, ch.get("content", "")),
                )
        con.commit()
        con.close()


def chunks_for_pack(pack_id: str) -> list[dict]:
    """Existing provenance rows for a pack, oldest chunk-order first — read
    BEFORE an install overwrites them, so the caller can diff old vs new
    content per doc and skip re-embedding docs that haven't actually changed."""
    with conn() as con:
        rows = con.execute(
            "SELECT * FROM knowledge_chunks WHERE pack_id = ? ORDER BY doc_id, chunk_index",
            (pack_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def upsert_chunk(chunk: dict) -> None:
    """Row-level upsert for ONE chunk — unlike ``replace_chunks`` (whole-pack
    delete+reinsert, used by git/STIX connector installs), this never touches
    any other row in the pack. Needed for incremental vulnerability sync,
    where a pack can hold hundreds of thousands of rows and a sync run only
    ever touches the handful that actually changed."""
    with _lock:
        con = conn()
        con.execute(
            "INSERT INTO knowledge_chunks "
            "(id,pack_id,pack_version,doc_id,document,source_type,title,publisher,"
            " canonical_url,licence,trust_level,risk_level,domain,section,chunk_index,"
            " content_hash,content,created_at,cve_id,cwe_id,capec_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET pack_version=excluded.pack_version,"
            " doc_id=excluded.doc_id, document=excluded.document, title=excluded.title,"
            " publisher=excluded.publisher, canonical_url=excluded.canonical_url,"
            " licence=excluded.licence, trust_level=excluded.trust_level,"
            " risk_level=excluded.risk_level, domain=excluded.domain, section=excluded.section,"
            " chunk_index=excluded.chunk_index, content_hash=excluded.content_hash,"
            " content=excluded.content, cve_id=excluded.cve_id, cwe_id=excluded.cwe_id,"
            " capec_id=excluded.capec_id",
            (
                chunk["id"], chunk["pack_id"], chunk.get("pack_version"), chunk.get("doc_id"),
                chunk.get("document"), chunk.get("source_type", "built_in"), chunk.get("title"),
                chunk.get("publisher"), chunk.get("canonical_url"), chunk.get("licence"),
                chunk.get("trust_level"), chunk.get("risk_level"), chunk.get("domain"),
                chunk.get("section"), chunk.get("chunk_index"), chunk.get("content_hash"),
                chunk.get("content"), _ts(), chunk.get("cve_id"), chunk.get("cwe_id"),
                chunk.get("capec_id"),
            ),
        )
        if fts_available():
            con.execute("DELETE FROM knowledge_chunks_fts WHERE chunk_id = ?", (chunk["id"],))
            con.execute(
                "INSERT INTO knowledge_chunks_fts (chunk_id,pack_id,content) VALUES (?,?,?)",
                (chunk["id"], chunk["pack_id"], chunk.get("content", "")),
            )
        con.commit()
        con.close()


def delete_chunk(chunk_id: str) -> None:
    with _lock:
        con = conn()
        con.execute("DELETE FROM knowledge_chunks WHERE id = ?", (chunk_id,))
        if fts_available():
            con.execute("DELETE FROM knowledge_chunks_fts WHERE chunk_id = ?", (chunk_id,))
        con.commit()
        con.close()


def get_chunk_by_cve(cve_id: str) -> dict | None:
    with conn() as con:
        row = con.execute(
            "SELECT * FROM knowledge_chunks WHERE cve_id = ? LIMIT 1", (cve_id,)
        ).fetchone()
    return dict(row) if row else None


def get_chunk_by_cwe(cwe_id: str) -> dict | None:
    with conn() as con:
        row = con.execute(
            "SELECT * FROM knowledge_chunks WHERE cwe_id = ? LIMIT 1", (cwe_id,)
        ).fetchone()
    return dict(row) if row else None


def get_chunk_by_capec(capec_id: str) -> dict | None:
    with conn() as con:
        row = con.execute(
            "SELECT * FROM knowledge_chunks WHERE capec_id = ? LIMIT 1", (capec_id,)
        ).fetchone()
    return dict(row) if row else None


def delete_chunks(pack_id: str) -> None:
    with _lock:
        con = conn()
        con.execute("DELETE FROM knowledge_chunks WHERE pack_id = ?", (pack_id,))
        if fts_available():
            con.execute("DELETE FROM knowledge_chunks_fts WHERE pack_id = ?", (pack_id,))
        con.commit()
        con.close()


def get_chunk(chunk_id: str) -> dict | None:
    with conn() as con:
        row = con.execute("SELECT * FROM knowledge_chunks WHERE id = ?", (chunk_id,)).fetchone()
    return dict(row) if row else None


def find_chunks_by_title_prefix(prefix: str, pack_ids: list[str] | None = None, limit: int = 3) -> list[dict]:
    """2026-09-15: chunks whose own document/title starts with an exact
    identifier (e.g. "T1055", "LLM06") — the canonical page for that id, as
    opposed to a chunk that merely mentions it in passing. Used to inject a
    canonical page that a broad, high-volume cross-referencing pack (e.g.
    mitre-d3fend-src's technique tables) has crowded out of the top-N
    candidate pool entirely, the same way an exact CVE/CWE/CAPEC id is
    fetched directly rather than relying on embedding similarity to surface
    it (see retrieval.py's ``_exact_id_chunk_ids``)."""
    # A bare "%" wildcard after the prefix would also match "T1055.001",
    # "T1055.002" etc when the caller only asked for "T1055" — the id must be
    # followed by a space (covers "T1055 — X" and "T1055 - X") or be an exact
    # match, never immediately followed by another digit or ".NNN".
    space_like = f"{prefix} %"
    with conn() as con:
        sql = ("SELECT * FROM knowledge_chunks WHERE "
               "(document = ? OR document LIKE ? OR title = ? OR title LIKE ?) ")
        params: list = [prefix, space_like, prefix, space_like]
        if pack_ids:
            sql += "AND pack_id IN (%s) " % ",".join("?" * len(pack_ids))
            params += pack_ids
        # Deterministic tie-break across packs that both have a canonical page
        # for the same id (verified real case: mitre-attack-src's definitional
        # page and atomic-red-team-src's simulation procedure both title their
        # T1055 file "T1055 <dash> ...") -- shortest document title first, so
        # the base technique page sorts ahead of a same-pack sub-technique
        # variant, then pack_id for stable, reproducible ordering.
        sql += "ORDER BY LENGTH(COALESCE(document, title, '')), pack_id LIMIT ?"
        params.append(limit)
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def find_chunks_by_exact_filename_title(name: str, pack_ids: list[str] | None = None, limit: int = 3) -> list[dict]:
    """2026-09-16: chunks whose title is a filename-style identifier -- e.g.
    LOLBAS/GTFOBins pages titled "Rundll32.yml", "Certutil.yml" -- the
    canonical page for a specific named Windows binary, as opposed to a
    chunk that merely mentions the binary in passing (e.g. an ATT&CK
    technique page covering the broader proxy-execution category).

    Same purpose as ``find_chunks_by_title_prefix`` but a different boundary
    rule: those titles are separated by a space ("T1055 - X"); these are
    separated by a file extension ("Rundll32.yml", "Rundll32.md"). Reusing
    the space-boundary check there would silently match nothing here, and a
    bare "LIKE 'rundll32%'" would wrongly also match an unrelated document
    like "Rundll32Extractor.md" -- the extension dot is the real boundary.
    SQLite's LIKE is case-insensitive over ASCII by default, so this matches
    regardless of how the stored title is cased.
    """
    dot_like = f"{name}.%"
    with conn() as con:
        sql = ("SELECT * FROM knowledge_chunks WHERE "
               "(document = ? OR document LIKE ? OR title = ? OR title LIKE ?) ")
        params: list = [name, dot_like, name, dot_like]
        if pack_ids:
            sql += "AND pack_id IN (%s) " % ",".join("?" * len(pack_ids))
            params += pack_ids
        sql += "ORDER BY LENGTH(COALESCE(document, title, '')), pack_id LIMIT ?"
        params.append(limit)
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def neighbor_chunks(pack_id: str, doc_id: str, center_index: int, radius: int) -> list[dict]:
    """Chunks adjacent to ``center_index`` within the SAME document (same
    ``pack_id`` + ``doc_id``), ordered by ``chunk_index``, excluding the centre
    itself. Used by retrieval to stitch a chunk back together with the text that
    immediately surrounds it in its source document — the ingest step slices a
    document into ~800-char chunks, so a single retrieved chunk routinely ends
    mid-sentence and drops the rest of a command or procedure. Expanding within
    the same (pack_id, doc_id) keeps source attribution and project isolation
    intact: every neighbour is the same document from the same pack."""
    if radius <= 0 or doc_id is None or center_index is None:
        return []
    lo, hi = center_index - radius, center_index + radius
    with conn() as con:
        rows = con.execute(
            "SELECT * FROM knowledge_chunks WHERE pack_id = ? AND doc_id = ? "
            "AND chunk_index BETWEEN ? AND ? AND chunk_index != ? "
            "ORDER BY chunk_index",
            (pack_id, doc_id, lo, hi, center_index),
        ).fetchall()
    return [dict(r) for r in rows]


def enabled_pack_ids() -> list[str]:
    with conn() as con:
        rows = con.execute(
            "SELECT pack_id FROM knowledge_packs WHERE COALESCE(enabled,1) = 1"
        ).fetchall()
    return [r["pack_id"] for r in rows]


def pack_meta_map() -> dict[str, dict]:
    with conn() as con:
        rows = con.execute("SELECT * FROM knowledge_packs").fetchall()
    return {r["pack_id"]: dict(r) for r in rows}


def lexical_search(query: str, pack_ids: list[str] | None, limit: int) -> list[dict]:
    """FTS5 (or LIKE fallback) lexical search, scoped to the given pack ids."""
    if not query.strip():
        return []
    with conn() as con:
        if fts_available():
            sql = (
                "SELECT c.*, bm25(knowledge_chunks_fts) AS rank "
                "FROM knowledge_chunks_fts f "
                "JOIN knowledge_chunks c ON c.id = f.chunk_id "
                "WHERE knowledge_chunks_fts MATCH ? "
            )
            params: list = [_fts_query(query)]
            if pack_ids:
                sql += "AND c.pack_id IN (%s) " % ",".join("?" * len(pack_ids))
                params += pack_ids
            sql += "ORDER BY rank LIMIT ?"
            params.append(limit)
            try:
                rows = con.execute(sql, params).fetchall()
                return [dict(r) for r in rows]
            except sqlite3.OperationalError:
                pass  # malformed MATCH → fall through to LIKE
        # LIKE fallback
        sql = "SELECT * FROM knowledge_chunks WHERE content LIKE ? "
        params = [f"%{query}%"]
        if pack_ids:
            sql += "AND pack_id IN (%s) " % ",".join("?" * len(pack_ids))
            params += pack_ids
        sql += "LIMIT ?"
        params.append(limit)
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def _fts_query(query: str) -> str:
    """Turn free text into a safe FTS5 OR query (tokens quoted, punctuation dropped)."""
    import re
    tokens = re.findall(r"[A-Za-z0-9_]+", query)
    if not tokens:
        return '""'
    return " OR ".join(f'"{t}"' for t in tokens[:24])


# ---------------------------------------------------------------------------
# Update history
# ---------------------------------------------------------------------------

def record_update(pack_id: str, action: str, *, from_version: str | None = None,
                  to_version: str | None = None, from_checksum: str | None = None,
                  to_checksum: str | None = None, note: str | None = None) -> None:
    with _lock:
        con = conn()
        con.execute(
            "INSERT INTO knowledge_pack_updates "
            "(pack_id,action,from_version,to_version,from_checksum,to_checksum,note,at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (pack_id, action, from_version, to_version, from_checksum, to_checksum, note, _ts()),
        )
        con.commit()
        con.close()


def update_history(pack_id: str) -> list[dict]:
    with conn() as con:
        rows = con.execute(
            "SELECT * FROM knowledge_pack_updates WHERE pack_id = ? ORDER BY id DESC",
            (pack_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Import jobs (source-connector ingestion lifecycle)
# ---------------------------------------------------------------------------

def start_import_job(job_id: str, connector_id: str, ref: str | None = None) -> None:
    with _lock:
        con = conn()
        con.execute(
            "INSERT OR REPLACE INTO knowledge_import_jobs "
            "(id,connector_id,status,ref,started_at) VALUES (?,?,?,?,?)",
            (job_id, connector_id, "running", ref, _ts()),
        )
        con.commit()
        con.close()


def finish_import_job(job_id: str, status: str, **fields) -> None:
    cols = ["status", "finished_at"]
    vals: list = [status, _ts()]
    for k in ("pack_id", "ref", "doc_count", "chunk_count", "injection_findings",
              "licence", "disposition", "error", "detail"):
        if k in fields:
            cols.append(k)
            vals.append(fields[k])
    set_clause = ",".join(f"{c}=?" for c in cols)
    with _lock:
        con = conn()
        con.execute(f"UPDATE knowledge_import_jobs SET {set_clause} WHERE id=?",
                    (*vals, job_id))
        con.commit()
        con.close()


def get_import_job(job_id: str) -> dict | None:
    with conn() as con:
        row = con.execute("SELECT * FROM knowledge_import_jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_import_jobs(connector_id: str | None = None, limit: int = 50) -> list[dict]:
    with conn() as con:
        if connector_id:
            rows = con.execute(
                "SELECT * FROM knowledge_import_jobs WHERE connector_id=? "
                "ORDER BY started_at DESC LIMIT ?", (connector_id, limit)).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM knowledge_import_jobs ORDER BY started_at DESC LIMIT ?",
                (limit,)).fetchall()
    return [dict(r) for r in rows]
