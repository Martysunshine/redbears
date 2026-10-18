"""SQLite persistence for structured vulnerability knowledge.

Lives in the same project-wide ``memory.db`` as everything else (no new
infra) — reuses ``services.knowledge.store.conn()`` rather than opening a
second connection helper.

Three concerns:

1. ``vulnerability_records`` — one row per CVE. NVD, KEV and EPSS each own a
   disjoint set of columns and merge onto the SAME row through **column-scoped
   UPDATEs**, never a full-row overwrite — this is what lets three independent
   sources merge through the CVE id without one clobbering another's data.
2. ``cwe_records`` / ``capec_records`` (+ link tables) — MITRE's structured
   catalogs, refreshed whole-catalog but diffed per-record by content hash.
3. ``vulnerability_sync_state`` / ``vulnerability_import_jobs`` — incremental
   checkpoints and per-run history, mirroring the existing
   ``knowledge_import_jobs`` pattern one level down (per-source, not per-pack).

Every write here is idempotent: re-running a sync with unchanged upstream data
touches nothing (``content_hash`` / epsilon-gated float comparison decide what
actually needs a write), which is what makes interrupted-and-resumed syncs and
same-day re-runs safe.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from threading import Lock

from services.knowledge import store as kb_store

from .models import CapecRecord, CweRecord, EpssEntry, KevEntry, NvdCveEntry

_lock = Lock()

conn = kb_store.conn  # one connection helper, shared with the rest of Knowledge


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_obj(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_VULN_RECORD_COLUMNS = [
    ("nvd_backfill_attempts", "INTEGER DEFAULT 0"),
    ("nvd_unavailable_reason", "TEXT"),
    ("cvss_v4_vector", "TEXT"),
    ("cvss_v4_score", "REAL"),
    ("cvss_v4_severity", "TEXT"),
]

# NVD content-quality fields: a later sync only overwrites these when the new
# value is non-empty, so a transient/incomplete NVD response can never blank
# out previously-good data. Freshness/state fields (vuln_status, the two
# date columns) are NOT in this list — those always take the new value even
# if it looks "smaller" (e.g. a legitimate transition to vuln_status
# "Rejected"), because that transition is itself the authoritative update.
_NVD_QUALITY_FIELDS = ("description", "source_identifier",
                      "cvss_v4_vector", "cvss_v4_score", "cvss_v4_severity",
                      "cvss_v3_vector", "cvss_v3_score", "cvss_v3_severity",
                      "cvss_v2_vector", "cvss_v2_score", "cvss_v2_severity", "cvss_source")


def init_db() -> None:
    with _lock:
        con = conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS vulnerability_records (
                cve_id              TEXT PRIMARY KEY,
                vuln_status         TEXT,
                is_active           INTEGER DEFAULT 1,
                needs_nvd_backfill  INTEGER DEFAULT 0,
                description         TEXT,
                source_identifier   TEXT,
                published_date      TEXT,
                last_modified_date  TEXT,

                cvss_v3_vector      TEXT,
                cvss_v3_score       REAL,
                cvss_v3_severity    TEXT,
                cvss_v2_vector      TEXT,
                cvss_v2_score       REAL,
                cvss_v2_severity    TEXT,
                cvss_source         TEXT,

                epss_score          REAL,
                epss_percentile     REAL,
                epss_date           TEXT,

                kev_listed              INTEGER DEFAULT 0,
                kev_date_added          TEXT,
                kev_due_date            TEXT,
                kev_vulnerability_name  TEXT,
                kev_required_action     TEXT,
                kev_known_ransomware    TEXT,
                kev_notes               TEXT,

                affected_products_json TEXT,
                references_json        TEXT,

                primary_chunk_id TEXT,
                content_hash     TEXT,
                retrieved_at     TEXT,
                created_at       TEXT,
                updated_at       TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerability_records(kev_listed);
            CREATE INDEX IF NOT EXISTS idx_vuln_epss ON vulnerability_records(epss_score);
            CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerability_records(cvss_v3_score);
            CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vulnerability_records(last_modified_date);
            CREATE INDEX IF NOT EXISTS idx_vuln_active ON vulnerability_records(is_active);

            CREATE TABLE IF NOT EXISTS vulnerability_cwe_links (
                cve_id TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                PRIMARY KEY (cve_id, cwe_id)
            );
            CREATE INDEX IF NOT EXISTS idx_vcwe_cwe ON vulnerability_cwe_links(cwe_id);

            CREATE TABLE IF NOT EXISTS cwe_records (
                cwe_id TEXT PRIMARY KEY,
                name TEXT,
                abstraction TEXT,
                status TEXT,
                description TEXT,
                extended_description TEXT,
                likelihood_of_exploit TEXT,
                common_consequences_json TEXT,
                related_weaknesses_json TEXT,
                mitigations_json TEXT,
                detection_methods_json TEXT,
                references_json TEXT,
                primary_chunk_id TEXT,
                content_hash TEXT,
                version TEXT,
                retrieved_at TEXT,
                created_at TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS capec_records (
                capec_id TEXT PRIMARY KEY,
                name TEXT,
                abstraction TEXT,
                status TEXT,
                description TEXT,
                likelihood_of_attack TEXT,
                typical_severity TEXT,
                execution_flow_json TEXT,
                prerequisites_json TEXT,
                skills_required_json TEXT,
                related_weaknesses_json TEXT,
                related_attack_patterns_json TEXT,
                mitigations_json TEXT,
                references_json TEXT,
                primary_chunk_id TEXT,
                content_hash TEXT,
                version TEXT,
                retrieved_at TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS capec_cwe_links (
                capec_id TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                PRIMARY KEY (capec_id, cwe_id)
            );

            CREATE TABLE IF NOT EXISTS vulnerability_sync_state (
                source_id TEXT PRIMARY KEY,
                last_synced_at TEXT,
                cursor TEXT,
                last_status TEXT,
                last_error TEXT,
                records_seen_total INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS vulnerability_import_jobs (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                window_start TEXT,
                window_end TEXT,
                records_fetched INTEGER DEFAULT 0,
                records_added INTEGER DEFAULT 0,
                records_updated INTEGER DEFAULT 0,
                records_tombstoned INTEGER DEFAULT 0,
                records_skipped_unchanged INTEGER DEFAULT 0,
                injection_findings INTEGER DEFAULT 0,
                error TEXT,
                detail TEXT,
                started_at TEXT NOT NULL,
                finished_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_vimport_source ON vulnerability_import_jobs(source_id);

            CREATE TABLE IF NOT EXISTS vendor_advisories (
                advisory_id           TEXT PRIMARY KEY,
                source                TEXT NOT NULL,
                title                 TEXT,
                publisher             TEXT,
                initial_release_date  TEXT,
                current_release_date  TEXT,
                source_url            TEXT,
                content_hash          TEXT,
                retrieved_at          TEXT
            );
            CREATE TABLE IF NOT EXISTS vendor_advisory_findings (
                advisory_id           TEXT NOT NULL,
                cve_id                TEXT NOT NULL,
                cwe_id                TEXT,
                cvss_score            REAL,
                cvss_vector           TEXT,
                severity              TEXT,
                description           TEXT,
                remediation           TEXT,
                fixed_version         TEXT,
                vendor_reference_url  TEXT,
                PRIMARY KEY (advisory_id, cve_id)
            );
            CREATE INDEX IF NOT EXISTS idx_vaf_cve ON vendor_advisory_findings(cve_id);

            CREATE TABLE IF NOT EXISTS cve_cvss_scores (
                cve_id        TEXT NOT NULL,
                source        TEXT NOT NULL,
                cvss_version  TEXT NOT NULL,
                vector        TEXT,
                score         REAL,
                severity      TEXT,
                type          TEXT,
                PRIMARY KEY (cve_id, source, cvss_version)
            );
            CREATE INDEX IF NOT EXISTS idx_cvss_scores_cve ON cve_cvss_scores(cve_id);

            CREATE TABLE IF NOT EXISTS cisa_csaf_seen (
                advisory_id      TEXT PRIMARY KEY,
                feed_updated     TEXT,
                content_hash     TEXT,
                status           TEXT,
                last_attempt_at  TEXT,
                last_error       TEXT
            );

            CREATE TABLE IF NOT EXISTS redhat_csaf_seen (
                advisory_id      TEXT PRIMARY KEY,
                feed_updated     TEXT,
                content_hash     TEXT,
                status           TEXT,
                last_attempt_at  TEXT,
                last_error       TEXT
            );
            """
        )
        existing = {r[1] for r in con.execute("PRAGMA table_info(vulnerability_records)")}
        for col, decl in _VULN_RECORD_COLUMNS:
            if col not in existing:
                con.execute(f"ALTER TABLE vulnerability_records ADD COLUMN {col} {decl}")
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# KEV merge (kev_* columns only; tombstones delistings)
# ---------------------------------------------------------------------------

_KEV_COMPARE_FIELDS = ("kev_date_added", "kev_due_date", "kev_vulnerability_name",
                      "kev_required_action", "kev_known_ransomware", "kev_notes")


def sync_kev(entries: list[KevEntry]) -> dict:
    now = _ts()
    added = updated = unchanged = 0
    incoming_ids = {e.cve_id for e in entries}
    with _lock:
        con = conn()
        try:
            existing_kev = {
                r["cve_id"] for r in con.execute(
                    "SELECT cve_id FROM vulnerability_records WHERE kev_listed = 1"
                ).fetchall()
            }
            for e in entries:
                row = con.execute(
                    "SELECT kev_listed, kev_date_added, kev_due_date, kev_vulnerability_name, "
                    "kev_required_action, kev_known_ransomware, kev_notes "
                    "FROM vulnerability_records WHERE cve_id = ?", (e.cve_id,)
                ).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO vulnerability_records "
                        "(cve_id, is_active, needs_nvd_backfill, description, kev_listed, "
                        " kev_date_added, kev_due_date, kev_vulnerability_name, "
                        " kev_required_action, kev_known_ransomware, kev_notes, "
                        " retrieved_at, created_at, updated_at) "
                        "VALUES (?,1,1,?,1,?,?,?,?,?,?,?,?,?)",
                        (e.cve_id, e.short_description, e.date_added, e.due_date,
                         e.vulnerability_name, e.required_action, e.known_ransomware,
                         e.notes, now, now, now),
                    )
                    added += 1
                else:
                    incoming = (e.date_added, e.due_date, e.vulnerability_name,
                               e.required_action, e.known_ransomware, e.notes)
                    current = tuple(row[f] for f in _KEV_COMPARE_FIELDS)
                    if bool(row["kev_listed"]) and incoming == current:
                        unchanged += 1
                    else:
                        con.execute(
                            "UPDATE vulnerability_records SET kev_listed=1, kev_date_added=?, "
                            "kev_due_date=?, kev_vulnerability_name=?, kev_required_action=?, "
                            "kev_known_ransomware=?, kev_notes=?, updated_at=? WHERE cve_id=?",
                            (e.date_added, e.due_date, e.vulnerability_name, e.required_action,
                             e.known_ransomware, e.notes, now, e.cve_id),
                        )
                        updated += 1
                for cwe in e.cwe_ids:
                    con.execute(
                        "INSERT OR IGNORE INTO vulnerability_cwe_links (cve_id, cwe_id) VALUES (?,?)",
                        (e.cve_id, cwe),
                    )
            tombstoned = existing_kev - incoming_ids
            for cve_id in tombstoned:
                con.execute(
                    "UPDATE vulnerability_records SET kev_listed=0, kev_date_added=NULL, "
                    "kev_due_date=NULL, kev_vulnerability_name=NULL, kev_required_action=NULL, "
                    "kev_known_ransomware=NULL, kev_notes=NULL, updated_at=? WHERE cve_id=?",
                    (now, cve_id),
                )
            con.commit()
        finally:
            con.close()
    return {"added": added, "updated": updated, "unchanged": unchanged,
            "tombstoned": len(tombstoned), "fetched": len(entries)}


# ---------------------------------------------------------------------------
# NVD merge (NVD-owned columns only)
# ---------------------------------------------------------------------------

def sync_nvd_batch(entries: list[NvdCveEntry]) -> dict:
    now = _ts()
    added = updated = 0
    with _lock:
        con = conn()
        try:
            for e in entries:
                is_active = 0 if (e.vuln_status or "").lower() in ("rejected",) else 1
                row = con.execute(
                    "SELECT * FROM vulnerability_records WHERE cve_id = ?", (e.cve_id,)
                ).fetchone()
                refs = json.dumps(e.references[:15])
                products = json.dumps(e.affected_products[:50])
                if row is None:
                    con.execute(
                        "INSERT INTO vulnerability_records "
                        "(cve_id, vuln_status, is_active, needs_nvd_backfill, description, "
                        " source_identifier, published_date, last_modified_date, "
                        " cvss_v4_vector, cvss_v4_score, cvss_v4_severity, "
                        " cvss_v3_vector, cvss_v3_score, cvss_v3_severity, "
                        " cvss_v2_vector, cvss_v2_score, cvss_v2_severity, cvss_source, "
                        " references_json, affected_products_json, "
                        " retrieved_at, created_at, updated_at) "
                        "VALUES (?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (e.cve_id, e.vuln_status, is_active, e.description, e.source_identifier,
                         e.published_date, e.last_modified_date,
                         e.cvss_v4_vector, e.cvss_v4_score, e.cvss_v4_severity,
                         e.cvss_v3_vector, e.cvss_v3_score, e.cvss_v3_severity,
                         e.cvss_v2_vector, e.cvss_v2_score, e.cvss_v2_severity, e.cvss_source,
                         refs, products, now, now, now),
                    )
                    added += 1
                else:
                    # Content-quality fields: keep the prior value if the new
                    # fetch came back empty for it (never let a sparse
                    # response blank out previously-good data).
                    merged = {}
                    for field in _NVD_QUALITY_FIELDS:
                        new_val = getattr(e, field, None)
                        merged[field] = new_val if new_val not in (None, "") else row[field]
                    # References/affected-products: only replace when the new
                    # fetch actually returned something.
                    final_refs = refs if e.references else row["references_json"]
                    final_products = products if e.affected_products else row["affected_products_json"]
                    con.execute(
                        "UPDATE vulnerability_records SET vuln_status=?, is_active=?, "
                        "needs_nvd_backfill=0, description=?, source_identifier=?, "
                        "published_date=?, last_modified_date=?, "
                        "cvss_v4_vector=?, cvss_v4_score=?, cvss_v4_severity=?, "
                        "cvss_v3_vector=?, cvss_v3_score=?, cvss_v3_severity=?, "
                        "cvss_v2_vector=?, cvss_v2_score=?, cvss_v2_severity=?, cvss_source=?, "
                        "references_json=?, affected_products_json=?, updated_at=? "
                        "WHERE cve_id=?",
                        (e.vuln_status, is_active, merged["description"], merged["source_identifier"],
                         e.published_date, e.last_modified_date,
                         merged["cvss_v4_vector"], merged["cvss_v4_score"], merged["cvss_v4_severity"],
                         merged["cvss_v3_vector"], merged["cvss_v3_score"], merged["cvss_v3_severity"],
                         merged["cvss_v2_vector"], merged["cvss_v2_score"], merged["cvss_v2_severity"],
                         merged["cvss_source"], final_refs, final_products, now, e.cve_id),
                    )
                    updated += 1
                # NVD's own CWE assignment replaces any prior NVD-sourced links for
                # this CVE (KEV-sourced links use the same table but are additive
                # elsewhere — duplicates are harmless, the PK is (cve_id, cwe_id)).
                for cwe in e.cwe_ids:
                    con.execute(
                        "INSERT OR IGNORE INTO vulnerability_cwe_links (cve_id, cwe_id) VALUES (?,?)",
                        (e.cve_id, cwe),
                    )
                # Every individual source-specific CVSS metric NVD returned —
                # preserved separately even when it disagrees with the
                # "preferred" score selected onto the row above.
                for s in e.all_cvss_scores:
                    con.execute(
                        """INSERT INTO cve_cvss_scores (cve_id, source, cvss_version, vector, score, severity, type)
                           VALUES (?,?,?,?,?,?,?)
                           ON CONFLICT(cve_id, source, cvss_version) DO UPDATE SET
                             vector=excluded.vector, score=excluded.score,
                             severity=excluded.severity, type=excluded.type""",
                        (e.cve_id, s.get("source") or "unknown", s["cvss_version"],
                         s.get("vector"), s.get("score"), s.get("severity"), s.get("type")),
                    )
            con.commit()
        finally:
            con.close()
    return {"added": added, "updated": updated, "fetched": len(entries)}


def get_cvss_scores_for_cve(cve_id: str) -> list[dict]:
    """Every source-specific CVSS metric on file for this CVE — the raw
    material for surfacing "which score came from which source" and any
    cross-source disagreement, distinct from the single preferred score
    selected onto ``vulnerability_records``."""
    con = conn()
    rows = con.execute(
        "SELECT source, cvss_version, vector, score, severity, type FROM cve_cvss_scores "
        "WHERE cve_id = ? ORDER BY cvss_version DESC, source", (cve_id.upper(),),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# EPSS merge (epss_* columns only; epsilon-gated skip-if-unchanged)
# ---------------------------------------------------------------------------

def sync_epss_batch(entries: list[EpssEntry], epsilon: float = 1e-4) -> dict:
    now = _ts()
    added = updated = unchanged = 0
    with _lock:
        con = conn()
        try:
            for e in entries:
                row = con.execute(
                    "SELECT epss_score, epss_percentile FROM vulnerability_records WHERE cve_id = ?",
                    (e.cve_id,),
                ).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO vulnerability_records "
                        "(cve_id, is_active, needs_nvd_backfill, epss_score, epss_percentile, "
                        " epss_date, retrieved_at, created_at, updated_at) "
                        "VALUES (?,1,1,?,?,?,?,?,?)",
                        (e.cve_id, e.score, e.percentile, e.as_of, now, now, now),
                    )
                    added += 1
                    continue
                prev_score, prev_pct = row["epss_score"], row["epss_percentile"]
                changed = (
                    prev_score is None
                    or abs(float(prev_score) - e.score) > epsilon
                    or prev_pct is None
                    or abs(float(prev_pct) - e.percentile) > epsilon
                )
                if not changed:
                    unchanged += 1
                    continue
                con.execute(
                    "UPDATE vulnerability_records SET epss_score=?, epss_percentile=?, "
                    "epss_date=?, updated_at=? WHERE cve_id=?",
                    (e.score, e.percentile, e.as_of, now, e.cve_id),
                )
                updated += 1
            con.commit()
        finally:
            con.close()
    return {"added": added, "updated": updated, "unchanged": unchanged, "fetched": len(entries)}


# ---------------------------------------------------------------------------
# CWE / CAPEC (whole-catalog refresh, diffed per-record by content hash)
# ---------------------------------------------------------------------------

def sync_cwe_records(records: list[CweRecord]) -> dict:
    now = _ts()
    added = updated = unchanged = 0
    with _lock:
        con = conn()
        try:
            for r in records:
                payload = asdict(r)
                chash = _hash_obj(payload)
                row = con.execute(
                    "SELECT content_hash FROM cwe_records WHERE cwe_id = ?", (r.cwe_id,)
                ).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO cwe_records (cwe_id, name, abstraction, status, description, "
                        "extended_description, likelihood_of_exploit, common_consequences_json, "
                        "related_weaknesses_json, mitigations_json, detection_methods_json, "
                        "references_json, content_hash, version, retrieved_at, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (r.cwe_id, r.name, r.abstraction, r.status, r.description,
                         r.extended_description, r.likelihood_of_exploit,
                         json.dumps(r.common_consequences), json.dumps(r.related_weaknesses),
                         json.dumps(r.mitigations), json.dumps(r.detection_methods),
                         json.dumps(r.references), chash, r.version, now, now, now),
                    )
                    added += 1
                elif row["content_hash"] != chash:
                    con.execute(
                        "UPDATE cwe_records SET name=?, abstraction=?, status=?, description=?, "
                        "extended_description=?, likelihood_of_exploit=?, common_consequences_json=?, "
                        "related_weaknesses_json=?, mitigations_json=?, detection_methods_json=?, "
                        "references_json=?, content_hash=?, version=?, updated_at=? WHERE cwe_id=?",
                        (r.name, r.abstraction, r.status, r.description, r.extended_description,
                         r.likelihood_of_exploit, json.dumps(r.common_consequences),
                         json.dumps(r.related_weaknesses), json.dumps(r.mitigations),
                         json.dumps(r.detection_methods), json.dumps(r.references),
                         chash, r.version, now, r.cwe_id),
                    )
                    updated += 1
                else:
                    unchanged += 1
            con.commit()
        finally:
            con.close()
    return {"added": added, "updated": updated, "unchanged": unchanged, "fetched": len(records)}


def sync_capec_records(records: list[CapecRecord]) -> dict:
    now = _ts()
    added = updated = unchanged = 0
    with _lock:
        con = conn()
        try:
            for r in records:
                payload = asdict(r)
                chash = _hash_obj(payload)
                row = con.execute(
                    "SELECT content_hash FROM capec_records WHERE capec_id = ?", (r.capec_id,)
                ).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO capec_records (capec_id, name, abstraction, status, description, "
                        "likelihood_of_attack, typical_severity, execution_flow_json, prerequisites_json, "
                        "skills_required_json, related_weaknesses_json, related_attack_patterns_json, "
                        "mitigations_json, references_json, content_hash, version, retrieved_at, "
                        "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (r.capec_id, r.name, r.abstraction, r.status, r.description,
                         r.likelihood_of_attack, r.typical_severity,
                         json.dumps(r.execution_flow), json.dumps(r.prerequisites),
                         json.dumps(r.skills_required), json.dumps(r.related_weaknesses),
                         json.dumps(r.related_attack_patterns), json.dumps(r.mitigations),
                         json.dumps(r.references), chash, r.version, now, now, now),
                    )
                    added += 1
                elif row["content_hash"] != chash:
                    con.execute(
                        "UPDATE capec_records SET name=?, abstraction=?, status=?, description=?, "
                        "likelihood_of_attack=?, typical_severity=?, execution_flow_json=?, "
                        "prerequisites_json=?, skills_required_json=?, related_weaknesses_json=?, "
                        "related_attack_patterns_json=?, mitigations_json=?, references_json=?, "
                        "content_hash=?, version=?, updated_at=? WHERE capec_id=?",
                        (r.name, r.abstraction, r.status, r.description, r.likelihood_of_attack,
                         r.typical_severity, json.dumps(r.execution_flow), json.dumps(r.prerequisites),
                         json.dumps(r.skills_required), json.dumps(r.related_weaknesses),
                         json.dumps(r.related_attack_patterns), json.dumps(r.mitigations),
                         json.dumps(r.references), chash, r.version, now, r.capec_id),
                    )
                    updated += 1
                else:
                    unchanged += 1
                for cwe in r.related_weaknesses:
                    con.execute(
                        "INSERT OR IGNORE INTO capec_cwe_links (capec_id, cwe_id) VALUES (?,?)",
                        (r.capec_id, cwe),
                    )
            con.commit()
        finally:
            con.close()
    return {"added": added, "updated": updated, "unchanged": unchanged, "fetched": len(records)}


# ---------------------------------------------------------------------------
# Exact-ID lookup (no vector/FTS involved)
# ---------------------------------------------------------------------------

def get_vulnerability(cve_id: str) -> dict | None:
    with conn() as con:
        row = con.execute(
            "SELECT * FROM vulnerability_records WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row is None:
            return None
        rec = dict(row)
        cwes = con.execute(
            "SELECT cwe_id FROM vulnerability_cwe_links WHERE cve_id = ?", (cve_id,)
        ).fetchall()
    rec["cwe_ids"] = [r["cwe_id"] for r in cwes]
    rec["affected_products"] = json.loads(rec.get("affected_products_json") or "[]")
    rec["references"] = json.loads(rec.get("references_json") or "[]")
    return rec


def get_cwe(cwe_id: str) -> dict | None:
    with conn() as con:
        row = con.execute("SELECT * FROM cwe_records WHERE cwe_id = ?", (cwe_id,)).fetchone()
        if row is None:
            return None
        rec = dict(row)
        cves = con.execute(
            "SELECT cve_id FROM vulnerability_cwe_links WHERE cwe_id = ? LIMIT 50", (cwe_id,)
        ).fetchall()
        capecs = con.execute(
            "SELECT capec_id FROM capec_cwe_links WHERE cwe_id = ?", (cwe_id,)
        ).fetchall()
    for jf in ("common_consequences", "related_weaknesses", "mitigations",
               "detection_methods", "references"):
        rec[jf] = json.loads(rec.pop(f"{jf}_json", None) or "[]")
    rec["example_cve_ids"] = [r["cve_id"] for r in cves]
    rec["related_capec_ids"] = [r["capec_id"] for r in capecs]
    return rec


def get_capec(capec_id: str) -> dict | None:
    with conn() as con:
        row = con.execute("SELECT * FROM capec_records WHERE capec_id = ?", (capec_id,)).fetchone()
        if row is None:
            return None
        rec = dict(row)
    for jf in ("execution_flow", "prerequisites", "skills_required", "related_weaknesses",
               "related_attack_patterns", "mitigations", "references"):
        rec[jf] = json.loads(rec.pop(f"{jf}_json", None) or "[]")
    return rec


def search_vulnerabilities(kev_only: bool = False, min_cvss: float | None = None,
                           min_epss: float | None = None, since: str | None = None,
                           limit: int = 50) -> list[dict]:
    clauses = ["is_active = 1"]
    params: list = []
    if kev_only:
        clauses.append("kev_listed = 1")
    if min_cvss is not None:
        clauses.append("cvss_v3_score >= ?")
        params.append(min_cvss)
    if min_epss is not None:
        clauses.append("epss_score >= ?")
        params.append(min_epss)
    if since:
        clauses.append("last_modified_date >= ?")
        params.append(since)
    sql = (
        "SELECT cve_id, description, cvss_v3_score, cvss_v3_severity, epss_score, "
        "epss_percentile, kev_listed, kev_due_date, last_modified_date FROM vulnerability_records "
        "WHERE " + " AND ".join(clauses)
        + " ORDER BY kev_listed DESC, COALESCE(epss_score,0) DESC, COALESCE(cvss_v3_score,0) DESC LIMIT ?"
    )
    params.append(limit)
    with conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def kev_listed_cve_ids() -> list[str]:
    with conn() as con:
        rows = con.execute(
            "SELECT cve_id FROM vulnerability_records WHERE kev_listed = 1"
        ).fetchall()
    return [r["cve_id"] for r in rows]


def kev_ids_needing_nvd_backfill() -> list[str]:
    """KEV-listed CVEs that still need an NVD lookup — the resumable frontier
    for ``sync.enrich_kev_from_nvd``. Once a CVE's NVD data is merged in,
    ``sync_nvd_batch`` clears ``needs_nvd_backfill``, so a restarted
    enrichment run naturally skips everything already done. A CVE marked
    permanently unavailable (``mark_nvd_unavailable``) also clears
    ``needs_nvd_backfill``, so it is excluded here too — it will never be
    retried again without an explicit reset."""
    with conn() as con:
        rows = con.execute(
            "SELECT cve_id FROM vulnerability_records WHERE kev_listed = 1 AND needs_nvd_backfill = 1"
        ).fetchall()
    return [r["cve_id"] for r in rows]


def mark_nvd_unavailable(cve_id: str, reason: str) -> None:
    """Terminal outcome: stop retrying this CVE (clears ``needs_nvd_backfill``)
    and record why, so a legitimately-missing NVD record (withdrawn/reserved
    CVE, persistent lookup failure) does not get re-requested on every future
    enrichment resume."""
    now = _ts()
    with _lock:
        con = conn()
        con.execute(
            "UPDATE vulnerability_records SET needs_nvd_backfill=0, nvd_unavailable_reason=?, "
            "updated_at=? WHERE cve_id=?",
            (reason, now, cve_id),
        )
        con.commit()
        con.close()


def bump_nvd_backfill_attempt(cve_id: str) -> int:
    """Increment and return the per-CVE attempt counter (survives across
    separate enrich-kev runs/resumes) — used to cap retries on a CVE that
    keeps failing transiently, distinct from the in-request retry/backoff
    inside a single HTTP call."""
    with _lock:
        con = conn()
        con.execute(
            "UPDATE vulnerability_records SET nvd_backfill_attempts = COALESCE(nvd_backfill_attempts,0) + 1 "
            "WHERE cve_id=?",
            (cve_id,),
        )
        con.commit()
        row = con.execute(
            "SELECT nvd_backfill_attempts FROM vulnerability_records WHERE cve_id=?", (cve_id,)
        ).fetchone()
        con.close()
    return row["nvd_backfill_attempts"] if row else 0


def nvd_unavailable_cve_ids() -> list[dict]:
    """KEV-listed CVEs permanently marked unavailable, with their reason —
    for reporting, never re-queried by the enrichment frontier."""
    with conn() as con:
        rows = con.execute(
            "SELECT cve_id, nvd_unavailable_reason, nvd_backfill_attempts FROM vulnerability_records "
            "WHERE kev_listed = 1 AND nvd_unavailable_reason IS NOT NULL"
        ).fetchall()
    return [dict(r) for r in rows]


def counts() -> dict:
    with conn() as con:
        vuln = con.execute("SELECT COUNT(*) c FROM vulnerability_records").fetchone()["c"]
        kev = con.execute("SELECT COUNT(*) c FROM vulnerability_records WHERE kev_listed=1").fetchone()["c"]
        stub = con.execute("SELECT COUNT(*) c FROM vulnerability_records WHERE needs_nvd_backfill=1").fetchone()["c"]
        cwe = con.execute("SELECT COUNT(*) c FROM cwe_records").fetchone()["c"]
        capec = con.execute("SELECT COUNT(*) c FROM capec_records").fetchone()["c"]
        vcwe_links = con.execute("SELECT COUNT(*) c FROM vulnerability_cwe_links").fetchone()["c"]
        capec_links = con.execute("SELECT COUNT(*) c FROM capec_cwe_links").fetchone()["c"]
    return {"vulnerability_records": vuln, "kev_listed": kev, "needs_nvd_backfill": stub,
            "cwe_records": cwe, "capec_records": capec,
            "vulnerability_cwe_links": vcwe_links, "capec_cwe_links": capec_links}


# ---------------------------------------------------------------------------
# Primary-chunk / content-hash bookkeeping (for citation resolution + re-embed skip)
# ---------------------------------------------------------------------------

def set_vuln_chunk(cve_id: str, chunk_id: str, content_hash: str) -> None:
    with _lock:
        con = conn()
        con.execute(
            "UPDATE vulnerability_records SET primary_chunk_id=?, content_hash=? WHERE cve_id=?",
            (chunk_id, content_hash, cve_id),
        )
        con.commit()
        con.close()


def get_vuln_content_hash(cve_id: str) -> str | None:
    with conn() as con:
        row = con.execute(
            "SELECT content_hash FROM vulnerability_records WHERE cve_id=?", (cve_id,)
        ).fetchone()
    return row["content_hash"] if row else None


def set_cwe_chunk(cwe_id: str, chunk_id: str) -> None:
    with _lock:
        con = conn()
        con.execute("UPDATE cwe_records SET primary_chunk_id=? WHERE cwe_id=?", (chunk_id, cwe_id))
        con.commit()
        con.close()


def set_capec_chunk(capec_id: str, chunk_id: str) -> None:
    with _lock:
        con = conn()
        con.execute("UPDATE capec_records SET primary_chunk_id=? WHERE capec_id=?", (chunk_id, capec_id))
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Sync-state checkpoints
# ---------------------------------------------------------------------------

def get_sync_state(source_id: str) -> dict | None:
    with conn() as con:
        row = con.execute(
            "SELECT * FROM vulnerability_sync_state WHERE source_id = ?", (source_id,)
        ).fetchone()
    return dict(row) if row else None


def set_sync_state(source_id: str, *, cursor: str | None = None, status: str | None = None,
                   error: str | None = None, records_seen_delta: int = 0) -> None:
    now = _ts()
    with _lock:
        con = conn()
        existing = con.execute(
            "SELECT records_seen_total FROM vulnerability_sync_state WHERE source_id=?",
            (source_id,),
        ).fetchone()
        total = (existing["records_seen_total"] if existing else 0) + records_seen_delta
        con.execute(
            "INSERT INTO vulnerability_sync_state (source_id, last_synced_at, cursor, last_status, "
            "last_error, records_seen_total) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(source_id) DO UPDATE SET last_synced_at=excluded.last_synced_at, "
            "cursor=COALESCE(excluded.cursor, vulnerability_sync_state.cursor), "
            "last_status=excluded.last_status, last_error=excluded.last_error, "
            "records_seen_total=excluded.records_seen_total",
            (source_id, now, cursor, status, error, total),
        )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# Import jobs (per-source ingestion lifecycle)
# ---------------------------------------------------------------------------

def start_job(job_id: str, source_id: str, mode: str, window_start: str | None = None,
             window_end: str | None = None) -> None:
    with _lock:
        con = conn()
        con.execute(
            "INSERT OR REPLACE INTO vulnerability_import_jobs "
            "(id, source_id, mode, status, window_start, window_end, started_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (job_id, source_id, mode, "running", window_start, window_end, _ts()),
        )
        con.commit()
        con.close()


def finish_job(job_id: str, status: str, **fields) -> None:
    cols = ["status", "finished_at"]
    vals: list = [status, _ts()]
    for k in ("records_fetched", "records_added", "records_updated", "records_tombstoned",
              "records_skipped_unchanged", "injection_findings", "error", "detail"):
        if k in fields:
            cols.append(k)
            vals.append(fields[k])
    set_clause = ",".join(f"{c}=?" for c in cols)
    with _lock:
        con = conn()
        con.execute(f"UPDATE vulnerability_import_jobs SET {set_clause} WHERE id=?", (*vals, job_id))
        con.commit()
        con.close()


def list_jobs(source_id: str | None = None, limit: int = 50) -> list[dict]:
    with conn() as con:
        if source_id:
            rows = con.execute(
                "SELECT * FROM vulnerability_import_jobs WHERE source_id=? "
                "ORDER BY started_at DESC LIMIT ?", (source_id, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM vulnerability_import_jobs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def stale_running_jobs(source_id: str, older_than_seconds: int = 7200) -> list[dict]:
    """Jobs stuck in 'running' (crashed mid-run) — safe to retry over."""
    cutoff = datetime.now(timezone.utc).timestamp() - older_than_seconds
    out = []
    for j in list_jobs(source_id):
        if j["status"] != "running":
            continue
        try:
            started = datetime.fromisoformat(j["started_at"]).timestamp()
        except (ValueError, TypeError):
            continue
        if started < cutoff:
            out.append(j)
    return out


# ---------------------------------------------------------------------------
# Vendor advisories (CISA CSAF etc.) — CVE-row enrichment, never a duplicate
# of the NVD record itself.
# ---------------------------------------------------------------------------

def upsert_vendor_advisory(rec: dict) -> str:
    """Returns ``"added"``, ``"updated"`` or ``"unchanged"``. Content-hash
    gated so a resumed run over an already-current advisory writes nothing."""
    payload = {k: rec.get(k) for k in ("source", "title", "publisher",
               "initial_release_date", "current_release_date", "source_url")}
    chash = _hash_obj(payload)
    with _lock:
        con = conn()
        cur = con.execute("SELECT content_hash FROM vendor_advisories WHERE advisory_id=?",
                          (rec["advisory_id"],))
        row = cur.fetchone()
        if row is not None and row["content_hash"] == chash:
            con.close()
            return "unchanged"
        status = "updated" if row is not None else "added"
        now = _ts()
        con.execute(
            """INSERT INTO vendor_advisories
               (advisory_id, source, title, publisher, initial_release_date,
                current_release_date, source_url, content_hash, retrieved_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(advisory_id) DO UPDATE SET
                 source=excluded.source, title=excluded.title, publisher=excluded.publisher,
                 initial_release_date=excluded.initial_release_date,
                 current_release_date=excluded.current_release_date,
                 source_url=excluded.source_url, content_hash=excluded.content_hash,
                 retrieved_at=excluded.retrieved_at""",
            (rec["advisory_id"], rec.get("source"), rec.get("title"), rec.get("publisher"),
             rec.get("initial_release_date"), rec.get("current_release_date"),
             rec.get("source_url"), chash, now),
        )
        con.commit()
        con.close()
        return status


# Fields where a new value that is empty/None should never clobber a prior
# non-empty value — CSAF documents occasionally get republished with a
# trimmed remediation/description section; the richer prior text is kept.
_FINDING_QUALITY_FIELDS = ("cwe_id", "cvss_score", "cvss_vector", "severity",
                          "description", "remediation", "fixed_version", "vendor_reference_url")


def replace_vendor_findings(advisory_id: str, findings: list[dict]) -> None:
    with _lock:
        con = conn()
        existing = {
            r["cve_id"]: dict(r)
            for r in con.execute(
                "SELECT * FROM vendor_advisory_findings WHERE advisory_id=?", (advisory_id,)
            ).fetchall()
        }
        con.execute("DELETE FROM vendor_advisory_findings WHERE advisory_id=?", (advisory_id,))
        for f in findings:
            if not f.get("cve_id"):
                continue
            prior = existing.get(f["cve_id"])
            merged = dict(f)
            if prior:
                for field in _FINDING_QUALITY_FIELDS:
                    if not merged.get(field) and prior.get(field):
                        merged[field] = prior[field]
            con.execute(
                """INSERT OR IGNORE INTO vendor_advisory_findings
                   (advisory_id, cve_id, cwe_id, cvss_score, cvss_vector, severity,
                    description, remediation, fixed_version, vendor_reference_url)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (advisory_id, merged["cve_id"], merged.get("cwe_id"), merged.get("cvss_score"),
                 merged.get("cvss_vector"), merged.get("severity"), merged.get("description"),
                 merged.get("remediation"), merged.get("fixed_version"), merged.get("vendor_reference_url")),
            )
        con.commit()
        con.close()


# ---------------------------------------------------------------------------
# CISA CSAF resume/checkpoint cache — keyed by advisory_id, compares against
# the feed's own `updated` timestamp so a resumed run skips re-fetching any
# advisory whose upstream document hasn't changed since it was last fetched.
# ---------------------------------------------------------------------------

def get_cisa_csaf_seen(advisory_id: str) -> dict | None:
    con = conn()
    row = con.execute("SELECT * FROM cisa_csaf_seen WHERE advisory_id=?", (advisory_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def record_cisa_csaf_seen(advisory_id: str, *, feed_updated: str | None, content_hash: str | None,
                          status: str, error: str | None = None) -> None:
    with _lock:
        con = conn()
        con.execute(
            """INSERT INTO cisa_csaf_seen (advisory_id, feed_updated, content_hash, status,
                                           last_attempt_at, last_error)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(advisory_id) DO UPDATE SET
                 feed_updated=excluded.feed_updated, content_hash=excluded.content_hash,
                 status=excluded.status, last_attempt_at=excluded.last_attempt_at,
                 last_error=excluded.last_error""",
            (advisory_id, feed_updated, content_hash, status, _ts(), error),
        )
        con.commit()
        con.close()


def cisa_csaf_seen_stats() -> dict:
    con = conn()
    rows = con.execute("SELECT status, COUNT(*) c FROM cisa_csaf_seen GROUP BY status").fetchall()
    con.close()
    return {r["status"]: r["c"] for r in rows}


# ---------------------------------------------------------------------------
# Red Hat CSAF resume/checkpoint cache — same shape as cisa_csaf_seen, kept as
# a separate table (rather than adding a `provider` column to the CISA one) so
# the well-tested CISA checkpoint path is never touched by this addition.
# ---------------------------------------------------------------------------

def get_redhat_csaf_seen(advisory_id: str) -> dict | None:
    con = conn()
    row = con.execute("SELECT * FROM redhat_csaf_seen WHERE advisory_id=?", (advisory_id,)).fetchone()
    con.close()
    return dict(row) if row else None


def record_redhat_csaf_seen(advisory_id: str, *, feed_updated: str | None, content_hash: str | None,
                            status: str, error: str | None = None) -> None:
    with _lock:
        con = conn()
        con.execute(
            """INSERT INTO redhat_csaf_seen (advisory_id, feed_updated, content_hash, status,
                                              last_attempt_at, last_error)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(advisory_id) DO UPDATE SET
                 feed_updated=excluded.feed_updated, content_hash=excluded.content_hash,
                 status=excluded.status, last_attempt_at=excluded.last_attempt_at,
                 last_error=excluded.last_error""",
            (advisory_id, feed_updated, content_hash, status, _ts(), error),
        )
        con.commit()
        con.close()


def redhat_csaf_seen_stats() -> dict:
    con = conn()
    rows = con.execute("SELECT status, COUNT(*) c FROM redhat_csaf_seen GROUP BY status").fetchall()
    con.close()
    return {r["status"]: r["c"] for r in rows}


def get_vendor_advisories_for_cve(cve_id: str) -> list[dict]:
    con = conn()
    rows = con.execute(
        """SELECT va.advisory_id, va.source, va.title, va.publisher, va.source_url,
                  va.current_release_date, f.cwe_id, f.cvss_score, f.cvss_vector,
                  f.severity, f.description, f.remediation, f.fixed_version,
                  f.vendor_reference_url
           FROM vendor_advisory_findings f JOIN vendor_advisories va
             ON f.advisory_id = va.advisory_id
           WHERE f.cve_id = ?""",
        (cve_id.upper(),),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def vendor_advisory_counts() -> dict:
    con = conn()
    advisories = con.execute("SELECT source, COUNT(*) c FROM vendor_advisories GROUP BY source").fetchall()
    findings = con.execute("SELECT COUNT(*) c FROM vendor_advisory_findings").fetchone()
    distinct_cves = con.execute("SELECT COUNT(DISTINCT cve_id) c FROM vendor_advisory_findings").fetchone()
    con.close()
    return {
        "advisories_by_source": {r["source"]: r["c"] for r in advisories},
        "total_advisories": sum(r["c"] for r in advisories),
        "total_findings": findings["c"],
        "distinct_cves_enriched": distinct_cves["c"],
    }
