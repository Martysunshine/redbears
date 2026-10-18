"""Sync orchestration: checkpoint -> fetch -> neutralize -> merge -> upsert
retrieval-text chunks -> update checkpoint -> job record -> audit.

Each ``sync_*`` function is a complete, isolated pipeline for one source. A
failure in one never touches another's data or checkpoint — every function
catches its own exceptions, records them on the job/sync-state rows, and
returns an ``ok: False`` result rather than raising, so a caller (the router,
the CLI, a future scheduler) can run all five and continue past a failure.

Retrieval-text chunks are only written when a record's generated text has
actually changed (content-hash compared against what's already stored) — this
is what keeps a same-day EPSS re-run or an unchanged-KEV-catalog re-run cheap.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx

import config
import log_config
from services import rag_service
from services.knowledge import store as kb_store

from . import osv_store, store, text_repr
from .sources import capec, cisa_csaf, cwe, epss, kev, nvd
from .sources import ghsa as ghsa_src
from .sources import osv as osv_src
from .sources import redhat_csaf
from .sources.osv_schema import parse_osv_record

_VULN_PACK_ID = "vulnerability-cve"
_CWE_PACK_ID = "mitre-cwe"
_CAPEC_PACK_ID = "mitre-capec"


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nvd_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _chunk_windows(start: datetime, end: datetime, max_days: int) -> list[tuple[datetime, datetime]]:
    windows = []
    cur = start
    step = timedelta(days=max_days)
    while cur < end:
        nxt = min(cur + step, end)
        windows.append((cur, nxt))
        cur = nxt
    return windows or [(start, end)]


def _register_pack(pack_id: str, title: str, domain: str, security_domain: str,
                   licence: str, attribution: str, trust_level: str,
                   source_urls: list[str], doc_count: int, chunk_count: int,
                   version: str | None = None) -> None:
    now = _ts()
    con = kb_store.conn()
    try:
        # enabled=0 — a new vulnerability pack arrives SWITCHED OFF.
        #
        # It used to be 1, so the first sync silently enrolled these packs into
        # general knowledge retrieval. That is not neutral: the vulnerability
        # hits are fused as their own ranked list with full weight and no
        # similarity floor, the per-pack diversity cap is 3 while the answer only
        # has room for 6 citations, and these three packs carry the maximum trust
        # and freshness weights. So "how do I test session management" could come
        # back citing CVEs instead of the OWASP testing guide — a regression in
        # answers people already rely on, caused by a sync they ran for an
        # unrelated reason.
        #
        # Off by default makes enabling it a decision, taken after looking at the
        # data. The ON CONFLICT clause deliberately does NOT touch `enabled`, so
        # re-syncing never re-enables a pack somebody turned off.
        con.execute(
            "INSERT INTO knowledge_packs (pack_id,version,title,domain,doc_count,chunk_count,"
            "installed_at,updated_at,enabled,content_checksum,licence,attribution,"
            "risk_classification,security_domain,source_urls,trust_level,retrieved_at,"
            "last_reviewed_at,freshness_policy,installation_status,update_status,pack_kind) "
            "VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(pack_id) DO UPDATE SET version=excluded.version, doc_count=excluded.doc_count,"
            " chunk_count=excluded.chunk_count, updated_at=excluded.updated_at,"
            " retrieved_at=excluded.retrieved_at, update_status='current'",
            (pack_id, version or now[:10], title, domain, doc_count, chunk_count, now, now,
             None, licence, attribution, "informational", security_domain,
             ",".join(source_urls), trust_level, now, now,
             "Rolling; see vulnerability_sync_state for last sync.", "installed", "current",
             "vulnerability_feed"),
        )
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Re-embed helpers — only write a chunk when the generated text actually changed
# ---------------------------------------------------------------------------

async def _reembed_vulnerability(cve_id: str) -> bool:
    rec = store.get_vulnerability(cve_id)
    if rec is None:
        return False
    text = text_repr.vulnerability_text(rec)
    chash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if rec.get("content_hash") == chash:
        return False
    chunk_id = f"vuln::cve::{cve_id}"
    metadata = {
        "is_knowledge": True, "knowledge_pack": _VULN_PACK_ID, "doc_id": chunk_id,
        "cve_id": cve_id, "kev_listed": bool(rec.get("kev_listed")),
        "cvss_v3_score": rec.get("cvss_v3_score"), "epss_score": rec.get("epss_score"),
    }
    await rag_service.upsert_vulnerability_chunk_async(chunk_id, text, metadata)
    kb_store.upsert_chunk({
        "id": chunk_id, "pack_id": _VULN_PACK_ID, "pack_version": _ts()[:10],
        "doc_id": chunk_id, "document": cve_id, "source_type": "vulnerability_feed",
        "title": cve_id, "publisher": "NVD / CISA / FIRST",
        "canonical_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "licence": "nist-nvd-public", "trust_level": "official",
        "risk_level": "critical" if rec.get("kev_listed") else "informational",
        "domain": "vulnerability", "section": None, "chunk_index": 0,
        "content_hash": chash, "content": text, "cve_id": cve_id,
    })
    store.set_vuln_chunk(cve_id, chunk_id, chash)
    return True


async def _reembed_cwe(cwe_id: str) -> bool:
    rec = store.get_cwe(cwe_id)
    if rec is None:
        return False
    text = text_repr.cwe_text(rec)
    chunk_id = f"vuln::cwe::{cwe_id}"
    chash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    metadata = {"is_knowledge": True, "knowledge_pack": _CWE_PACK_ID, "doc_id": chunk_id, "cwe_id": cwe_id}
    await rag_service.upsert_vulnerability_chunk_async(chunk_id, text, metadata)
    kb_store.upsert_chunk({
        "id": chunk_id, "pack_id": _CWE_PACK_ID, "pack_version": rec.get("version") or _ts()[:10],
        "doc_id": chunk_id, "document": cwe_id, "source_type": "vulnerability_feed",
        "title": f"{cwe_id}: {rec.get('name') or ''}", "publisher": "MITRE",
        "canonical_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
        "licence": "mitre-cwe-terms", "trust_level": "official", "risk_level": "informational",
        "domain": "vulnerability", "section": None, "chunk_index": 0,
        "content_hash": chash, "content": text, "cwe_id": cwe_id,
    })
    store.set_cwe_chunk(cwe_id, chunk_id)
    return True


async def _reembed_capec(capec_id: str) -> bool:
    rec = store.get_capec(capec_id)
    if rec is None:
        return False
    text = text_repr.capec_text(rec)
    chunk_id = f"vuln::capec::{capec_id}"
    chash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    metadata = {"is_knowledge": True, "knowledge_pack": _CAPEC_PACK_ID, "doc_id": chunk_id, "capec_id": capec_id}
    await rag_service.upsert_vulnerability_chunk_async(chunk_id, text, metadata)
    kb_store.upsert_chunk({
        "id": chunk_id, "pack_id": _CAPEC_PACK_ID, "pack_version": rec.get("version") or _ts()[:10],
        "doc_id": chunk_id, "document": capec_id, "source_type": "vulnerability_feed",
        "title": f"{capec_id}: {rec.get('name') or ''}", "publisher": "MITRE",
        "canonical_url": f"https://capec.mitre.org/data/definitions/{capec_id.split('-')[1]}.html",
        "licence": "mitre-capec-terms", "trust_level": "official", "risk_level": "informational",
        "domain": "vulnerability", "section": None, "chunk_index": 0,
        "content_hash": chash, "content": text, "capec_id": capec_id,
    })
    store.set_capec_chunk(capec_id, chunk_id)
    return True


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

async def sync_kev() -> dict:
    job_id = f"job-{kev.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, kev.SOURCE_ID, "incremental")
    try:
        raw = await kev.fetch_raw()
        entries, meta, findings = kev.normalize(raw)
        merge = store.sync_kev(entries)
        reembedded = 0
        for e in entries:
            if await _reembed_vulnerability(e.cve_id):
                reembedded += 1
        _register_pack(_VULN_PACK_ID, "Vulnerability records (CISA KEV / NVD / EPSS)", "defensive",
                       "vulnerability-management", kev.LICENCE, kev.ATTRIBUTION, "official",
                       [config.KEV_FEED_URL], store.counts()["vulnerability_records"],
                       store.counts()["vulnerability_records"], version=str(meta.get("catalog_version")))
        store.set_sync_state(kev.SOURCE_ID, cursor=str(meta.get("catalog_version")),
                             status="succeeded", records_seen_delta=len(entries))
        store.finish_job(job_id, "succeeded", records_fetched=len(entries),
                         records_added=merge["added"], records_updated=merge["updated"],
                         records_tombstoned=merge["tombstoned"], injection_findings=findings,
                         detail=f"catalog_version={meta.get('catalog_version')}; "
                                f"chunks_reembedded={reembedded}")
        result = {"ok": True, "source": kev.SOURCE_ID, "job_id": job_id, "fetched": len(entries),
                 **merge, "chunks_reembedded": reembedded,
                 "catalog_version": meta.get("catalog_version"), "injection_findings": findings}
        log_config.audit("vuln_sync_kev", {k: v for k, v in result.items() if k != "job_id"})
        return result
    except Exception as e:  # noqa: BLE001 — isolate this source's failure
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        store.set_sync_state(kev.SOURCE_ID, status="failed", error=str(e))
        log_config.error("vuln_sync_kev", str(e), {})
        return {"ok": False, "source": kev.SOURCE_ID, "job_id": job_id, "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# CISA CSAF vendor advisories (enriches CVE rows; never a duplicate NVD row)
# ---------------------------------------------------------------------------

async def sync_cisa_advisories(*, max_advisories: int | None = None,
                              max_runtime_s: float | None = None) -> dict:
    """Production incremental synchronizer over the *entire* CISA CSAF ROLIE
    corpus (no fixed sample size). Resumable: an advisory whose feed
    ``updated`` timestamp matches what was recorded on a prior successful
    fetch is skipped without a network call (``store.cisa_csaf_seen``).
    Bounded concurrency + per-advisory retry/backoff; one bad or malformed
    advisory is isolated and never stops or corrupts the rest of the batch.
    """
    job_id = f"job-{cisa_csaf.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, cisa_csaf.SOURCE_ID, "incremental")
    try:
        index = await cisa_csaf.fetch_feed_index()
    except Exception as e:  # noqa: BLE001
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        log_config.error("vuln_sync_cisa_csaf", str(e), {})
        return {"ok": False, "source": cisa_csaf.SOURCE_ID, "job_id": job_id,
               "error": f"{type(e).__name__}: {e}"}

    budget_s = config.CISA_CSAF_MAX_RUNTIME_S if max_runtime_s is None else max_runtime_s
    deadline = time.monotonic() + budget_s
    candidates = index if max_advisories is None else index[:max_advisories]

    added = updated = unchanged = failed = 0
    findings_written = 0
    injection_findings = 0
    failures: list[str] = []
    enriched_cves: set[str] = set()
    time_budget_hit = False
    sem = asyncio.Semaphore(config.CISA_CSAF_MAX_CONCURRENCY)
    lock = asyncio.Lock()

    async def _process(client: httpx.AsyncClient, entry: dict) -> None:
        nonlocal added, updated, unchanged, failed, findings_written, injection_findings
        advisory_id = entry.get("advisory_id") or entry["content_url"]
        seen = store.get_cisa_csaf_seen(advisory_id)
        if seen and seen.get("status") == "ok" and seen.get("feed_updated") == entry.get("updated"):
            async with lock:
                unchanged += 1
            return
        async with sem:
            try:
                raw = await cisa_csaf.fetch_advisory_with_retry(client, entry["content_url"])
                advisory, per_cve, findings = cisa_csaf.normalize_advisory(raw, entry)
            except Exception as e:  # noqa: BLE001 — isolate; never corrupts the batch
                async with lock:
                    failed += 1
                    failures.append(f"{advisory_id}: {type(e).__name__}: {e}")
                store.record_cisa_csaf_seen(advisory_id, feed_updated=entry.get("updated"),
                                            content_hash=None, status="failed",
                                            error=f"{type(e).__name__}: {e}")
                return
        async with lock:
            status = store.upsert_vendor_advisory(advisory)
            store.replace_vendor_findings(advisory["advisory_id"], per_cve)
            if status == "added":
                added += 1
            elif status == "updated":
                updated += 1
            else:
                unchanged += 1
            findings_written += len(per_cve)
            injection_findings += findings
            enriched_cves.update(f["cve_id"] for f in per_cve if f.get("cve_id"))
            store.record_cisa_csaf_seen(advisory_id, feed_updated=entry.get("updated"),
                                        content_hash=None, status="ok")

    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        attempted = 0
        tasks = []
        for entry in candidates:
            if time.monotonic() >= deadline:
                time_budget_hit = True
                break
            attempted += 1
            tasks.append(asyncio.create_task(_process(client, entry)))
            if len(tasks) >= config.CISA_CSAF_MAX_CONCURRENCY * 4:
                await asyncio.gather(*tasks)
                tasks = []
        if tasks:
            await asyncio.gather(*tasks)

    successful = added + updated
    _register_pack(
        "vendor-advisories-cisa-csaf", "CISA CSAF vendor advisories (IT + OT/ICS)", "defensive",
        "vulnerability-management", cisa_csaf.LICENCE, cisa_csaf.ATTRIBUTION, "official",
        [cisa_csaf.PROVIDER_METADATA_URL], store.vendor_advisory_counts().get("total_advisories", 0), 0,
    )
    store.set_sync_state(cisa_csaf.SOURCE_ID, status="succeeded", records_seen_delta=successful)
    store.finish_job(job_id, "succeeded", records_fetched=attempted, records_added=added,
                     records_updated=updated, injection_findings=injection_findings,
                     detail=f"findings={findings_written}; failed={failed}; unchanged={unchanged}; "
                            f"time_budget_hit={time_budget_hit}")
    result = {
        "ok": True, "source": cisa_csaf.SOURCE_ID, "job_id": job_id,
        "corpus_size": len(index), "attempted": attempted, "successful": successful,
        "added": added, "updated": updated, "unchanged": unchanged, "failed": failed,
        "findings_written": findings_written, "unique_cves_enriched": len(enriched_cves),
        "injection_findings": injection_findings, "failure_sample": failures[:5],
        "time_budget_hit": time_budget_hit, "coverage_pct": round(100.0 * attempted / len(index), 1) if index else 100.0,
    }
    log_config.audit("vuln_sync_cisa_csaf", {k: v for k, v in result.items() if k not in ("job_id", "failure_sample")})
    return result


# ---------------------------------------------------------------------------
# Red Hat CSAF — same production shape as CISA CSAF above (resume/checkpoint,
# bounded concurrency, retry/backoff, per-advisory failure isolation). Only
# RHSA-* (security advisory) documents are in the feed index; RHBA/RHEA are
# filtered out at the source-module level, before this function ever sees them.
# ---------------------------------------------------------------------------

async def sync_redhat_advisories(*, max_advisories: int | None = None,
                                 max_runtime_s: float | None = None) -> dict:
    job_id = f"job-{redhat_csaf.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, redhat_csaf.SOURCE_ID, "incremental")
    try:
        index = await redhat_csaf.fetch_feed_index()
    except Exception as e:  # noqa: BLE001
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        log_config.error("vuln_sync_redhat_csaf", str(e), {})
        return {"ok": False, "source": redhat_csaf.SOURCE_ID, "job_id": job_id,
               "error": f"{type(e).__name__}: {e}"}

    budget_s = config.CISA_CSAF_MAX_RUNTIME_S if max_runtime_s is None else max_runtime_s
    deadline = time.monotonic() + budget_s
    candidates = index if max_advisories is None else index[:max_advisories]

    added = updated = unchanged = failed = 0
    findings_written = 0
    injection_findings = 0
    failures: list[str] = []
    enriched_cves: set[str] = set()
    time_budget_hit = False
    sem = asyncio.Semaphore(config.CISA_CSAF_MAX_CONCURRENCY)
    lock = asyncio.Lock()

    async def _process(client: httpx.AsyncClient, entry: dict) -> None:
        nonlocal added, updated, unchanged, failed, findings_written, injection_findings
        advisory_id = entry.get("advisory_id") or entry["content_url"]
        seen = store.get_redhat_csaf_seen(advisory_id)
        if seen and seen.get("status") == "ok" and seen.get("feed_updated") == entry.get("updated"):
            async with lock:
                unchanged += 1
            return
        async with sem:
            try:
                raw = await cisa_csaf.fetch_advisory_with_retry(client, entry["content_url"])
                advisory, per_cve, findings = redhat_csaf.normalize_advisory(raw, entry)
            except Exception as e:  # noqa: BLE001 — isolate; never corrupts the batch
                async with lock:
                    failed += 1
                    failures.append(f"{advisory_id}: {type(e).__name__}: {e}")
                store.record_redhat_csaf_seen(advisory_id, feed_updated=entry.get("updated"),
                                              content_hash=None, status="failed",
                                              error=f"{type(e).__name__}: {e}")
                return
        async with lock:
            status = store.upsert_vendor_advisory(advisory)
            store.replace_vendor_findings(advisory["advisory_id"], per_cve)
            if status == "added":
                added += 1
            elif status == "updated":
                updated += 1
            else:
                unchanged += 1
            findings_written += len(per_cve)
            injection_findings += findings
            enriched_cves.update(f["cve_id"] for f in per_cve if f.get("cve_id"))
            store.record_redhat_csaf_seen(advisory_id, feed_updated=entry.get("updated"),
                                          content_hash=None, status="ok")

    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        attempted = 0
        tasks = []
        for entry in candidates:
            if time.monotonic() >= deadline:
                time_budget_hit = True
                break
            attempted += 1
            tasks.append(asyncio.create_task(_process(client, entry)))
            if len(tasks) >= config.CISA_CSAF_MAX_CONCURRENCY * 4:
                await asyncio.gather(*tasks)
                tasks = []
        if tasks:
            await asyncio.gather(*tasks)

    successful = added + updated
    _register_pack(
        "vendor-advisories-redhat-csaf", "Red Hat CSAF security advisories (RHSA)", "defensive",
        "vulnerability-management", redhat_csaf.LICENCE, redhat_csaf.ATTRIBUTION, "official",
        [redhat_csaf.PROVIDER_METADATA_URL], store.vendor_advisory_counts().get("total_advisories", 0), 0,
    )
    store.set_sync_state(redhat_csaf.SOURCE_ID, status="succeeded", records_seen_delta=successful)
    store.finish_job(job_id, "succeeded", records_fetched=attempted, records_added=added,
                     records_updated=updated, injection_findings=injection_findings,
                     detail=f"findings={findings_written}; failed={failed}; unchanged={unchanged}; "
                            f"time_budget_hit={time_budget_hit}")
    result = {
        "ok": True, "source": redhat_csaf.SOURCE_ID, "job_id": job_id,
        "corpus_size": len(index), "attempted": attempted, "successful": successful,
        "added": added, "updated": updated, "unchanged": unchanged, "failed": failed,
        "findings_written": findings_written, "unique_cves_enriched": len(enriched_cves),
        "injection_findings": injection_findings, "failure_sample": failures[:5],
        "time_budget_hit": time_budget_hit, "coverage_pct": round(100.0 * attempted / len(index), 1) if index else 100.0,
    }
    log_config.audit("vuln_sync_redhat_csaf", {k: v for k, v in result.items() if k not in ("job_id", "failure_sample")})
    return result


# ---------------------------------------------------------------------------
# MITRE CWE
# ---------------------------------------------------------------------------

async def sync_cwe() -> dict:
    job_id = f"job-{cwe.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, cwe.SOURCE_ID, "full_refresh")
    try:
        raw = await cwe.fetch_raw()
        records, version, findings = cwe.normalize(raw)
        merge = store.sync_cwe_records(records)
        reembedded = 0
        for r in records:
            if await _reembed_cwe(r.cwe_id):
                reembedded += 1
        _register_pack(_CWE_PACK_ID, "MITRE Common Weakness Enumeration (CWE)", "defensive",
                       "vulnerability-management", cwe.LICENCE, cwe.ATTRIBUTION, "official",
                       [config.CWE_CATALOG_URL], len(records), reembedded, version=version)
        store.set_sync_state(cwe.SOURCE_ID, cursor=version, status="succeeded",
                             records_seen_delta=len(records))
        store.finish_job(job_id, "succeeded", records_fetched=len(records),
                         records_added=merge["added"], records_updated=merge["updated"],
                         records_skipped_unchanged=merge["unchanged"], injection_findings=findings,
                         detail=f"catalog_version={version}; chunks_reembedded={reembedded}")
        result = {"ok": True, "source": cwe.SOURCE_ID, "job_id": job_id, "fetched": len(records),
                 **merge, "chunks_reembedded": reembedded, "catalog_version": version,
                 "injection_findings": findings}
        log_config.audit("vuln_sync_cwe", {k: v for k, v in result.items() if k != "job_id"})
        return result
    except Exception as e:  # noqa: BLE001
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        store.set_sync_state(cwe.SOURCE_ID, status="failed", error=str(e))
        log_config.error("vuln_sync_cwe", str(e), {})
        return {"ok": False, "source": cwe.SOURCE_ID, "job_id": job_id, "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# MITRE CAPEC
# ---------------------------------------------------------------------------

async def sync_capec() -> dict:
    job_id = f"job-{capec.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, capec.SOURCE_ID, "full_refresh")
    try:
        raw = await capec.fetch_raw()
        records, version, findings = capec.normalize(raw)
        merge = store.sync_capec_records(records)
        reembedded = 0
        for r in records:
            if await _reembed_capec(r.capec_id):
                reembedded += 1
        _register_pack(_CAPEC_PACK_ID, "MITRE Common Attack Pattern Enumeration and Classification (CAPEC)",
                       "offensive", "vulnerability-management", capec.LICENCE, capec.ATTRIBUTION,
                       "official", [config.CAPEC_CATALOG_URL], len(records), reembedded, version=version)
        store.set_sync_state(capec.SOURCE_ID, cursor=version, status="succeeded",
                             records_seen_delta=len(records))
        store.finish_job(job_id, "succeeded", records_fetched=len(records),
                         records_added=merge["added"], records_updated=merge["updated"],
                         records_skipped_unchanged=merge["unchanged"], injection_findings=findings,
                         detail=f"catalog_version={version}; chunks_reembedded={reembedded}")
        result = {"ok": True, "source": capec.SOURCE_ID, "job_id": job_id, "fetched": len(records),
                 **merge, "chunks_reembedded": reembedded, "catalog_version": version,
                 "injection_findings": findings}
        log_config.audit("vuln_sync_capec", {k: v for k, v in result.items() if k != "job_id"})
        return result
    except Exception as e:  # noqa: BLE001
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        store.set_sync_state(capec.SOURCE_ID, status="failed", error=str(e))
        log_config.error("vuln_sync_capec", str(e), {})
        return {"ok": False, "source": capec.SOURCE_ID, "job_id": job_id, "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# FIRST EPSS — SQL merge for all rows, but chunk re-embed bounded to CVEs that
# already have KEV or NVD context (a pure EPSS-only stub for a CVE nobody has
# enriched yet is not useful retrieval text, and embedding all ~250k rows on
# every daily run is the storage/runtime blocker called out in the plan).
# ---------------------------------------------------------------------------

async def sync_epss(*, reembed_limit: int | None = None) -> dict:
    job_id = f"job-{epss.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, epss.SOURCE_ID, "incremental")
    try:
        raw = await epss.fetch_raw()
        entries, score_date = epss.normalize(raw)
        merge = store.sync_epss_batch(entries, epsilon=config.EPSS_SCORE_EPSILON)

        candidate_ids = _cves_with_context({e.cve_id for e in entries})
        if reembed_limit is not None:
            candidate_ids = candidate_ids[:reembed_limit]
        reembedded = 0
        for cve_id in candidate_ids:
            if await _reembed_vulnerability(cve_id):
                reembedded += 1

        _register_pack(_VULN_PACK_ID, "Vulnerability records (CISA KEV / NVD / EPSS)", "defensive",
                       "vulnerability-management", epss.LICENCE, epss.ATTRIBUTION, "official",
                       [config.EPSS_BULK_URL], store.counts()["vulnerability_records"],
                       store.counts()["vulnerability_records"], version=score_date)
        store.set_sync_state(epss.SOURCE_ID, cursor=score_date, status="succeeded",
                             records_seen_delta=len(entries))
        store.finish_job(job_id, "succeeded", records_fetched=len(entries),
                         records_added=merge["added"], records_updated=merge["updated"],
                         records_skipped_unchanged=merge["unchanged"],
                         detail=f"score_date={score_date}; reembed_candidates={len(candidate_ids)}; "
                                f"chunks_reembedded={reembedded}")
        result = {"ok": True, "source": epss.SOURCE_ID, "job_id": job_id, "fetched": len(entries),
                 **merge, "reembed_candidates": len(candidate_ids), "chunks_reembedded": reembedded,
                 "score_date": score_date}
        log_config.audit("vuln_sync_epss", {k: v for k, v in result.items() if k != "job_id"})
        return result
    except Exception as e:  # noqa: BLE001
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        store.set_sync_state(epss.SOURCE_ID, status="failed", error=str(e))
        log_config.error("vuln_sync_epss", str(e), {})
        return {"ok": False, "source": epss.SOURCE_ID, "job_id": job_id, "error": f"{type(e).__name__}: {e}"}


def _cves_with_context(cve_ids: set[str]) -> list[str]:
    """Of the given ids, which already have KEV or NVD-sourced context (i.e.
    are worth spending an embed on right now)?"""
    ids = list(cve_ids)
    out: list[str] = []
    batch_size = 500  # stay well under SQLite's default ~999-parameter limit
    con = kb_store.conn()
    try:
        for i in range(0, len(ids), batch_size):
            batch = ids[i:i + batch_size]
            placeholders = ",".join("?" * len(batch))
            rows = con.execute(
                f"SELECT cve_id FROM vulnerability_records WHERE cve_id IN ({placeholders}) "
                "AND (kev_listed = 1 OR description IS NOT NULL)",
                batch,
            ).fetchall()
            out.extend(r["cve_id"] for r in rows)
    finally:
        con.close()
    return out


# ---------------------------------------------------------------------------
# NIST NVD — windowed incremental sync + KEV-enrichment (exact-id) + backfill
# ---------------------------------------------------------------------------

async def _sync_nvd_window(start: datetime, end: datetime, mode: str, *, embed: bool = True) -> dict:
    """``embed=False`` writes full structured data (description, CVSS, CWE,
    CPE, references) to SQL for every CVE in range but skips the Chroma
    re-embed step — used for large historical backfills, where embedding
    every one of ~360k CVE rows would be storage waste for records reachable
    by exact CVE-id lookup anyway. Incremental/day-to-day syncs keep
    ``embed=True`` so recently-changed CVEs stay semantically searchable."""
    job_id = f"job-{nvd.SOURCE_ID}-{uuid.uuid4().hex[:8]}"
    store.start_job(job_id, nvd.SOURCE_ID, mode, window_start=start.isoformat(), window_end=end.isoformat())
    try:
        added = updated = fetched_total = findings_total = reembedded = 0
        for w_start, w_end in _chunk_windows(start, end, config.NVD_WINDOW_DAYS):
            raw_cves = await nvd.fetch_window(_nvd_dt(w_start), _nvd_dt(w_end))
            findings = [0]
            entries = [e for e in (nvd.normalize_cve_obj(c, findings) for c in raw_cves) if e]
            findings_total += findings[0]
            fetched_total += len(entries)
            merge = store.sync_nvd_batch(entries)
            added += merge["added"]
            updated += merge["updated"]
            if embed:
                for e in entries:
                    if await _reembed_vulnerability(e.cve_id):
                        reembedded += 1
            store.set_sync_state(nvd.SOURCE_ID, cursor=w_end.isoformat(), status="running",
                                 records_seen_delta=len(entries))
        _register_pack(_VULN_PACK_ID, "Vulnerability records (CISA KEV / NVD / EPSS)", "defensive",
                       "vulnerability-management", nvd.LICENCE, nvd.ATTRIBUTION, "official",
                       [config.NVD_API_BASE_URL], store.counts()["vulnerability_records"],
                       store.counts()["vulnerability_records"], version=end.date().isoformat())
        store.set_sync_state(nvd.SOURCE_ID, status="succeeded")
        store.finish_job(job_id, "succeeded", records_fetched=fetched_total, records_added=added,
                         records_updated=updated, injection_findings=findings_total,
                         detail=f"window {start.date()}..{end.date()}; chunks_reembedded={reembedded}")
        result = {"ok": True, "source": nvd.SOURCE_ID, "job_id": job_id, "fetched": fetched_total,
                 "added": added, "updated": updated, "chunks_reembedded": reembedded,
                 "injection_findings": findings_total,
                 "window": [start.isoformat(), end.isoformat()]}
        log_config.audit("vuln_sync_nvd", {k: v for k, v in result.items() if k not in ("job_id", "window")})
        return result
    except Exception as e:  # noqa: BLE001
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        store.set_sync_state(nvd.SOURCE_ID, status="failed", error=str(e))
        log_config.error("vuln_sync_nvd", str(e), {})
        return {"ok": False, "source": nvd.SOURCE_ID, "job_id": job_id, "error": f"{type(e).__name__}: {e}"}


async def sync_nvd_incremental(days: int = 7) -> dict:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return await _sync_nvd_window(start, end, "incremental")


async def sync_nvd_backfill(start: datetime, end: datetime, *, embed: bool = False) -> dict:
    """Explicit, operator-only. Never called by app startup or the incremental
    sync path. ``embed`` defaults False here (unlike the incremental path)
    because a backfill spans a wide date range and can touch a very large
    number of CVEs — see ``_sync_nvd_window``'s docstring."""
    return await _sync_nvd_window(start, end, "backfill", embed=embed)


async def enrich_kev_from_nvd(batch_size: int = 20) -> dict:
    """Exact-CVE-id NVD lookups for every currently KEV-listed CVE — the
    'enrichment/backfill of every currently KEV-listed CVE' requirement.

    Writes to the store every ``batch_size`` results (not once at the end) —
    this is what makes an interrupted run resumable: a restart re-queries
    ``needs_nvd_backfill=1`` and picks up only the CVEs still missing NVD
    data, rather than losing all progress and starting over. One request per
    id, paced via the shared NVD pacer.

    A single lookup failure never aborts the batch, but it also must not loop
    forever on a CVE that legitimately has no NVD record:
      - NVD responding with zero results (a valid response, just empty) is a
        definitive "not in NVD" answer — marked unavailable immediately.
      - An HTTP 404 is likewise definitive — marked unavailable immediately.
      - Any other error (timeout, transient 5xx, connection drop) increments
        a per-CVE attempt counter that survives across resumes; once it
        crosses ``config.NVD_MAX_BACKFILL_ATTEMPTS`` the CVE is marked
        unavailable with the last error as the reason. Below that cap it
        stays pending and will be retried on the next run.
    """
    job_id = f"job-{nvd.SOURCE_ID}-kev-enrich-{uuid.uuid4().hex[:8]}"
    pending = store.kev_ids_needing_nvd_backfill()
    total_kev = len(store.kev_listed_cve_ids())
    store.start_job(job_id, nvd.SOURCE_ID, "kev_enrichment")
    added = updated = fetched_total = findings_total = reembedded = 0
    marked_unavailable = 0
    pacer = nvd.new_pacer()
    try:
        batch: list = []

        async def _flush():
            nonlocal added, updated, fetched_total, reembedded, batch
            if not batch:
                return
            merge = store.sync_nvd_batch(batch)
            added += merge["added"]
            updated += merge["updated"]
            fetched_total += len(batch)
            for e in batch:
                if await _reembed_vulnerability(e.cve_id):
                    reembedded += 1
            store.set_sync_state(nvd.SOURCE_ID, status="running", records_seen_delta=len(batch))
            batch = []

        async with httpx.AsyncClient() as client:
            for cve_id in pending:
                try:
                    data = await nvd._get_with_retry(client, pacer, {"cveId": cve_id})
                except httpx.HTTPStatusError as e:
                    if e.response is not None and e.response.status_code == 404:
                        store.mark_nvd_unavailable(cve_id, "not_found_in_nvd (HTTP 404)")
                        marked_unavailable += 1
                    else:
                        attempts = store.bump_nvd_backfill_attempt(cve_id)
                        if attempts >= config.NVD_MAX_BACKFILL_ATTEMPTS:
                            store.mark_nvd_unavailable(
                                cve_id, f"lookup_failed_after_{attempts}_attempts: {type(e).__name__}: {e}")
                            marked_unavailable += 1
                    continue  # isolate a single lookup failure — never abort the batch
                except Exception as e:  # noqa: BLE001 — network/timeout/etc, transient
                    attempts = store.bump_nvd_backfill_attempt(cve_id)
                    if attempts >= config.NVD_MAX_BACKFILL_ATTEMPTS:
                        store.mark_nvd_unavailable(
                            cve_id, f"lookup_failed_after_{attempts}_attempts: {type(e).__name__}: {e}")
                        marked_unavailable += 1
                    continue
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    store.mark_nvd_unavailable(cve_id, "nvd_returned_zero_results")
                    marked_unavailable += 1
                    continue
                findings = [0]
                e = nvd.normalize_cve_obj(vulns[0]["cve"], findings)
                findings_total += findings[0]
                if e:
                    batch.append(e)
                if len(batch) >= batch_size:
                    await _flush()
            await _flush()

        remaining = len(store.kev_ids_needing_nvd_backfill())
        store.finish_job(job_id, "succeeded", records_fetched=fetched_total,
                         records_added=added, records_updated=updated,
                         injection_findings=findings_total,
                         detail=f"kev_total={total_kev}; pending_at_start={len(pending)}; "
                                f"remaining_after={remaining}; chunks_reembedded={reembedded}; "
                                f"marked_unavailable={marked_unavailable}")
        result = {"ok": True, "source": nvd.SOURCE_ID, "job_id": job_id, "kev_total": total_kev,
                 "pending_at_start": len(pending), "fetched": fetched_total, "added": added,
                 "updated": updated, "remaining_after": remaining, "chunks_reembedded": reembedded,
                 "marked_unavailable": marked_unavailable, "injection_findings": findings_total}
        log_config.audit("vuln_enrich_kev_from_nvd", {k: v for k, v in result.items() if k != "job_id"})
        return result
    except Exception as e:  # noqa: BLE001
        remaining = len(store.kev_ids_needing_nvd_backfill())
        store.finish_job(job_id, "failed", error=f"{type(e).__name__}: {e}",
                         records_fetched=fetched_total, records_added=added, records_updated=updated,
                         detail=f"partial progress preserved; remaining_after={remaining}; "
                                f"marked_unavailable={marked_unavailable}")
        log_config.error("vuln_enrich_kev_from_nvd", str(e), {"fetched_before_failure": fetched_total})
        return {"ok": False, "source": nvd.SOURCE_ID, "job_id": job_id, "error": f"{type(e).__name__}: {e}",
                "fetched_before_failure": fetched_total, "remaining_after": remaining,
                "marked_unavailable": marked_unavailable}


# ---------------------------------------------------------------------------
# GitHub Security Advisory Database (reviewed advisories) — one sparse clone,
# then every advisory file is a local read; no per-advisory network cost, so
# a single run covers the full reviewed corpus.
# ---------------------------------------------------------------------------

async def sync_ghsa(*, max_advisories: int | None = None) -> dict:
    t0 = time.time()
    try:
        clone_dir, commit_sha = ghsa_src.clone_reviewed_advisories()
    except Exception as e:  # noqa: BLE001
        osv_store.set_sync_state(ghsa_src.SOURCE_ID, status="failed", error=str(e))
        log_config.error("vuln_sync_ghsa", str(e), {})
        return {"ok": False, "source": ghsa_src.SOURCE_ID, "error": f"{type(e).__name__}: {e}"}

    added = updated = unchanged = failed = withdrawn_count = injection_findings = 0
    failures: list[str] = []
    attempted = 0
    try:
        files = list(ghsa_src.iter_advisory_files(clone_dir))
        if max_advisories is not None:
            files = files[:max_advisories]
        for path in files:
            attempted += 1
            raw = ghsa_src.load_advisory(path)
            if raw is None:
                failed += 1
                failures.append(f"{path.name}: unreadable or malformed JSON")
                continue
            findings = [0]
            try:
                rec = parse_osv_record(raw, findings_counter=findings)
            except Exception as e:  # noqa: BLE001 — isolate; never stop the batch
                failed += 1
                failures.append(f"{path.name}: {type(e).__name__}: {e}")
                continue
            if rec is None:
                failed += 1
                failures.append(f"{path.name}: no usable advisory id")
                continue
            injection_findings += findings[0]
            status = osv_store.upsert_ghsa(rec, source_url=ghsa_src.source_url_for(rec.record_id))
            if status == "added":
                added += 1
            elif status == "updated":
                updated += 1
            else:
                unchanged += 1
            if rec.withdrawn:
                withdrawn_count += 1
    finally:
        ghsa_src.cleanup(clone_dir)

    successful = added + updated
    counts = osv_store.counts()
    _register_pack("vulnerability-ghsa", "GitHub Security Advisory Database (reviewed)", "defensive",
                   "vulnerability-management", ghsa_src.LICENCE, ghsa_src.ATTRIBUTION, "official",
                   [ghsa_src.REPO_URL], counts.get("ghsa_total", 0), 0, version=commit_sha[:12])
    osv_store.set_sync_state(ghsa_src.SOURCE_ID, cursor=commit_sha, status="succeeded",
                             records_seen_delta=successful)
    result = {"ok": True, "source": ghsa_src.SOURCE_ID, "commit": commit_sha,
             "attempted": attempted, "successful": successful, "added": added, "updated": updated,
             "unchanged": unchanged, "failed": failed, "withdrawn": withdrawn_count,
             "injection_findings": injection_findings, "failure_sample": failures[:5],
             "elapsed_s": round(time.time() - t0, 1)}
    log_config.audit("vuln_sync_ghsa", {k: v for k, v in result.items() if k != "failure_sample"})
    return result


# ---------------------------------------------------------------------------
# OSV.dev — per-ecosystem bulk export. Records whose own id is GHSA-shaped
# are skipped (already covered by sync_ghsa; storing them again under osv_*
# would be a conflicting duplicate of the same real-world advisory).
# ---------------------------------------------------------------------------

async def sync_osv_ecosystem(ecosystem: str, *, max_records: int | None = None) -> dict:
    t0 = time.time()
    workroot = config.KNOWLEDGE_CONNECTOR_WORKDIR
    from pathlib import Path
    Path(workroot).mkdir(parents=True, exist_ok=True)
    try:
        zip_path = await osv_src.download_ecosystem_zip(ecosystem, Path(workroot))
    except Exception as e:  # noqa: BLE001
        osv_store.set_sync_state(f"osv-{ecosystem}", status="failed", error=str(e))
        log_config.error("vuln_sync_osv", str(e), {"ecosystem": ecosystem})
        return {"ok": False, "source": f"osv-{ecosystem}", "error": f"{type(e).__name__}: {e}"}

    added = updated = unchanged = failed = skipped_ghsa_dupe = withdrawn_count = injection_findings = 0
    failures: list[str] = []
    attempted = 0
    try:
        for raw in osv_src.iter_records_from_zip(zip_path):
            if max_records is not None and attempted >= max_records:
                break
            attempted += 1
            rid = raw.get("id") if isinstance(raw, dict) else None
            if isinstance(rid, str) and rid.upper().startswith("GHSA-"):
                skipped_ghsa_dupe += 1
                continue
            findings = [0]
            try:
                rec = parse_osv_record(raw, findings_counter=findings)
            except Exception as e:  # noqa: BLE001
                failed += 1
                failures.append(f"{rid}: {type(e).__name__}: {e}")
                continue
            if rec is None:
                failed += 1
                failures.append("record with no usable id")
                continue
            injection_findings += findings[0]
            status = osv_store.upsert_osv(rec, ecosystem_source=ecosystem,
                                          source_url=f"https://osv.dev/vulnerability/{rec.record_id}")
            if status == "added":
                added += 1
            elif status == "updated":
                updated += 1
            else:
                unchanged += 1
            if rec.withdrawn:
                withdrawn_count += 1
    finally:
        osv_src.cleanup(zip_path)

    successful = added + updated
    source_id = f"osv-{ecosystem}"
    osv_store.set_sync_state(source_id, status="succeeded", records_seen_delta=successful)
    result = {"ok": True, "source": source_id, "ecosystem": ecosystem,
             "attempted": attempted, "successful": successful, "added": added, "updated": updated,
             "unchanged": unchanged, "failed": failed, "skipped_ghsa_duplicate": skipped_ghsa_dupe,
             "withdrawn": withdrawn_count, "injection_findings": injection_findings,
             "failure_sample": failures[:5], "elapsed_s": round(time.time() - t0, 1)}
    log_config.audit("vuln_sync_osv", {k: v for k, v in result.items() if k != "failure_sample"})
    return result


async def sync_osv_all(ecosystems: list[str] | None = None) -> dict:
    ecos = ecosystems or osv_src.ECOSYSTEMS
    results = {}
    for eco in ecos:
        results[eco] = await sync_osv_ecosystem(eco)
    counts = osv_store.counts()
    _register_pack("vulnerability-osv", "OSV.dev structured vulnerability records", "defensive",
                   "vulnerability-management", osv_src.LICENCE, osv_src.ATTRIBUTION, "official",
                   [osv_src.BASE_URL], counts.get("osv_total", 0), 0)
    return {"ok": all(r.get("ok") for r in results.values()), "by_ecosystem": results,
           "total_osv_records": counts.get("osv_total", 0)}
