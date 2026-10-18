"""Vulnerability Knowledge API — CISA KEV, NVD CVE, FIRST EPSS, MITRE CWE,
MITRE CAPEC, merged by CVE/CWE/CAPEC id. Admin-only, same tier as
``routers/knowledge.py`` (reconfigures one shared knowledge base for
everyone). Sync endpoints run bounded/incremental work only — full historical
NVD backfill is intentionally NOT exposed here; it is an explicit operator CLI
command (``services/knowledge/vulnerabilities/cli.py``), never an HTTP route
someone could hit by accident.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from models.schemas import VulnSearchRequest
from services.knowledge.vulnerabilities import retrieval, store, sync

router = APIRouter(prefix="/knowledge/vuln", tags=["vulnerabilities"])


@router.get("/sources")
async def list_sources():
    sources = ["cisa-kev", "mitre-cwe", "mitre-capec", "first-epss", "nvd-cve"]
    return {"sources": [
        {"source_id": s, "sync_state": store.get_sync_state(s),
         "recent_jobs": store.list_jobs(s, limit=5)}
        for s in sources
    ], "counts": store.counts()}


@router.post("/sources/{source_id}/sync")
async def sync_source(
    source_id: str,
    # BOUNDED, because the docstring above promises this route cannot start a
    # full historical import and nothing was enforcing it. `days` was a bare
    # scalar, so FastAPI bound it as an unvalidated query param with no ceiling:
    # `?days=100000` reached sync_nvd_incremental and would pull NVD's entire
    # history — measured at roughly 4-8 GB and hours of CPU, onto a VPS that has
    # repeatedly sat above 85% disk. A disk-full event there corrupts the live
    # database, so this is a data-loss guard, not a politeness limit.
    #
    # The unbounded path still exists where it belongs: cli.py's backfill, which
    # requires explicit --start/--end typed by a human on the box.
    days: int = Query(7, ge=1, le=30, description="Look back this many days (max 30)."),
):
    if source_id == "cisa-kev":
        result = await sync.sync_kev()
    elif source_id == "mitre-cwe":
        result = await sync.sync_cwe()
    elif source_id == "mitre-capec":
        result = await sync.sync_capec()
    elif source_id == "first-epss":
        result = await sync.sync_epss()
    elif source_id == "nvd-cve":
        result = await sync.sync_nvd_incremental(days=days)
    else:
        raise HTTPException(status_code=404, detail=f"Unknown source '{source_id}'")
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("error", "sync failed"))
    return result


@router.post("/sources/nvd-cve/enrich-kev")
async def enrich_kev():
    result = await sync.enrich_kev_from_nvd()
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail=result.get("error", "enrichment failed"))
    return result


@router.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    rec = retrieval.get_cve(cve_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"'{cve_id}' not found in the local knowledge base")
    return rec


@router.get("/cwe/{cwe_id}")
async def get_cwe(cwe_id: str):
    rec = retrieval.get_cwe(cwe_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"'{cwe_id}' not found in the local knowledge base")
    return rec


@router.get("/capec/{capec_id}")
async def get_capec(capec_id: str):
    rec = retrieval.get_capec(capec_id)
    if rec is None:
        raise HTTPException(status_code=404, detail=f"'{capec_id}' not found in the local knowledge base")
    return rec


@router.get("/cwe/{cwe_id}/related-capec")
async def cwe_related_capec(cwe_id: str):
    return {"cwe_id": cwe_id, "related_capec": retrieval.capecs_related_to_cwe(cwe_id)}


@router.post("/search")
async def search(request: VulnSearchRequest):
    return await retrieval.search(request.query, top_k=request.top_k, kev_only=request.kev_only,
                                  min_cvss=request.min_cvss, min_epss=request.min_epss,
                                  since=request.since)
