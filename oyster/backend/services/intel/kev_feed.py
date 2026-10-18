"""Security Intel "Latest intelligence" feed — CISA KEV fallback.

OpenCVE's hosted API requires an organisation token (verified live,
2026-10-18: `GET https://app.opencve.io/api/v2/cves` with no bearer returns
`401 {"error":{"code":"not_authenticated","message":"Authentication
credentials were not provided."}}` — see services/integrations/opencve.py).
Rather than self-host OpenCVE, this module mirrors the same feed contract
(`refresh()`/`get_feed()`, same shape as services/intel/opencve_feed.py) using
the official public CISA KEV catalog, which needs no credential:

    GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Verified live (2026-10-18): 200, JSON, top-level
{title, catalogVersion, dateReleased, count, vulnerabilities:[...]}; each
vulnerability has {cveID, vendorProject, product, vulnerabilityName,
dateAdded, shortDescription, requiredAction, dueDate,
knownRansomwareCampaignUse, forensicTriage, notes, cwes}. This is the exact
schema services/knowledge/vulnerabilities/sources/kev.py already ingests for
the knowledge base — this module is a separate, independent cache for the
Security Intel UI feed, not a change to that pipeline.

KEV is "known exploited vulnerabilities," not every CVE, and carries no CVSS
score — `get_feed()` never attaches or invents a severity for these entries.
routers/security_intel_feed.py selects this module automatically whenever
OpenCVE has no token configured; the router/UI label every entry "CISA KEV"
so the two sources are never visually confused.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import httpx

import config

_lock = threading.Lock()


def _cache_path() -> Path:
    return Path(config.KEV_INTEL_CACHE_PATH)


def _load() -> dict:
    p = _cache_path()
    if not p.exists():
        return {"entries": {}, "last_synced_at": None, "last_attempt_at": None, "last_error": None}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {"entries": {}, "last_synced_at": None, "last_attempt_at": None, "last_error": None}


def _save(data: dict) -> None:
    p = _cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=1))


def _normalize(raw: dict) -> dict | None:
    cve_id = raw.get("cveID")
    if not cve_id:
        return None  # never invent an id for a record that doesn't have one
    return {
        "cve_id": cve_id,
        "vendor_project": raw.get("vendorProject"),
        "product": raw.get("product"),
        "vulnerability_name": raw.get("vulnerabilityName"),
        "date_added": raw.get("dateAdded"),
        "short_description": raw.get("shortDescription"),
        "required_action": raw.get("requiredAction"),
        "due_date": raw.get("dueDate"),
        # Deliberately no CVSS/severity field — KEV doesn't carry one and
        # this module never computes or guesses one.
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


async def _fetch_live() -> list[dict]:
    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        resp = await client.get(config.KEV_FEED_URL)
    if resp.status_code != 200:
        raise RuntimeError(f"CISA KEV feed returned HTTP {resp.status_code}")
    data = resp.json()
    out = []
    for v in data.get("vulnerabilities", []):
        norm = _normalize(v)
        if norm:
            out.append(norm)
    return out


def _merge(cache: dict, fetched: list[dict]) -> dict:
    entries = dict(cache.get("entries", {}))
    for raw in fetched:
        entries[raw["cve_id"]] = raw  # the catalog is authoritative; always take the fetched record
    ordered = sorted(entries.values(), key=lambda e: e.get("date_added") or "", reverse=True)
    trimmed = ordered[: config.OPENCVE_CACHE_MAX_ENTRIES]
    cache = dict(cache)
    cache["entries"] = {e["cve_id"]: e for e in trimmed}
    return cache


async def refresh(*, vendor: str | None = None, product: str | None = None) -> dict:
    """Manual (or scheduled) refresh of the whole KEV catalog, then filtered
    client-side by vendor/product if given (the feed is one JSON file — there
    is no server-side filter to ask for). A failed fetch keeps the existing
    cache and reports the error rather than clearing it, same contract as
    opencve_feed.refresh()."""
    now = time.time()
    fetched: list[dict] = []
    error: str | None = None
    try:
        fetched = await _fetch_live()
    except (httpx.HTTPError, RuntimeError, ValueError) as exc:
        error = f"CISA KEV feed fetch failed: {type(exc).__name__}: {exc}"[:500]

    with _lock:
        cache = _load()
        if fetched:
            cache = _merge(cache, fetched)
        cache["last_attempt_at"] = now
        if error is None:
            cache["last_synced_at"] = now
            cache["last_error"] = None
        else:
            cache["last_error"] = error
        _save(cache)
    return get_feed(vendor=vendor, product=product)


def get_feed(*, vendor: str | None = None, product: str | None = None) -> dict:
    """Read-only view: cached entries, sync status, staleness. Never makes a
    network call — refresh() does that. KEV has no per-vendor/product server
    endpoint, so a filter here is a simple case-insensitive substring match
    over the already-cached catalog."""
    cache = _load()
    entries = list(cache.get("entries", {}).values())
    if vendor:
        entries = [e for e in entries if vendor.lower() in (e.get("vendor_project") or "").lower()]
    if product:
        entries = [e for e in entries if product.lower() in (e.get("product") or "").lower()]
    entries.sort(key=lambda e: e.get("date_added") or "", reverse=True)
    last_synced_at = cache.get("last_synced_at")
    last_attempt_at = cache.get("last_attempt_at")
    stale = bool(last_attempt_at and last_attempt_at != last_synced_at and cache.get("last_error"))
    return {
        "source": "cisa_kev",
        "entries": entries,
        "last_synced_at": last_synced_at,
        "last_attempt_at": last_attempt_at,
        "last_error": cache.get("last_error"),
        "stale": stale,
        "configured": True,  # no credential needed — always "configured"
    }
