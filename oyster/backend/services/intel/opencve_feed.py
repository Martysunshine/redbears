"""Security Intel "Latest intelligence" feed: a small, deduplicated, disk-cached
mirror of recent OpenCVE catalog activity (services/integrations/opencve.py),
refreshed manually (and, if deliberately enabled, on a timer — see
config.OPENCVE_SCHEDULED_REFRESH_ENABLED).

Design constraints from the brief, and how each is met:
  - "Bounded pagination, caching, request timeouts, rate-limit handling and
    deduplication by CVE ID." -> fetch_latest() pulls a small, bounded number
    of pages (FETCH_PAGES) through the adapter (which already enforces a
    request timeout and surfaces 429s as IntegrationError), and _merge()
    dedupes by cve_id, keeping the newest `updated_at` for each.
  - "Keep cached data outside Git." -> the cache file lives under
    config.OPENCVE_CACHE_PATH, which defaults to $REDBEARS_ASSETS/data (never
    inside the repo).
  - "A failed refresh must retain cached results and show that they may be
    stale." -> refresh() never clears the cache on failure; it records
    last_error and last_attempt_at, and get_feed()'s `stale` flag is true
    whenever the most recent attempt did not succeed.
  - "Do not confuse: high severity / known exploitation / applicability to a
    supplied application / successful reproduction in our lab." -> this module
    only ever carries OpenCVE's own fields (plus the newly_published /
    recently_modified classification derived from OpenCVE's created_at /
    updated_at — NOT NVD's publishedDate/lastModifiedDate, which the v2 schema
    does not expose; see services/integrations/opencve.py). It never computes
    or asserts exploitation/applicability/reproduction — those only ever come
    from the KEV/CSAF knowledge-base sources or an actual scenario run.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import config
from services.integrations.base import IntegrationError, IntegrationStatus
from services.integrations.opencve import adapter as opencve_adapter

FETCH_PAGES = 3  # bounded: at most FETCH_PAGES * page_size CVEs fetched per refresh
_lock = threading.Lock()


def _cache_path() -> Path:
    return Path(config.OPENCVE_CACHE_PATH)


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


def _classify(entry: dict, now: float) -> dict:
    """Attach newly_published / recently_modified flags from OpenCVE's own
    created_at/updated_at timestamps (ISO 8601). Never guesses a date that
    isn't present."""
    out = dict(entry)
    created = entry.get("created_at")
    updated = entry.get("updated_at")

    def _age_s(iso: str | None) -> float | None:
        if not iso:
            return None
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            return now - dt.timestamp()
        except (ValueError, TypeError):
            return None

    created_age = _age_s(created)
    updated_age = _age_s(updated)
    out["newly_published"] = created_age is not None and created_age <= config.OPENCVE_RECENT_WINDOW_S
    out["recently_modified"] = (
        updated_age is not None and created != updated
        and updated_age <= config.OPENCVE_RECENT_WINDOW_S
    )
    return out


def _merge(cache: dict, fetched: list[dict]) -> dict:
    entries = dict(cache.get("entries", {}))
    for raw in fetched:
        cve_id = raw.get("cve_id")
        if not cve_id:
            continue  # never invent an id for a record that doesn't have one
        existing = entries.get(cve_id)
        if existing is None or raw.get("updated_at", "") >= existing.get("updated_at", ""):
            entries[cve_id] = raw
    # Bounded cache size: keep the most recently updated N entries.
    ordered = sorted(entries.values(), key=lambda e: e.get("updated_at") or "", reverse=True)
    trimmed = ordered[: config.OPENCVE_CACHE_MAX_ENTRIES]
    cache = dict(cache)
    cache["entries"] = {e["cve_id"]: e for e in trimmed}
    return cache


async def refresh(*, vendor: str | None = None, product: str | None = None) -> dict:
    """Manual (or scheduled) refresh. Always returns the resulting feed state
    — on failure the existing cache is kept untouched apart from last_error/
    last_attempt_at, per the brief's "retain cached results, show stale"."""
    with _lock:
        cache = _load()
    now = time.time()
    fetched: list[dict] = []
    error: str | None = None
    try:
        page = 1
        while page <= FETCH_PAGES:
            data = await opencve_adapter.list_cves(
                vendor=vendor, product=product, page=page, page_size=config.OPENCVE_PAGE_SIZE)
            results = data.get("results", [])
            fetched.extend(results)
            if not data.get("next") or not results:
                break
            page += 1
    except IntegrationError as exc:
        error = exc.detail
        if exc.status == IntegrationStatus.NOT_CONFIGURED:
            error = "OpenCVE is not configured — set OPENCVE_API_TOKEN to enable the live feed."

    with _lock:
        cache = _load()  # re-read: another refresh may have run concurrently
        if fetched:
            cache = _merge(cache, fetched)
        cache["last_attempt_at"] = now
        if error is None:
            cache["last_synced_at"] = now
            cache["last_error"] = None
        else:
            cache["last_error"] = error
        _save(cache)
    return get_feed()


def get_feed() -> dict:
    """Read-only view: cached entries (classified), sync status, staleness.
    Never makes a network call — refresh() does that."""
    cache = _load()
    now = time.time()
    entries = [_classify(e, now) for e in cache.get("entries", {}).values()]
    entries.sort(key=lambda e: e.get("updated_at") or "", reverse=True)
    last_synced_at = cache.get("last_synced_at")
    last_attempt_at = cache.get("last_attempt_at")
    stale = bool(last_attempt_at and last_attempt_at != last_synced_at and cache.get("last_error"))
    return {
        "source": "opencve",
        "entries": entries,
        "last_synced_at": last_synced_at,
        "last_attempt_at": last_attempt_at,
        "last_error": cache.get("last_error"),
        "stale": stale,
        "configured": opencve_adapter.is_configured(),
    }
