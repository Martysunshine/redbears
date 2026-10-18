"""Security Intel "Latest intelligence" feed. OpenCVE's hosted API requires an
organisation token (verified live: an unauthenticated GET returns 401). When
no OPENCVE_API_TOKEN is configured, this falls back to the public CISA KEV
catalog (services/intel/kev_feed.py) rather than installing or self-hosting
OpenCVE — the response's `source` field ("opencve" | "cisa_kev") tells the UI
which one it's looking at, so the two are never visually confused. Manual
refresh only by default (brief: "Start with manual refresh"); scheduled
refresh is a separate config flag (config.OPENCVE_SCHEDULED_REFRESH_ENABLED),
off by default, and is wired up in app.py's startup hook, not here.
"""
from __future__ import annotations

from fastapi import APIRouter

from services.integrations.opencve import adapter as opencve_adapter
from services.intel import kev_feed, opencve_feed

router = APIRouter(prefix="/security-intel/feed", tags=["security-intel-feed"])


def _active():
    return opencve_feed if opencve_adapter.is_configured() else kev_feed


@router.get("")
async def get_feed():
    """Never makes a network call — serves whatever is cached, with a `stale`
    flag if the most recent refresh attempt failed."""
    return _active().get_feed()


@router.post("/refresh")
async def refresh_feed(vendor: str | None = None, product: str | None = None):
    """Manual refresh. A failed attempt (missing credential, rate limit,
    network error) retains the existing cache and reports `stale`/`last_error`
    rather than clearing it."""
    return await _active().refresh(vendor=vendor, product=product)
