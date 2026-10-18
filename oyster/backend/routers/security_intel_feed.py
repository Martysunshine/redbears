"""Security Intel "Latest intelligence" feed — read-only OpenCVE mirror.
Manual refresh only by default (brief: "Start with manual refresh"); scheduled
refresh is a separate config flag (config.OPENCVE_SCHEDULED_REFRESH_ENABLED),
off by default, and is wired up in app.py's startup hook, not here.
"""
from __future__ import annotations

from fastapi import APIRouter

from services.intel import opencve_feed

router = APIRouter(prefix="/security-intel/feed", tags=["security-intel-feed"])


@router.get("")
async def get_feed():
    """Never makes a network call — serves whatever is cached, with a `stale`
    flag if the most recent refresh attempt failed."""
    return opencve_feed.get_feed()


@router.post("/refresh")
async def refresh_feed(vendor: str | None = None, product: str | None = None):
    """Manual refresh. A failed attempt (missing credential, rate limit,
    network error) retains the existing cache and reports `stale`/`last_error`
    rather than clearing it."""
    return await opencve_feed.refresh(vendor=vendor, product=product)
