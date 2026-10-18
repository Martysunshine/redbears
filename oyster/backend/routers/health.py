from __future__ import annotations

import asyncio
import time

import httpx
from fastapi import APIRouter

import config
from services import ollama_probe

router = APIRouter(tags=["health"])

# /health is public, unauthenticated, and polled by every open tab and by the
# uptime monitors. It used to probe both Ollama endpoints on EVERY call — and
# it always tried the primary first, even during a failover cool-off, so each
# poll paid a 1.2 s connect timeout to a dead node. It now reads the state the
# background prober maintains (services/ollama_probe.py): no outbound call per
# request, and the same answer generation itself would act on.
#
# Only before the prober's first round (the first seconds after boot) does the
# old inline probe run — once, then cached for HEALTH_CACHE_S — so a restart
# never makes the status dot lie and a poll storm cannot become a probe storm.
_PROBE_TIMEOUT_S = 1.2
_boot_cache: tuple[float, str | None] | None = None
_boot_lock = asyncio.Lock()


def _tags_urls() -> list[str]:
    """Every Ollama that could serve generation, primary first."""
    urls = [config.OLLAMA_TAGS_URL]
    fallback = config.OLLAMA_FALLBACK_BASE_URL
    if fallback:
        fb = f"{fallback.rstrip('/')}/api/tags"
        if fb not in urls:
            urls.append(fb)
    return urls


async def _boot_probe() -> str | None:
    global _boot_cache
    async with _boot_lock:
        now = time.monotonic()
        if _boot_cache is not None and now - _boot_cache[0] < config.HEALTH_CACHE_S:
            return _boot_cache[1]
        live: str | None = None
        async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_S) as client:
            for url in _tags_urls():
                try:
                    if (await client.get(url)).status_code == 200:
                        live = url
                        break
                except Exception:  # noqa: BLE001 — unreachable is an answer, not an error
                    continue
        via = None if live is None else ("primary" if live == config.OLLAMA_TAGS_URL else "fallback")
        _boot_cache = (now, via)
        return via


@router.get("/health")
async def health():
    """Can Oyster actually generate? True if ANY configured Ollama answers."""
    if ollama_probe.has_data():
        via = ollama_probe.live_via()
        probe_age = ollama_probe.snapshot()["probe_age_s"]
    else:
        via = await _boot_probe()
        probe_age = None

    return {
        "status": "ok",
        "default_model": config.DEFAULT_MODEL,
        "available_models": list(config.AVAILABLE_MODELS.keys()),
        # True when generation would succeed — via the primary OR the fallback.
        "ollama": via is not None,
        # Which one, so "it works but slowly" is diagnosable from outside the
        # box. A label, never the URL: this endpoint is public and the URLs
        # are private addresses.
        "ollama_via": via,
        "ollama_primary": via == "primary",
        # How old the answer is, in seconds; null while the boot probe is the
        # source. Lets a monitor tell "fresh and false" from "stale".
        "probe_age_s": probe_age,
    }
