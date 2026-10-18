"""NVD-aware request pacing.

NVD's documented public rate limit is 5 requests / 30s without an API key, 50
requests / 30s with one. We stay conservative under that (a fixed sleep
between requests, not a burst-then-block scheme) rather than cutting it close.
The key itself is read from the environment only — never from a `.env` file
directly, never written anywhere, never logged.
"""

from __future__ import annotations

import asyncio
import os
import time

import config


def nvd_api_key() -> str | None:
    return os.getenv("OYSTER_NVD_API_KEY") or None


def nvd_min_interval_seconds() -> float:
    if nvd_api_key():
        return config.NVD_MIN_REQUEST_INTERVAL_WITH_KEY_S
    return config.NVD_MIN_REQUEST_INTERVAL_NO_KEY_S


class Pacer:
    """Sleeps as needed before each call so calls are spaced >= min_interval apart.

    Holds a lock across the sleep. Without it two coroutines can both read
    ``_last_call``, both compute the same remaining time, both sleep it, and both
    fire together — pacing that looks correct and is not. The lock makes the
    spacing hold under concurrency, which is the only situation it was for.
    """

    def __init__(self, min_interval_seconds: float):
        self.min_interval = min_interval_seconds
        self._last_call: float | None = None
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            if self._last_call is not None:
                elapsed = time.monotonic() - self._last_call
                remaining = self.min_interval - elapsed
                if remaining > 0:
                    await asyncio.sleep(remaining)
            self._last_call = time.monotonic()


# ONE pacer for the whole process, because the thing being rate-limited is NIST's
# view of this server's IP — not any single sync run.
#
# Every entry point used to build its own Pacer, so two overlapping syncs (a
# double-click on the admin button is enough) each paced themselves correctly and
# together hit NVD at twice the agreed rate. NVD answers that with 403s and, if it
# continues, by blocking the address — which would take out the feature for
# everyone, silently, and not obviously because of a double-click.
#
# Rebuilt when the key changes, since the permitted interval depends on it.
_shared_pacer: Pacer | None = None
_shared_interval: float | None = None


def shared_pacer() -> Pacer:
    global _shared_pacer, _shared_interval
    interval = nvd_min_interval_seconds()
    if _shared_pacer is None or _shared_interval != interval:
        _shared_pacer = Pacer(interval)
        _shared_interval = interval
    return _shared_pacer


class DownloadTooLarge(RuntimeError):
    """An upstream feed exceeded its byte budget and was abandoned mid-stream."""


async def get_capped(
    client, url: str, *, max_bytes: int | None = None, **kwargs
) -> bytes:
    """GET a URL, refusing to buffer more than `max_bytes`.

    Every feed fetcher used to do ``resp.content`` with no ceiling, so the size of
    what we load into a 3 GB container was entirely at the upstream's discretion.
    These are third-party feeds that legitimately grow — NVD's is already ~51 MB —
    and an unbounded read on a shared box turns "the feed got bigger" into "the
    container OOMs and takes Oyster's chat down with it".

    Streams and aborts as soon as the budget is passed, so an oversized feed costs
    the budget rather than the whole file. Raising is deliberate: a truncated feed
    silently imported would be worse than a failed sync, because the gaps would
    look like real absences of vulnerabilities.
    """
    limit = max_bytes or config.VULN_MAX_DOWNLOAD_BYTES
    chunks: list[bytes] = []
    total = 0
    async with client.stream("GET", url, **kwargs) as resp:
        resp.raise_for_status()
        # Trust a declared length enough to fail early, never enough to skip the
        # running count — Content-Length is a claim, not a guarantee.
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise DownloadTooLarge(
                f"{url} declares {int(declared):,} bytes, over the {limit:,} byte budget"
            )
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > limit:
                raise DownloadTooLarge(
                    f"{url} exceeded the {limit:,} byte budget (read {total:,} and still going)"
                )
            chunks.append(chunk)
    return b"".join(chunks)
