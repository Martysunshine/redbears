"""Ask VoiceIQ what an account paid for — and never depend on the answer.

Red Orca sells "priority access to Oyster" on its paid plans. The money, the
`subscriptions` table and the plan catalog all live in the VoiceIQ backend.
Oyster is a separate application with its own SQLite database and no reach into
any of it; what the two share is the Supabase project whose tokens they both
verify. So Oyster forwards the caller's OWN token to VoiceIQ's
``GET /billing/entitlements`` and reads one flag out of the reply.

THE POINT OF THIS FILE IS THE FAILURE MODE, NOT THE FEATURE.

Priority is a nice-to-have; chat working is not. Every path through here that
is not a clear, timely "yes" resolves to ``False`` — no priority, ordinary
queue, request proceeds. That covers a billing API that is down, slow, moved,
misconfigured, returning nonsense, or simply never deployed (the default: no
URL configured at all). The queue must behave exactly as it does today if this
module were deleted.

Three things keep someone else's outage from becoming our latency:

  * a SHORT timeout (config.BILLING_TIMEOUT_S) — the call sits in front of a
    user's chat request;
  * a per-account CACHE — a plan does not change between two messages, so the
    steady state is one HTTP call per user per few minutes, not one per chat;
  * a COOL-OFF after any failure — a *down* API answers instantly at the TCP
    level or hangs for the full timeout, and paying that on every request is
    how a billing outage would turn into an Oyster outage. After a failure we
    simply stop asking for a minute.

Nothing here is a security boundary. The worst outcome of getting it wrong is
that someone waits in the ordinary line, or doesn't.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

import config

log = logging.getLogger("oyster.entitlements")

# supabase sub -> (is_priority, expires_at monotonic). Keyed by `sub` and not by
# the token: tokens rotate hourly, the account behind them does not.
_cache: dict[str, tuple[bool, float]] = {}

# While monotonic() < this, we do not call the billing API at all.
_cooloff_until: float = 0.0

# Set once per cool-off window so a sustained outage does not write a log line
# per chat request.
_outage_logged = False


def _cache_get(key: str) -> Optional[bool]:
    hit = _cache.get(key)
    if hit is None:
        return None
    value, expires_at = hit
    if time.monotonic() >= expires_at:
        _cache.pop(key, None)
        return None
    return value


def _cache_put(key: str, value: bool) -> None:
    ttl = max(1, int(config.BILLING_CACHE_TTL_S))
    if len(_cache) >= max(1, int(config.BILLING_CACHE_MAX)):
        # Drop what has already expired; if that is not enough, drop everything.
        # A cleared cache costs one extra HTTP call per active user and nothing
        # else, which is a much better trade than an unbounded dict on a box
        # with 7.8 GB of RAM.
        now = time.monotonic()
        for k in [k for k, (_, exp) in _cache.items() if now >= exp]:
            _cache.pop(k, None)
        if len(_cache) >= max(1, int(config.BILLING_CACHE_MAX)):
            _cache.clear()
    _cache[key] = (value, time.monotonic() + ttl)


def _begin_cooloff(reason: str) -> None:
    global _cooloff_until, _outage_logged
    _cooloff_until = time.monotonic() + max(0, int(config.BILLING_FAILURE_COOLOFF_S))
    if not _outage_logged:
        _outage_logged = True
        log.warning(
            "[entitlements] billing lookup failed (%s) — treating everyone as "
            "non-priority for %ss",
            reason,
            config.BILLING_FAILURE_COOLOFF_S,
        )


async def _fetch(token: str) -> Optional[bool]:
    """One call to VoiceIQ. True/False on a definitive answer, None on outage.

    The None/False distinction is only about CACHING: a definitive "this
    account does not pay" is worth remembering for the full TTL, while "the
    billing API is unreachable" must not be remembered as a fact about the
    user — it is remembered as a cool-off instead, so the moment the API comes
    back the next lookup is real.
    """
    url = f"{config.BILLING_API_URL}/billing/entitlements"
    try:
        async with httpx.AsyncClient(timeout=config.BILLING_TIMEOUT_S) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    except Exception as exc:  # noqa: BLE001 — every transport failure is "no"
        _begin_cooloff(type(exc).__name__)
        return None

    if resp.status_code in (401, 403, 404):
        # A real answer: VoiceIQ does not recognise this account, or has nothing
        # for it. Not an outage — cache it, or every chat from every anonymous-
        # ish signed-in visitor re-asks.
        return False
    if resp.status_code != 200:
        _begin_cooloff(f"HTTP {resp.status_code}")
        return None
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        _begin_cooloff("unparseable body")
        return None
    if not isinstance(data, dict):
        _begin_cooloff("unexpected body")
        return None
    return bool(data.get("oyster_priority"))


async def is_priority(identity: dict, token: Optional[str]) -> bool:
    """Should this caller be served ahead of the ordinary queue?

    Never raises. Never returns True on a guess.

    Tiers, before any network call is considered:
      * ``anon``  — no account, so nothing was bought. False.
      * ``admin`` — the operator. True, without asking anyone: they are already
        exempt from every other cap in this codebase, they are the person
        debugging the box while it is busy, and they have no reason to hold a
        VoiceIQ subscription at all. (Under the local DISABLE_AUTH bypass every
        caller is ``admin``, which makes priority uniformly true — i.e. exactly
        the same ordering as today. That is the intended no-op, not a bug.)
      * ``user``  — the only tier we actually ask about.
    """
    global _outage_logged

    tier = identity.get("tier")
    if tier == "admin":
        return True
    if tier != "user":
        return False
    if not config.BILLING_API_URL or not token:
        # No billing API configured (the default) — the entitlement is simply
        # not readable from here, so nobody is priority and nothing waits.
        return False

    sub = identity.get("sub") or ""
    if sub:
        cached = _cache_get(sub)
        if cached is not None:
            return cached

    if time.monotonic() < _cooloff_until:
        return False
    _outage_logged = False

    answer = await _fetch(token)
    if answer is None:
        return False
    if sub:
        _cache_put(sub, answer)
    return answer


def reset_for_tests() -> None:
    """Clear cache + cool-off. Tests only; process-global state otherwise."""
    global _cooloff_until, _outage_logged
    _cache.clear()
    _cooloff_until = 0.0
    _outage_logged = False
