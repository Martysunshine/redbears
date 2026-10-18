"""The JWKS cache serves stale keys instantly and refreshes them off the
request path — never holding its lock across the network.

Background: until 2026-09-14 `_get_jwks` held `_jwks_lock` across `httpx.get`.
Every ten minutes the first request to find the cache stale paid the fetch
inline and every concurrent request queued behind it on the lock, draining
the threadpool into one HTTP call. These tests pin the new contract; the
network is a fake `_fetch_jwks`, so nothing here touches Supabase.
"""
from __future__ import annotations

import threading
import time

import pytest

import config
from services import auth_service as auth

KEYS_V1 = [{"kid": "k1", "kty": "EC"}]
KEYS_V2 = [{"kid": "k2", "kty": "EC"}]


class FakeFetch:
    """Stand-in for `_fetch_jwks`: counts calls, can block, can fail, and
    records whether the module lock was free while it ran."""

    def __init__(self, result=KEYS_V2):
        self.result = result
        self.calls = 0
        self.gate = threading.Event()   # set → fetch may return
        self.gate.set()
        self.started = threading.Event()
        self.lock_was_free: list[bool] = []

    def __call__(self):
        self.calls += 1
        self.started.set()
        # The whole point: a fetch must never run with `_jwks_lock` held.
        got = auth._jwks_lock.acquire(timeout=0.2)
        self.lock_was_free.append(got)
        if got:
            auth._jwks_lock.release()
        self.gate.wait(timeout=5)
        return self.result


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    auth.reset_jwks_for_tests()
    monkeypatch.setattr(config, "SUPABASE_JWKS_TTL_S", 600)
    monkeypatch.setattr(config, "JWKS_KID_MISS_COOLOFF_S", 30)
    yield
    auth.reset_jwks_for_tests()


def _prime(keys=KEYS_V1, age_s: float = 0.0) -> None:
    """Put keys in the cache as if fetched `age_s` seconds ago."""
    with auth._jwks_lock:
        auth._jwks_cache["keys"] = keys
        auth._jwks_cache["fetched_at"] = time.monotonic() - age_s


def test_fresh_cache_is_served_without_a_fetch(monkeypatch):
    fetch = FakeFetch()
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    _prime(KEYS_V1, age_s=1)
    assert auth._get_jwks() == KEYS_V1
    assert fetch.calls == 0


def test_stale_cache_is_served_at_once_and_refreshed_in_the_background(monkeypatch):
    fetch = FakeFetch(result=KEYS_V2)
    fetch.gate.clear()                        # hold the "network" open
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    _prime(KEYS_V1, age_s=10_000)

    t0 = time.monotonic()
    got = auth._get_jwks()
    elapsed = time.monotonic() - t0

    assert got == KEYS_V1, "stale keys must be served immediately"
    assert elapsed < 0.1, f"caller waited {elapsed:.3f}s on a background refresh"
    assert fetch.started.wait(timeout=2), "no background refresh started"

    fetch.gate.set()
    auth.wait_for_jwks_refresh_for_tests()
    assert auth._get_jwks() == KEYS_V2, "cache not updated by the background refresh"
    assert fetch.calls == 1


def test_many_stale_callers_trigger_exactly_one_refresh(monkeypatch):
    fetch = FakeFetch(result=KEYS_V2)
    fetch.gate.clear()
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    _prime(KEYS_V1, age_s=10_000)

    results = []
    threads = [threading.Thread(target=lambda: results.append(auth._get_jwks()))
               for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2)

    assert len(results) == 20 and all(r == KEYS_V1 for r in results)
    fetch.gate.set()
    auth.wait_for_jwks_refresh_for_tests()
    assert fetch.calls == 1, f"{fetch.calls} fetches for one stale window"


def test_the_lock_is_never_held_across_the_fetch(monkeypatch):
    fetch = FakeFetch(result=KEYS_V2)
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)

    # Inline path (nothing cached) …
    auth._get_jwks()
    # … background path (stale) …
    _prime(KEYS_V1, age_s=10_000)
    auth._get_jwks()
    auth.wait_for_jwks_refresh_for_tests()
    # … and the forced path (kid miss).
    auth._get_jwks(force_refresh=True)

    assert fetch.calls == 3
    assert all(fetch.lock_was_free), fetch.lock_was_free


def test_a_failed_background_refresh_keeps_the_stale_keys(monkeypatch):
    fetch = FakeFetch(result=None)            # network down
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    _prime(KEYS_V1, age_s=10_000)

    assert auth._get_jwks() == KEYS_V1
    auth.wait_for_jwks_refresh_for_tests()
    assert auth._get_jwks() == KEYS_V1, "a failed refresh must not empty the cache"
    assert fetch.calls >= 1


def test_nothing_cached_and_fetch_fails_is_unavailable(monkeypatch):
    monkeypatch.setattr(auth, "_fetch_jwks", FakeFetch(result=None))
    with pytest.raises(auth.AuthServiceUnavailable):
        auth._get_jwks()


def test_nothing_cached_fetches_inline(monkeypatch):
    fetch = FakeFetch(result=KEYS_V2)
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    assert auth._get_jwks() == KEYS_V2
    assert fetch.calls == 1
    # And the result is now cached: a second call is free.
    assert auth._get_jwks() == KEYS_V2
    assert fetch.calls == 1


def test_kid_miss_refreshes_inline_but_only_once_per_cooloff(monkeypatch):
    fetch = FakeFetch(result=KEYS_V2)
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    _prime(KEYS_V1, age_s=1)                  # fresh, so only force can fetch

    assert auth._get_jwks(force_refresh=True) == KEYS_V2   # rotation honoured
    assert fetch.calls == 1
    for _ in range(50):                                   # a flood of bad kids
        auth._get_jwks(force_refresh=True)
    assert fetch.calls == 1, "kid-miss refreshes must be cooled"

    # Once the cool-off has passed, a forced refresh is allowed again.
    with auth._jwks_lock:
        auth._jwks_refresh["last_forced_at"] = time.monotonic() - 31
    auth._get_jwks(force_refresh=True)
    assert fetch.calls == 2


def test_kid_miss_inside_cooloff_returns_cached_keys(monkeypatch):
    fetch = FakeFetch(result=KEYS_V2)
    monkeypatch.setattr(auth, "_fetch_jwks", fetch)
    _prime(KEYS_V1, age_s=1)
    with auth._jwks_lock:
        auth._jwks_refresh["last_forced_at"] = time.monotonic()   # just forced
    assert auth._get_jwks(force_refresh=True) == KEYS_V1
    assert fetch.calls == 0


def test_unavailable_maps_to_503_with_retry_after(monkeypatch):
    """Both gates tell the client when to come back, not just that it failed."""
    from fastapi import HTTPException

    monkeypatch.setattr(config, "DISABLE_AUTH", False)
    monkeypatch.setattr(auth, "_verify_supabase_token",
                        lambda _t: (_ for _ in ()).throw(auth.AuthServiceUnavailable()))
    with pytest.raises(HTTPException) as admin_exc:
        auth.require_admin(token="x")
    assert admin_exc.value.status_code == 503
    assert admin_exc.value.headers.get("Retry-After") == auth.AUTH_RETRY_AFTER

    class _Req:
        headers: dict = {}
        client = None

    with pytest.raises(HTTPException) as chat_exc:
        auth.require_chat_access(_Req(), token="x")
    assert chat_exc.value.status_code == 503
    assert chat_exc.value.headers.get("Retry-After") == auth.AUTH_RETRY_AFTER
