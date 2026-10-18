"""Supabase JWT verification for the single-operator admin gate.

Oyster was built for one local operator with zero authentication. Any
network-reachable deployment (the Hostinger VPS, redorca.tech/oyster) must
gate every route behind a verified Supabase token whose email is on the
``config.ADMIN_EMAILS`` allow-list — sign-up in Supabase alone is NOT enough.

Verification mirrors the pattern already proven in the Dolphin/VoiceIQ backend
(``Voiceiq/backend/app/core/security.py``): asymmetric (ES256/RS256) tokens are
checked against the project's JWKS endpoint; legacy HS256 projects use
``SUPABASE_JWT_SECRET``. Oyster has no local user table — there is nothing to
provision, we only need "is this a verified, allow-listed identity?".
"""
from __future__ import annotations

import threading
import time
from threading import Lock
from typing import Optional

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

import config

# auto_error=False so a missing token falls through to our own 401 (which we
# want to control uniformly, and to allow the DISABLE_AUTH dev bypass below).
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# Seconds a caller should wait before retrying a 503 from this module. The
# only way to get one is "no keys cached and the fetch failed", which a
# background retry or the next caller's inline fetch normally clears at once.
AUTH_RETRY_AFTER = "10"

# ---------------------------------------------------------------------------
# JWKS cache — stale-while-revalidate
#
# Until 2026-09-14 `_get_jwks` held `_jwks_lock` ACROSS the network fetch.
# When the cached keys aged past SUPABASE_JWKS_TTL_S (10 min), the first
# request to notice paid the fetch (up to 5 s) inline, and every other request
# arriving in that window queued on the lock behind it — all of them in the
# threadpool, so the whole app's request capacity drained into one HTTP call
# to Supabase. Once every ten minutes, at exactly the moment a phone came back
# from the background and fired its boot requests.
#
# Now: a stale cache is served immediately and refreshed by ONE background
# thread; the lock guards only the dict, never a socket. The inline fetch
# survives for two cases that genuinely cannot proceed without it — nothing
# cached at all (the first request after boot, if the lifespan warm-up has
# not landed yet), and a token whose signing key is not in the cache (a key
# rotation, which must verify on the first try). The latter is cooled so a
# flood of tokens with bogus kids cannot become a flood of fetches.
# ---------------------------------------------------------------------------

_jwks_cache: dict = {"keys": None, "fetched_at": 0.0}
_jwks_lock = Lock()                      # guards the three module dicts/flags below only
_jwks_refresh: dict = {"running": False, "thread": None, "last_forced_at": 0.0}


class AuthServiceUnavailable(Exception):
    """JWKS endpoint unreachable and no cached keys — cannot verify anything."""


def _fetch_jwks() -> Optional[list]:
    """One HTTP fetch of the key set. Never called with `_jwks_lock` held."""
    if not config.SUPABASE_URL:
        return None
    url = f"{config.SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"
    try:
        resp = httpx.get(url, timeout=5.0)
        resp.raise_for_status()
        return resp.json().get("keys") or []
    except Exception:
        return None


def _store_jwks(keys: list) -> None:
    with _jwks_lock:
        _jwks_cache["keys"] = keys
        _jwks_cache["fetched_at"] = time.monotonic()


def _refresh_jwks_blocking() -> Optional[list]:
    """Fetch and, on success, store. Returns the new keys or None."""
    keys = _fetch_jwks()
    if keys is not None:
        _store_jwks(keys)
    return keys


def _refresh_jwks_background() -> None:
    """Start at most one refresh thread; callers keep serving the stale keys."""
    with _jwks_lock:
        if _jwks_refresh["running"]:
            return
        _jwks_refresh["running"] = True

    def work() -> None:
        try:
            _refresh_jwks_blocking()
        finally:
            with _jwks_lock:
                _jwks_refresh["running"] = False

    t = threading.Thread(target=work, name="jwks-refresh", daemon=True)
    with _jwks_lock:
        _jwks_refresh["thread"] = t
    t.start()


def _get_jwks(force_refresh: bool = False) -> list:
    """Cached JWKS for the Supabase project.

    - Fresh cache → returned at once.
    - Stale cache → returned at once; one background refresh is started.
    - Nothing cached → fetched inline (only ever the first request after a
      boot, and the lifespan warm-up normally beats it); raises
      ``AuthServiceUnavailable`` if that fetch fails, because there is
      nothing to verify with.
    - ``force_refresh`` (a token's kid is not in the cache) → fetched inline,
      but not more than once per ``JWKS_KID_MISS_COOLOFF_S``; inside the
      cool-off the cached keys are returned unchanged, so the token simply
      fails verification as it should.

    `_jwks_lock` is never held while the network is in flight.
    """
    now = time.monotonic()
    with _jwks_lock:
        keys = _jwks_cache["keys"]
        age = now - _jwks_cache["fetched_at"]

    if keys is None:
        fetched = _refresh_jwks_blocking()
        if fetched is None:
            raise AuthServiceUnavailable()
        return fetched

    if force_refresh:
        with _jwks_lock:
            allowed = (now - _jwks_refresh["last_forced_at"]) >= config.JWKS_KID_MISS_COOLOFF_S
            if allowed:
                _jwks_refresh["last_forced_at"] = now
        if allowed:
            fetched = _refresh_jwks_blocking()
            if fetched is not None:
                return fetched
        return keys                      # stale beats nothing, as before

    if age >= config.SUPABASE_JWKS_TTL_S:
        _refresh_jwks_background()
    return keys


def reset_jwks_for_tests() -> None:
    """Forget every cached key and flag. Tests only."""
    t = _jwks_refresh.get("thread")
    if t is not None and t.is_alive():
        t.join(timeout=5)
    with _jwks_lock:
        _jwks_cache["keys"] = None
        _jwks_cache["fetched_at"] = 0.0
        _jwks_refresh["running"] = False
        _jwks_refresh["thread"] = None
        _jwks_refresh["last_forced_at"] = 0.0


def wait_for_jwks_refresh_for_tests(timeout: float = 5.0) -> None:
    """Block until the background refresh thread (if any) has finished."""
    with _jwks_lock:
        t = _jwks_refresh.get("thread")
    if t is not None:
        t.join(timeout=timeout)


def _verify_supabase_token(token: str) -> Optional[dict]:
    """Verify a Supabase access token; return its claims or None if invalid.

    Never explains WHY a token failed (uniform 401 upstream).
    """
    try:
        header = jwt.get_unverified_header(token)
    except JWTError:
        return None
    alg = header.get("alg", "")
    decode_kwargs: dict = dict(
        algorithms=[alg],
        audience=config.SUPABASE_AUD,
        options={"leeway": 30},
    )
    if config.SUPABASE_URL:
        decode_kwargs["issuer"] = f"{config.SUPABASE_URL.rstrip('/')}/auth/v1"

    if alg in ("ES256", "RS256") and config.SUPABASE_URL:
        kid = header.get("kid")
        jwk_key = next((k for k in _get_jwks() if k.get("kid") == kid), None)
        if jwk_key is None:
            jwk_key = next((k for k in _get_jwks(force_refresh=True) if k.get("kid") == kid), None)
        if jwk_key is None:
            return None
        try:
            return jwt.decode(token, jwk_key, **decode_kwargs)
        except JWTError:
            return None

    if alg == "HS256" and config.SUPABASE_JWT_SECRET:
        try:
            return jwt.decode(token, config.SUPABASE_JWT_SECRET, **decode_kwargs)
        except JWTError:
            return None

    return None


def require_admin(token: Optional[str] = Depends(oauth2_scheme)) -> dict:
    """FastAPI dependency: allow only a verified, allow-listed admin identity.

    Local-dev bypass (``config.DISABLE_AUTH``) is preserved so
    ``uvicorn main:app --reload`` keeps working with no Supabase setup at all.
    ``config.py`` refuses to boot with this bypass on in production, so a
    misconfigured deploy fails closed instead of silently serving everything.
    """
    if config.DISABLE_AUTH:
        return {"email": "dev-local", "sub": "dev-local"}

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if token is None:
        raise unauthorized
    try:
        claims = _verify_supabase_token(token)
    except AuthServiceUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service temporarily unavailable",
            headers={"Retry-After": AUTH_RETRY_AFTER},
        )
    if not claims:
        raise unauthorized

    email = (claims.get("email") or "").strip().lower()
    if not email or email not in config.ADMIN_EMAILS:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
    return claims


def _client_ip(request: Request) -> str:
    """Real client IP behind the nginx proxy.

    nginx sets ``X-Forwarded-For: $proxy_add_x_forwarded_for`` — it APPENDS
    the true client address to whatever the client sent, so the RIGHTMOST
    entry is the only one the caller cannot spoof. (The Voiceiq demo limiter
    reads the first entry; for a daily free-tier allowance that would be a
    one-header bypass.)
    """
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"


def require_chat_access(
    request: Request, token: Optional[str] = Depends(oauth2_scheme)
) -> dict:
    """Soft gate for the public chat surface (/chat, /me).

    Tiers:
      - ``admin`` — verified token, email on ``config.ADMIN_EMAILS``. Full
        behavior (operator memory injection, free model choice).
      - ``user``  — verified token, any other email. Unlimited, stateless chat.
      - ``anon``  — no token at all. Subject to the per-IP daily allowance
        (checked and consumed in the chat route, NOT here, so ``/me`` never
        burns quota).

    A PRESENT-but-invalid token still gets the uniform 401 — silently
    downgrading a broken session to anonymous would make expiry look like the
    daily limit. Everything outside this surface keeps ``require_admin``.
    """
    if config.DISABLE_AUTH:
        return {"tier": "admin", "email": "dev-local", "sub": "dev-local"}

    if token is not None:
        try:
            claims = _verify_supabase_token(token)
        except AuthServiceUnavailable:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Auth service temporarily unavailable",
                headers={"Retry-After": AUTH_RETRY_AFTER},
            )
        if not claims:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        email = (claims.get("email") or "").strip().lower()
        tier = "admin" if email and email in config.ADMIN_EMAILS else "user"
        # `sub` is Supabase's immutable per-account id — the key conversation
        # ownership is stamped with (email can be changed by the user).
        return {"tier": tier, "email": email, "sub": claims.get("sub")}

    if not config.PUBLIC_CHAT_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"tier": "anon", "ip": _client_ip(request)}


def require_account(identity: dict = Depends(require_chat_access)) -> dict:
    """Any signed-in account (``user`` or ``admin``); anonymous is refused.

    The operator surface — projects, scope, red-team planning, long-term
    memory, settings — used to sit behind ``require_admin``. It is now open to
    every account, so the gate had to widen from "is on the allow-list" to
    "is signed in at all". What keeps one account out of another's data is no
    longer the gate but the per-caller project resolved in
    ``services/project_context.py``.
    """
    if identity.get("tier") == "anon":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in to use this feature",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return identity
