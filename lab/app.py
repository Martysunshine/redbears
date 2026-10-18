"""Red Bears IDOR demo lab — a tiny, intentionally-vulnerable FastAPI target.

This is a disposable teaching target (in the spirit of OWASP Juice Shop / DVWA /
WebGoat): it exists so the Red Bears agent can demonstrate finding one real
authorization flaw and then confirming a patch removed it. It is **not** a
general tool and must only ever be reached on loopback.

One codebase, two modes selected by ``LAB_MODE`` (identical fixtures in both):

* ``vulnerable`` — authentication works, but the object-level ownership check is
  deliberately omitted, so any authenticated persona can read any record
  (Broken Object Level Authorization / IDOR).
* ``patched`` — the same app with the ownership check restored: a persona
  reading a record they do not own gets 403 with no record content.

Safety properties, by construction:

* Read-only: ``GET`` endpoints only. No write/delete routes exist.
* No secrets or realistic data in responses (see fixtures.py).
* Identity comes only from the bearer token → persona mapping; an ``X-User`` (or
  similar) header is never trusted as proof of identity.
* Logs record method, path, persona label, status, mode and a request id —
  never the bearer token value.
* ``LAB_MODE`` is process configuration, chosen by the operator at startup. It
  is not an endpoint and cannot be changed by a request.
"""

from __future__ import annotations

import logging
import os
import uuid

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import fixtures

VALID_MODES = ("vulnerable", "patched")

logger = logging.getLogger("redbears.lab")


def _normalise_mode(mode: str | None) -> str:
    resolved = (mode or os.environ.get("LAB_MODE") or "vulnerable").strip().lower()
    if resolved not in VALID_MODES:
        raise ValueError(f"LAB_MODE must be one of {VALID_MODES}, got {resolved!r}")
    return resolved


def _bearer_persona(authorization: str | None) -> str:
    """Resolve the Authorization header to a persona, or 401.

    Only ``Authorization: Bearer <token>`` is accepted. The token is matched
    against the demo tokens (fixtures); anything else is 401. No other header
    (e.g. ``X-User``) is ever consulted — a caller cannot assert an identity.
    """
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[len("bearer "):].strip()
    persona = fixtures.persona_for_token(token)
    if persona is None:
        # 401 with a generic message — never echoes the presented token.
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")
    return persona


def create_app(mode: str | None = None) -> FastAPI:
    resolved_mode = _normalise_mode(mode)
    app = FastAPI(
        title="Red Bears IDOR demo lab",
        description=(
            "Disposable, loopback-only teaching target with an intentional "
            "object-level authorization flaw in `vulnerable` mode. Not for use "
            "against any system but this local demo."
        ),
        version="1.0.0",
    )
    app.state.mode = resolved_mode

    @app.middleware("http")
    async def _sanitised_access_log(request: Request, call_next):
        request_id = uuid.uuid4().hex[:12]
        # Resolve the persona for logging without failing the request here; the
        # route dependency is what actually enforces auth. Never logs the token.
        persona = fixtures.persona_for_token(_token_from_request(request))
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        logger.info(
            "lab request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "persona": persona or "-",
                "status": response.status_code,
                "mode": resolved_mode,
            },
        )
        return response

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True, "mode": resolved_mode}

    @app.get("/api/records/{record_id}")
    async def get_record(record_id: int, persona: str = Depends(_require_persona)) -> JSONResponse:
        record = fixtures.RECORDS.get(record_id)
        if record is None:
            # Unknown id → 404 regardless of mode or persona.
            raise HTTPException(status_code=404, detail="Record not found")
        # The one deliberate difference between the two modes: patched mode
        # enforces object-level ownership; vulnerable mode omits that check.
        if resolved_mode == "patched" and record["owner"] != persona:
            # 403 carries no record content — nothing about the record leaks.
            raise HTTPException(status_code=403, detail="Forbidden")
        return JSONResponse(record)

    return app


def _token_from_request(request: Request) -> str | None:
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[len("bearer "):].strip()
    return None


async def _require_persona(authorization: str | None = Header(default=None)) -> str:
    return _bearer_persona(authorization)


# Module-level app for `uvicorn lab.app:app` — mode comes from LAB_MODE.
app = create_app()
