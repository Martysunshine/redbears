"""Oyster MCP gateway — Streamable HTTP transport (ChatGPT-ready).

A single ``/mcp`` endpoint speaking the MCP Streamable HTTP transport, plus an
unauthenticated ``/healthz`` readiness probe that reveals nothing sensitive.

Security posture (see docs/MCP_GATEWAY.md for the full threat model):

* No anonymous access — every ``/mcp`` request needs a bearer token (Supabase
  JWT allow-listed, or a configured static token). Even ``initialize`` is gated.
* Origin validation — a request carrying a browser ``Origin`` is refused unless
  that origin is explicitly allow-listed (DNS-rebinding defence). Native clients
  send no Origin and are allowed. CORS credentials are echoed only for an
  explicitly allow-listed origin — never a wildcard.
* Per-identity rate limiting, request-size and response-size limits.
* Opaque, identity-bound sessions with a TTL.
* Loopback bind by default; a network bind requires a deliberate env change and
  a TLS-terminating reverse proxy in front.

The app is a plain Starlette application so it can be driven by uvicorn in
production and by starlette.testclient in tests, with no extra dependency.
"""

from __future__ import annotations

import json
import time
import uuid
from threading import Lock

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

import config
import log_config

from . import PROTOCOL_VERSION
from .core import protocol, security
from .core.identity import AuthError, resolve_http_identity

_SESSION_TTL_S = 3600
_MAX_SESSIONS = 10_000


class _SessionStore:
    def __init__(self):
        self._s: dict[str, dict] = {}
        self._lock = Lock()

    def create(self, fingerprint: str) -> str:
        sid = uuid.uuid4().hex
        with self._lock:
            if len(self._s) >= _MAX_SESSIONS:
                self._prune(force=True)
            self._s[sid] = {"fp": fingerprint, "created": time.monotonic()}
        return sid

    def valid(self, sid: str, fingerprint: str) -> bool:
        with self._lock:
            self._prune()
            row = self._s.get(sid)
            return bool(row and row["fp"] == fingerprint)

    def drop(self, sid: str) -> None:
        with self._lock:
            self._s.pop(sid, None)

    def _prune(self, force: bool = False) -> None:
        now = time.monotonic()
        dead = [k for k, v in self._s.items() if now - v["created"] > _SESSION_TTL_S]
        for k in dead:
            self._s.pop(k, None)
        if force and self._s:
            # Drop the oldest to make room.
            oldest = min(self._s, key=lambda k: self._s[k]["created"])
            self._s.pop(oldest, None)


def create_app() -> Starlette:
    limiter = security.RateLimiter(config.MCP_RATE_LIMIT_PER_MIN)
    sessions = _SessionStore()

    def _origin_ok(request: Request) -> bool:
        origin = request.headers.get("origin")
        if not origin:
            return True  # native MCP clients send no Origin
        return origin in config.MCP_ALLOWED_ORIGINS

    def _cors_headers(request: Request) -> dict:
        origin = request.headers.get("origin")
        if origin and origin in config.MCP_ALLOWED_ORIGINS:
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Headers": "authorization, content-type, mcp-session-id",
                "Access-Control-Allow-Methods": "POST, GET, DELETE, OPTIONS",
                "Vary": "Origin",
            }
        return {}

    async def healthz(request: Request) -> Response:
        # Deliberately minimal — a readiness probe reveals nothing sensitive.
        return JSONResponse({"status": "ok", "protocol": PROTOCOL_VERSION,
                             "enabled": bool(config.MCP_GATEWAY_ENABLED)})

    async def mcp_options(request: Request) -> Response:
        return Response(status_code=204, headers=_cors_headers(request))

    async def mcp_get(request: Request) -> Response:
        # No server-initiated SSE stream is offered at this endpoint.
        return JSONResponse({"error": "SSE stream not offered; POST JSON-RPC to this endpoint"},
                            status_code=405, headers={"Allow": "POST, DELETE, OPTIONS"})

    async def mcp_delete(request: Request) -> Response:
        sid = request.headers.get("mcp-session-id")
        if sid:
            sessions.drop(sid)
        return Response(status_code=204, headers=_cors_headers(request))

    async def mcp_post(request: Request) -> Response:
        cors = _cors_headers(request)

        # 1) Origin / DNS-rebinding defence.
        if not _origin_ok(request):
            return JSONResponse({"error": "origin not allowed"}, status_code=403, headers=cors)

        # 2) Authenticate — no anonymous access.
        try:
            identity = resolve_http_identity(request.headers.get("authorization"))
        except AuthError as exc:
            code = 403 if exc.code == "forbidden" else (503 if exc.code == "unavailable" else 401)
            headers = dict(cors)
            if code == 401:
                headers["WWW-Authenticate"] = "Bearer"
            log_config.audit("mcp_auth_denied", {"surface": "mcp_gateway", "transport": "http",
                                                 "reason": exc.code})
            return JSONResponse({"error": exc.message}, status_code=code, headers=headers)

        # 3) Rate limit (per identity).
        allowed, retry = limiter.check(identity.rate_key())
        if not allowed:
            log_config.audit("mcp_rate_limited", {"surface": "mcp_gateway", "transport": "http",
                                                  "actor": identity.audit_actor()})
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429,
                                headers={**cors, "Retry-After": str(retry)})

        # 4) Request-size limit (declared then actual).
        clen = request.headers.get("content-length")
        if clen and clen.isdigit() and int(clen) > config.MCP_MAX_REQUEST_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413, headers=cors)
        body = await request.body()
        if len(body) > config.MCP_MAX_REQUEST_BYTES:
            return JSONResponse({"error": "request too large"}, status_code=413, headers=cors)

        # 5) Parse JSON-RPC (single message; batching is not offered).
        try:
            message = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": protocol.PARSE_ERROR, "message": "Parse error"}},
                headers=cors)
        if isinstance(message, list):
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": protocol.INVALID_REQUEST, "message": "Batch is not supported"}},
                headers=cors)

        # 6) Session handling. initialize mints a session; other calls may carry
        #    one and it must be valid + bound to this identity.
        method = message.get("method") if isinstance(message, dict) else None
        sid = request.headers.get("mcp-session-id")
        resp_headers = dict(cors)
        if method == "initialize":
            new_sid = sessions.create(identity.token_fingerprint)
            resp_headers["Mcp-Session-Id"] = new_sid
        elif sid:
            if not sessions.valid(sid, identity.token_fingerprint):
                return JSONResponse({"error": "invalid or expired session"}, status_code=404,
                                    headers=cors)

        # 7) Dispatch through the shared protocol layer.
        response = await protocol.handle_rpc(identity, message)
        resp_headers["Mcp-Correlation-Id"] = identity.correlation_id

        if response is None:
            # Notification — accept with no body.
            return Response(status_code=202, headers=resp_headers)
        return JSONResponse(response, headers=resp_headers)

    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/mcp", mcp_post, methods=["POST"]),
        Route("/mcp", mcp_get, methods=["GET"]),
        Route("/mcp", mcp_delete, methods=["DELETE"]),
        Route("/mcp", mcp_options, methods=["OPTIONS"]),
    ]
    return Starlette(routes=routes)


app = create_app()
