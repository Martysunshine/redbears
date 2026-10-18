"""Oyster Red Team API — application entry point.

This file is intentionally thin: it builds the FastAPI app, wires CORS, mounts
every router, and initialises persistent memory. All endpoint logic lives in
the ``routers/`` package and the mounted sub-apps (``mcp_server``,
``agent_loop``, ``memory`` and the optional ``security_kb``).
"""

from __future__ import annotations

import os
import sys
import traceback

from fastapi import Depends, FastAPI
from fastapi.concurrency import run_in_threadpool as _run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request as _StarletteRequest

import config
import log_config
from agent_loop.server import router as agent_loop_router
from mcp_server.server import router as mcp_router
from memory import store as memory_store
from memory.server import router as memory_router
from routers import ACCOUNT_ROUTERS, PROTECTED_ROUTERS, PUBLIC_ROUTERS, TIERED_ROUTERS
from routers.execution import require_execution_enabled
from services import conversation_service, project_service
from services.auth_service import require_account, require_admin

# The allow-list gate. It still guards everything that writes instance-wide
# state or executes a tool — see config.py for the production boot guard and
# services/auth_service.py for the verification logic. The per-account
# workspace surface uses require_account instead (see ACCOUNT_ROUTERS below).
_ADMIN_ONLY = [Depends(require_admin)]

# Security KB router (optional — only mounted if the KB package is importable).
#
# The KB is a standalone package that imports its own top-level ``config`` module
# (security_kb/config.py). Since the backend now also has a top-level ``config``
# module, we temporarily lift ours out of ``sys.modules`` while importing the KB
# so the KB's ``from config import ...`` resolves to *its* config, then restore
# ours. All KB config values are bound at import time, so the restore is safe.
if config.SECURITY_KB_DIR.exists() and str(config.SECURITY_KB_DIR) not in sys.path:
    sys.path.insert(0, str(config.SECURITY_KB_DIR))

_saved_config = sys.modules.pop("config", None)
try:
    from api.kb_routes import router as _kb_router
    _KB_AVAILABLE = True
except Exception:
    _kb_router = None
    _KB_AVAILABLE = False
finally:
    if _saved_config is not None:
        sys.modules["config"] = _saved_config


# Interactive docs are a development convenience, not a production feature: on
# the public deployment /docs, /redoc and /openapi.json handed any visitor a
# complete map of the API — including every admin-only route path and its
# request shape — which is free reconnaissance for anyone probing for a gap.
# Operators can still read them by running the app locally, or by setting
# OYSTER_ENVIRONMENT to anything but "production".
_IS_PROD = config.ENVIRONMENT.strip().lower() == "production"

import asyncio  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402

from services import ollama_probe, ollama_service  # noqa: E402


def _warm_singletons() -> None:
    """Pay the slow one-time costs at boot, off the event loop, so the first
    chat after a (re)start does not: Supabase's signing keys and the
    embedding model behind Chroma (seconds of CPU on this box). Never fatal."""
    try:
        from services import auth_service as _auth
        if hasattr(_auth, "_get_jwks"):
            _auth._get_jwks()
    except Exception as exc:  # noqa: BLE001
        print(f"  warm-up : jwks skipped ({type(exc).__name__})", file=sys.stderr)
    try:
        from services import rag_service as _rag
        _rag._get_client()
    except Exception as exc:  # noqa: BLE001
        print(f"  warm-up : embeddings skipped ({type(exc).__name__})", file=sys.stderr)


async def _opencve_scheduled_refresh_loop():
    """Only ever starts if config.OPENCVE_SCHEDULED_REFRESH_ENABLED is true —
    off by default (brief: "configurable and disabled until deliberately
    enabled"). A failed refresh just logs and retries next interval; the feed
    cache itself already handles "keep the old data, mark it stale" (see
    services/intel/opencve_feed.py)."""
    from services.intel import opencve_feed
    while True:
        try:
            await opencve_feed.refresh()
        except Exception as exc:  # noqa: BLE001 — never let the loop die silently
            print(f"  opencve scheduled refresh failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        await asyncio.sleep(config.OPENCVE_SCHEDULED_REFRESH_INTERVAL_S)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    # Failover/slot-count is decided from the prober's state, never
    # discovered inside a user's request — see services/ollama_probe.py.
    ollama_probe.start()
    asyncio.create_task(asyncio.to_thread(_warm_singletons))
    opencve_task = None
    if config.OPENCVE_SCHEDULED_REFRESH_ENABLED:
        opencve_task = asyncio.create_task(_opencve_scheduled_refresh_loop())
    try:
        yield
    finally:
        if opencve_task is not None:
            opencve_task.cancel()
        from routers.research import runs as research_runs
        from services.lab import provisioner
        await research_runs.close()
        await asyncio.to_thread(provisioner.cleanup_all)
        await ollama_probe.stop()
        await ollama_service.aclose_client()


app = FastAPI(
    title="Oyster Red Team API",
    version="3.0.0",
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # The frontend and the API are different origins, and neither header is
    # CORS-safelisted: without this a browser reads Retry-After as absent and
    # every "try again in N seconds" became "about 1 second".
    expose_headers=["Retry-After", "X-Oyster-Job", "X-Oyster-Model",
                    "X-Oyster-Policy-State", "X-Oyster-Policy-Replaced",
                    "X-Oyster-Response-Depth", "X-Oyster-Domain", "X-Oyster-Goal",
                    "X-Oyster-Target", "X-Oyster-Authorization", "X-Oyster-Capability",
                    "X-Oyster-Operational-Detail"],
)


# Anything that escaped every route. The body says only that we failed; the
# traceback goes to errors.jsonl. Starlette's default already hides the
# exception text — this keeps the JSON shape consistent and makes sure the
# cause is recorded where the operator looks, not lost in a container log.
@app.exception_handler(Exception)
async def _unhandled_error_handler(request: _StarletteRequest, exc: Exception):
    log_config.error(
        "unhandled",
        f"{type(exc).__name__}: {exc}",
        {"method": request.method, "path": request.url.path, "traceback": traceback.format_exc()},
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# Public — no auth. Healthchecks + the artifacts router (file/image/video/
# note upload, summarize, RAG-ask) — see routers/__init__.py for why the
# latter is deliberately open to anonymous visitors.
for _router in PUBLIC_ROUTERS:
    app.include_router(_router)

# Public chat surface — tier-gated inside its own route signatures
# (require_chat_access): anon 1/day, any verified account unlimited, admins
# full operator behavior.
for _router in TIERED_ROUTERS:
    app.include_router(_router)

# The workspace surface — any signed-in account, anonymous refused. Isolation
# is structural, not a gate: every route resolves its project from the caller's
# identity via services/project_context.py, so accounts cannot reach each
# other's scope, memories, settings or conversations. See routers/__init__.py
# for why these five, and not the rest.
for _router in ACCOUNT_ROUTERS:
    app.include_router(_router, dependencies=[Depends(require_account)])

# Everything else — admin-only, because it writes state shared by the whole
# instance or executes something (system, documents, rag, knowledge, datasets,
# findings, execution, evaluation, training).
for _router in PROTECTED_ROUTERS:
    app.include_router(_router, dependencies=_ADMIN_ONLY)

# Optional security KB — also admin-only.
if _KB_AVAILABLE and _kb_router is not None:
    app.include_router(_kb_router, prefix="/kb", tags=["security-kb"], dependencies=_ADMIN_ONLY)

# Sub-apps. mcp_router and agent_loop_router dispatch through the OLDER Phase 5
# MCP tool registry (network/API/security-test/AI-security/malware-analysis
# tools) — a separate surface from the Execution Engine that isn't covered by
# routers/execution.py's own router-level dependency. It has the same "can
# make this server issue real network requests" shape, so it shares the same
# kill-switch (config.EXECUTION_ENGINE_ENABLED) rather than being a second,
# forgotten hole once auth stops being the only thing gating it. memory_router
# is pure CRUD over the operator's own long-term recall — no tool execution —
# so it only needs the (currently inert while DISABLE_AUTH=true) admin gate.
app.include_router(
    mcp_router, prefix="/mcp", tags=["mcp"],
    dependencies=_ADMIN_ONLY + [Depends(require_execution_enabled)],
)
app.include_router(
    agent_loop_router, prefix="/agent", tags=["agent"],
    dependencies=_ADMIN_ONLY + [Depends(require_execution_enabled)],
)
app.include_router(memory_router, prefix="/memory", tags=["memory"], dependencies=_ADMIN_ONLY)

# ── Blue Team → SOC Copilot (vendored socmat workbench) ──────────────────────
# The socmat FastAPI app is mounted as a sub-app at /socmat/api. It keeps its
# own SQLAlchemy models/routers/integrations; Oyster only (1) forces its AI onto
# the local Ollama, (2) keeps its runtime state in Oyster's persisted DATA_DIR,
# and (3) gates + per-account-isolates it via the middleware below. socmat was
# single-tenant, so isolation is by the caller's Supabase `sub`: its get_db
# keys the SQLite file off request.state.socmat_owner (see
# socmat/services/api/database.py). Gated to any signed-in account, mirroring
# ACCOUNT_ROUTERS — anonymous is refused, exactly like Red Team.
os.environ.setdefault("AI_PROVIDER", "ollama")
os.environ.setdefault("OLLAMA_BASE_URL", config.OLLAMA_BASE_URL)
os.environ.setdefault("SOCMAT_DB_DIR", str(config.DATA_DIR / "socmat" / "userdbs"))
os.environ.setdefault("SOCMAT_UPLOAD_DIR", str(config.DATA_DIR / "socmat" / "uploads"))

# Imported defensively, exactly like the optional security KB above: socmat is
# a VENDORED sub-app, so a deploy whose image was built without it must still
# boot. It previously crashed the whole backend at import — one missing
# directory took the entire site down, including chat, findings and the API.
# An optional feature must degrade to "absent", never to "everything is down".
from services import auth_service as _auth  # noqa: E402

try:
    from socmat.services.api.main import app as _socmat_app
    _SOCMAT_AVAILABLE = True
except Exception as _socmat_exc:  # noqa: BLE001 — any import failure is non-fatal
    _socmat_app = None
    _SOCMAT_AVAILABLE = False
    print(f"  SOC Copilot: unavailable ({type(_socmat_exc).__name__}: {_socmat_exc})",
          file=sys.stderr)


@(_socmat_app.middleware("http") if _SOCMAT_AVAILABLE else (lambda f: f))
async def _socmat_gate(request: _StarletteRequest, call_next):
    """Verify the caller (like require_account) and stamp the per-account owner
    id used for DB isolation. Any signed-in account passes; anonymous is 401."""
    # CORS preflight carries no Authorization header — let it through so the
    # browser's cross-origin check succeeds before the real request.
    if request.method == "OPTIONS":
        return await call_next(request)
    if config.DISABLE_AUTH:
        request.state.socmat_owner = "dev-local"
        return await call_next(request)

    authz = request.headers.get("authorization", "")
    token = authz[7:].strip() if authz[:7].lower() == "bearer " else None
    if not token:
        return JSONResponse(
            {"detail": "Sign in to use this feature"}, status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        # Verification can block (a JWKS fetch on a key rotation, or the
        # first request after boot). Middleware runs on the event loop, so
        # it goes to the threadpool — the same place require_account's sync
        # dependency already runs.
        claims = await _run_in_threadpool(_auth._verify_supabase_token, token)
    except _auth.AuthServiceUnavailable:
        return JSONResponse({"detail": "Auth service temporarily unavailable"}, status_code=503,
                            headers={"Retry-After": _auth.AUTH_RETRY_AFTER})
    sub = (claims or {}).get("sub")
    if not claims or not sub:
        return JSONResponse(
            {"detail": "Not authenticated"}, status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
    request.state.socmat_owner = sub
    return await call_next(request)


if _SOCMAT_AVAILABLE and _socmat_app is not None:
    app.mount("/socmat/api", _socmat_app)

# Put the shared SQLite file into WAL mode BEFORE any schema work. WAL is a
# property of the database file (it persists), and it is what lets readers —
# the findings feed, chat history, the project switcher — carry on while
# someone else is writing, instead of the two colliding. Paired with the
# per-connection busy_timeout in services/db.py, a concurrent write now waits
# briefly rather than failing with "database is locked".
from services import db as _db  # noqa: E402

_journal_mode = _db.apply_startup_pragmas()
print(f"  SQLite     : journal_mode={_journal_mode} busy_timeout={_db.BUSY_TIMEOUT_MS}ms",
      file=sys.stderr)
# Say out loud WHERE generation will happen. Without this line, pointing Oyster
# at a second machine looks identical to not pointing it there: the .env is
# right, the app starts clean, and only a slow answer hints that nothing
# changed. (That is exactly how a docker-compose `environment:` entry silently
# overrode `env_file:` and kept generation on the small box.)
print(f"  Ollama     : {config.OLLAMA_BASE_URL}"
      + (f"  (fallback: {config.OLLAMA_FALLBACK_BASE_URL})"
         if config.OLLAMA_FALLBACK_BASE_URL else "  (no fallback configured)"),
      file=sys.stderr)
if _journal_mode.lower() != "wal":
    print(
        f"  SQLite     : WARNING expected WAL, got '{_journal_mode}' — concurrent "
        "writes may still fail with 'database is locked'",
        file=sys.stderr,
    )

# Persistent memory schema
memory_store.init_db()

# Project System schema + default project (must run after memory tables exist,
# since it backfills project_id onto them).
project_service.init_db()

# Conversation history schema (durable sidebar chats).
conversation_service.init_db()

# Per-account active-project pointer (private project switching).
from services import user_prefs as _user_prefs  # noqa: E402
_user_prefs.init_db()

# Per-user findings schema (saved chat messages + public share tokens).
from services import user_findings_service as _user_findings_service  # noqa: E402
_user_findings_service.init_db()

# Public nicknames ("User 7") for the findings feed. Runs after conversations
# and projects exist — its one-time backfill numbers accounts by first activity.
from services import user_profiles as _user_profiles  # noqa: E402
_user_profiles.init_db()

# Artifact ingestion schema (project-scoped uploads).
from services.artifacts import store as _artifact_store  # noqa: E402
_artifact_store.init_db()

# Knowledge Pack install-tracking schema (global, curated knowledge).
from services.knowledge import pack_service as _knowledge_service  # noqa: E402
_knowledge_service.init_db()

# Structured vulnerability knowledge (CISA KEV / NVD / EPSS / CWE / CAPEC).
# Schema only — no network call, no data fetch. Every sync is either an
# explicit admin-gated HTTP call or an explicit operator CLI invocation
# (services/knowledge/vulnerabilities/cli.py); nothing here runs automatically.
from services.knowledge.vulnerabilities import store as _vuln_store  # noqa: E402
_vuln_store.init_db()

# Structured NIST control-catalog knowledge (CSF 2.0 / SP 800-53 / SSDF).
# Same pattern: schema only here, sync is an explicit admin-gated HTTP call.
from services.knowledge.controls import store as _controls_store  # noqa: E402
_controls_store.init_db()

# Cross-source knowledge graph schema (nodes/edges/inconsistencies).
from services.knowledge.graph import store as _kg_store  # noqa: E402
_kg_store.init_db()

# Evaluation harness schema (eval runs + per-case results).
from services.evaluation import store as _eval_store  # noqa: E402
_eval_store.init_db()

# Execution Engine schema (proposals, executions, evidence, audit).
from services.execution import store as _execution_store  # noqa: E402
_execution_store.init_db()

# User Memory schema (long-term, per-project, encrypted-at-rest).
from services.user_memory import service as _user_memory_service  # noqa: E402
_user_memory_service.init_db()

# Dataset RAG schema (approved, licence-gated evaluation datasets).
from services.knowledge.datasets import store as _dataset_rag_store  # noqa: E402
_dataset_rag_store.init_db()

# Training pipeline schema (consent-gated LoRA, one isolated run at a time).
from services.training import store as _training_store  # noqa: E402
_training_store.init_db()

# Close out any job that was still live when this process last stopped. Training
# runs in a child process, so a "running" row at boot is definitionally dead —
# its worker went down with the previous process. Without this a crashed run
# stays "running" forever and the one-at-a-time guard would block every job after
# it. Never fatal: a reaper failure must not stop the server from booting.
try:
    _reaped = _training_store.reap_orphaned_jobs()
    if _reaped:
        print(f"  Training: marked {_reaped} orphaned job(s) as interrupted", file=sys.stderr)
except Exception as _reap_err:  # noqa: BLE001
    print(f"  Training: could not reap orphaned jobs ({_reap_err})", file=sys.stderr)

# Per-user training consent (opt-in; the only route a public user's chat can
# take into a dataset — see services/training/user_consent.py).
from services.training import user_consent as _user_consent  # noqa: E402
_user_consent.init_db()

# Per-caller attachment quota (see services/artifact_scope.py) — attachments
# are public, so the box must be able to say no.
from services import artifact_scope as _artifact_scope  # noqa: E402
_artifact_scope.init_db()

# SOC Copilot (socmat) — ensure the default owner DB exists and compile the
# global (file-based) YARA rules once. Per-account DBs initialise lazily on
# first request (socmat/services/api/database.py). Both are idempotent, so it
# is harmless if the mounted sub-app's own lifespan also runs them.
if _SOCMAT_AVAILABLE:
    try:
        from socmat.services.api.database import init_db as _socmat_init_db  # noqa: E402
        _socmat_init_db()
    except Exception as _socmat_db_err:  # noqa: BLE001 — degrade, never block boot
        print(f"  SOC Copilot: schema not initialised ({_socmat_db_err})", file=sys.stderr)
    try:
        from socmat.integrations.yara.loader import load_yara_rules as _socmat_load_yara  # noqa: E402
        _socmat_load_yara()
    except Exception as _socmat_yara_err:  # noqa: BLE001 — degrade, never block boot
        print(f"  SOC Copilot: YARA rules not loaded ({_socmat_yara_err})", file=sys.stderr)
