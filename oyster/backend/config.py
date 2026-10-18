"""Central configuration for the Oyster backend.

Single source of truth for paths, ports, hosts, the model registry, RAG /
embedding settings and log file locations. Every value is overridable via an
environment variable so nothing is hard-coded across the codebase.

This module is a *leaf*: it imports only the standard library so it can be
imported from anywhere without creating circular dependencies.
"""

from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Paths — anchored to this file so they resolve identically to the pre-refactor
# hard-coded constants (backend/ is the parent of this module).
# ---------------------------------------------------------------------------

BACKEND_DIR: Path = Path(__file__).resolve().parent
PROJECT_ROOT: Path = BACKEND_DIR.parent  # oyster/ — tools may read frontend files

DATA_DIR: Path = Path(_env("OYSTER_DATA_DIR", str(BACKEND_DIR / "data")))
LOGS_DIR: Path = Path(_env("OYSTER_LOGS_DIR", str(BACKEND_DIR / "logs")))
PROMPTS_DIR: Path = Path(_env("OYSTER_PROMPTS_DIR", str(BACKEND_DIR / "prompts")))
SCOPE_DIR: Path = Path(_env("OYSTER_SCOPE_DIR", str(BACKEND_DIR / "scope")))

UPLOAD_DIR: Path = DATA_DIR / "uploads"
VECTOR_DB_DIR: Path = Path(_env("OYSTER_VECTOR_DB_DIR", str(DATA_DIR / "vector_db")))
DOCUMENTS_JSON: Path = DATA_DIR / "documents.json"
EVIDENCE_JSON: Path = DATA_DIR / "evidence.json"
MEMORY_DB: Path = Path(_env("OYSTER_MEMORY_DB", str(DATA_DIR / "memory.db")))
SCOPE_FILE: Path = SCOPE_DIR / "engagement_scope.json"

# Security KB lives beside the backend package (optional, mounted if importable)
SECURITY_KB_DIR: Path = Path(_env("OYSTER_SECURITY_KB_DIR", str(PROJECT_ROOT / "security_kb")))

# Ensure the writable directories exist (safe, idempotent)
for _d in (DATA_DIR, LOGS_DIR, UPLOAD_DIR, SCOPE_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Networking — Ollama + service ports
# ---------------------------------------------------------------------------

OLLAMA_HOST: str = _env("OLLAMA_HOST", "localhost")
OLLAMA_PORT: int = _env_int("OLLAMA_PORT", 11434)
OLLAMA_BASE_URL: str = _env("OLLAMA_BASE_URL", f"http://{OLLAMA_HOST}:{OLLAMA_PORT}")
OLLAMA_GENERATE_URL: str = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL: str = f"{OLLAMA_BASE_URL}/api/tags"
# /api/chat, not /api/generate: chat sends a real messages[] array so Ollama
# applies the model's own chat template (role tags, stop tokens) instead of
# Oyster hand-formatting "User: .../Assistant: ..." text into a single raw
# prompt string, which a chat-tuned model reads as text to CONTINUE rather
# than a turn to answer — see oyster/docs/AI_HANDOFF.md 2026-09-30 for the
# incident this fixed (invented tools/commands, transcript leakage, lost
# follow-up context, all traced to that mismatch, not to the model itself).
OLLAMA_CHAT_URL: str = f"{OLLAMA_BASE_URL}/api/chat"
# A SECOND Ollama to fall back to when the first cannot be reached.
#
# Generation is the slowest thing Oyster does and this box is the weakest part
# of it, so the plan is to run Ollama on a much larger machine over a private
# Tailscale link. That machine is not a datacentre — it can sleep, or the home
# connection can drop — and "the fast box is asleep" must never mean "Oyster is
# down". Set this to the LOCAL Ollama so a failure degrades to slow rather than
# broken. Empty (the default) keeps the old single-endpoint behaviour exactly.
OLLAMA_FALLBACK_BASE_URL: str = _env("OLLAMA_FALLBACK_BASE_URL", "")
OLLAMA_FALLBACK_GENERATE_URL: str = (
    f"{OLLAMA_FALLBACK_BASE_URL}/api/generate" if OLLAMA_FALLBACK_BASE_URL else ""
)
OLLAMA_FALLBACK_CHAT_URL: str = (
    f"{OLLAMA_FALLBACK_BASE_URL}/api/chat" if OLLAMA_FALLBACK_BASE_URL else ""
)
# After the primary fails we stop trying it for this long, then probe it again —
# so a miniPC that wakes up is picked back up on its own, without a redeploy,
# but a sleeping one is not retried on every single request. Since the
# background prober exists this only governs the first seconds after boot
# (before its first round) and processes where it is not running.
OLLAMA_RETRY_PRIMARY_AFTER_S: int = _env_int("OYSTER_OLLAMA_RETRY_PRIMARY_AFTER_S", 30)
# The background prober (services/ollama_probe.py): GET /api/tags on every
# endpoint every PROBE_INTERVAL_S; an endpoint is "down" after FAILS_TO_DOWN
# consecutive failures and is then re-probed only every PROBE_DOWN_INTERVAL_S,
# so a blackholed node costs one short timeout a minute instead of one per
# user request.
OLLAMA_PROBE_INTERVAL_S: int = _env_int("OYSTER_OLLAMA_PROBE_INTERVAL_S", 15)
OLLAMA_PROBE_DOWN_INTERVAL_S: int = _env_int("OYSTER_OLLAMA_PROBE_DOWN_INTERVAL_S", 60)
OLLAMA_PROBE_CONNECT_S: float = float(_env("OYSTER_OLLAMA_PROBE_CONNECT_S", "2"))
OLLAMA_PROBE_FAILS_TO_DOWN: int = _env_int("OYSTER_OLLAMA_PROBE_FAILS_TO_DOWN", 2)
# Timeouts INSIDE a user's request. Connect is short because the prober has
# already decided which endpoint to try; it only ever fires when a node dies
# between two probe rounds. READ is the longest silence tolerated between two
# streamed chunks — a cold 8B load on CPU fits comfortably — and it is what
# stops a wedged generation from holding an Ollama permit forever.
# GENERATE bounds a NON-streaming call (RAG answers), which produces no bytes
# until it is completely finished.
OLLAMA_CONNECT_TIMEOUT_S: float = float(_env("OYSTER_OLLAMA_CONNECT_TIMEOUT_S", "3"))
OLLAMA_READ_TIMEOUT_S: float = float(_env("OYSTER_OLLAMA_READ_TIMEOUT_S", "180"))
OLLAMA_GENERATE_TIMEOUT_S: float = float(_env("OYSTER_OLLAMA_GENERATE_TIMEOUT_S", "600"))
# Thinking-capable models (Qwen3, DeepSeek-R1) spend their first tokens on a
# hidden monologue, which on CPU is time-to-first-token nobody sees. Off by
# default for chat; the prefixes say which model names get the flag.
OLLAMA_THINK: bool = _env("OYSTER_OLLAMA_THINK", "false").lower() in ("1", "true", "yes")
OLLAMA_THINKING_MODEL_PREFIXES: tuple[str, ...] = tuple(
    p.strip().lower()
    for p in _env("OYSTER_OLLAMA_THINKING_MODEL_PREFIXES", "oyster,qwen3,deepseek-r1,huihui").split(",")
    if p.strip()
)
# /health serves the prober's state; before its first round it runs one inline
# probe and caches the answer this long (routers/health.py).
HEALTH_CACHE_S: int = _env_int("OYSTER_HEALTH_CACHE_S", 10)

# CPU-performance knobs threaded into every Ollama call (services/
# ollama_service.py). keep_alive=-1 pins a model in RAM between requests — on a
# CPU-only VPS the cold reload (tens of seconds) otherwise dominates
# time-to-first-token for every visitor after an idle gap.
#
# KEEP_ALIVE applies ONLY to PUBLIC_CHAT_MODEL. KEEP_ALIVE_OTHER applies to
# every other model, and must stay FINITE. Pinning everything is what took the
# box down once: this VPS has 7.8 GB of RAM, and each model an operator used
# got pinned forever next to the public one (3B + 8B + 1B = 9.4 GB of weights
# resident), pushing 7 GB into swap and cutting generation to ~1 token/sec.
# Only one model can justify being permanently warm.
# num_thread 0 = let Ollama auto-detect cores.
OLLAMA_KEEP_ALIVE: str = _env("OYSTER_OLLAMA_KEEP_ALIVE", "-1")
OLLAMA_KEEP_ALIVE_OTHER: str = _env("OYSTER_OLLAMA_KEEP_ALIVE_OTHER", "5m")

# Chat queue (services/chat_queue.py). Generation throughput on this box is
# FLAT at ~8 tokens/sec no matter how many run at once — measured 2026-08-04:
# 1 caller 7.6 tok/s, 2 callers 4.3 each, 3 callers 2.7 each. Concurrency
# therefore buys nothing and only decides who waits vs who gets a slow answer,
# so we run 2 and queue the rest with a visible position.
# Raise CHAT_MAX_CONCURRENT (env, no redeploy) after a CPU upgrade.
CHAT_MAX_CONCURRENT: int = _env_int("OYSTER_CHAT_MAX_CONCURRENT", 2)
# Fairness: how many generations ONE account may have in flight at once. With
# only a couple of slots on the box, a single tab firing retries could hold
# every slot and the whole waiting line. At 1, nobody can crowd anyone out and
# the queue stays a queue of PEOPLE rather than of requests.
CHAT_MAX_PER_USER: int = _env_int("OYSTER_CHAT_MAX_PER_USER", 1)
# The TOTAL number of generations allowed to hit Ollama at once, from any
# source — chat, RAG, red-team panels, background memory extraction. Chat is
# already capped by CHAT_MAX_CONCURRENT, but everything else used to bypass it
# entirely and compete for the same cores. Defaults to the chat cap so the
# machine is never asked to do more than it can. See services/ollama_service.py.
OLLAMA_MAX_CONCURRENT: int = _env_int("OYSTER_OLLAMA_MAX_CONCURRENT", CHAT_MAX_CONCURRENT)

# ---------------------------------------------------------------------------
# The same two ceilings, but PER NODE.
#
# Which machine serves a generation changes at runtime (services/ollama_probe.py):
# this box's own Ollama runs one slot, the desktop inference node is configured
# for four. One static number is therefore wrong for whichever node is not
# serving — pinned low, the fast node is wasted; pinned high, the slow one
# reproduces the 2026-09-14 incident, where surplus callers stopped queueing
# VISIBLY and instead sat inside Ollama's own queue emitting zero bytes until
# OLLAMA_READ_TIMEOUT_S killed them. That is precisely the failure
# services/chat_queue.py exists to prevent ("they paid the wait AND got
# nothing"), so the limit has to follow the node rather than the deploy.
#
# All four default to the static values above, so behaviour is identical until
# one is set deliberately.
#
# DO NOT raise the *_PRIMARY values until the primary node's real
# OLLAMA_NUM_PARALLEL has been read off that machine's own server log. A
# Windows node started from the tray app instead of its configured service
# runs Ollama's default of ONE slot, and assuming four would recreate the
# incident there instead of here.
# ---------------------------------------------------------------------------
OLLAMA_MAX_CONCURRENT_PRIMARY: int = _env_int(
    "OYSTER_OLLAMA_MAX_CONCURRENT_PRIMARY", OLLAMA_MAX_CONCURRENT)
OLLAMA_MAX_CONCURRENT_FALLBACK: int = _env_int(
    "OYSTER_OLLAMA_MAX_CONCURRENT_FALLBACK", OLLAMA_MAX_CONCURRENT)
CHAT_MAX_CONCURRENT_PRIMARY: int = _env_int(
    "OYSTER_CHAT_MAX_CONCURRENT_PRIMARY", CHAT_MAX_CONCURRENT)
CHAT_MAX_CONCURRENT_FALLBACK: int = _env_int(
    "OYSTER_CHAT_MAX_CONCURRENT_FALLBACK", CHAT_MAX_CONCURRENT)


def effective_max_concurrent(via: str | None) -> int:
    """Total generations allowed on the node serving right now.

    ``via`` is ``services.ollama_probe.live_via()`` — "primary", "fallback",
    or None when the prober has no opinion yet (not started, first round not
    finished, or the standalone checks, which never start it). None keeps the
    static ceiling, so nothing changes before the prober speaks.

    Passed in as an argument rather than read here: ollama_probe imports this
    module, so config must never import it back.
    """
    if via == "primary":
        return max(1, OLLAMA_MAX_CONCURRENT_PRIMARY)
    if via == "fallback":
        return max(1, OLLAMA_MAX_CONCURRENT_FALLBACK)
    return max(1, OLLAMA_MAX_CONCURRENT)


def effective_chat_concurrent(via: str | None) -> int:
    """How many CHATS may generate at once on the node serving right now.

    Capped by the node's total ceiling as well: chat shares the machine with
    RAG, the red-team panels and background memory extraction, so it must
    never be admitted beyond what the whole box is allowed to run.
    """
    if via == "primary":
        base = CHAT_MAX_CONCURRENT_PRIMARY
    elif via == "fallback":
        base = CHAT_MAX_CONCURRENT_FALLBACK
    else:
        base = CHAT_MAX_CONCURRENT
    return min(max(1, base), effective_max_concurrent(via))


# The queue depth is DERIVED from this, not hard-coded: promising someone a
# place in a 30-minute line is worse than telling them to come back.
CHAT_MAX_QUEUE_WAIT_S: int = _env_int("OYSTER_CHAT_MAX_QUEUE_WAIT_S", 300)
# A job nobody is watching any more (closed tab) is dropped before it burns a
# slot — the scarcest resource here must not be spent on an absent user.
CHAT_JOB_DETACH_GRACE_S: int = _env_int("OYSTER_CHAT_JOB_DETACH_GRACE_S", 90)
# Finished jobs stay readable this long so a refresh can still collect the
# answer; then they are reaped.
CHAT_JOB_RETENTION_S: int = _env_int("OYSTER_CHAT_JOB_RETENTION_S", 600)
# How long a streaming view may stay silent before it sends a keepalive frame.
# Waiting in line and a model's cold load both produce no bytes at all, and a
# proxy with an idle timeout in front of the API (Cloudflare severs at 100 s)
# reads that silence as a dead connection. 20 s keeps a comfortable margin.
CHAT_STREAM_HEARTBEAT_S: int = _env_int("OYSTER_CHAT_STREAM_HEARTBEAT_S", 20)
# Wall clock on one generation. Nothing bounded a RUNNING job before: with a
# silent model it held a slot and an Ollama permit for ever. 600 s is about
# three times a long answer on this box; past it the job ends with the
# timeout sentence and the slot is released.
CHAT_JOB_MAX_RUNTIME_S: int = _env_int("OYSTER_CHAT_JOB_MAX_RUNTIME_S", 600)
# A RUNNING job nobody has watched for this long is cancelled by the reaper —
# a closed tab used to burn the whole generation and, because of
# CHAT_MAX_PER_USER, lock its owner out with 429 until it finished. Longer
# than CHAT_JOB_DETACH_GRACE_S on purpose: a phone backgrounded mid-answer
# must be able to come back and resume.
CHAT_RUNNING_DETACH_GRACE_S: int = _env_int("OYSTER_CHAT_RUNNING_DETACH_GRACE_S", 180)
# How often the reaper wakes (tests shrink it).
CHAT_REAPER_INTERVAL_S: float = float(_env("OYSTER_CHAT_REAPER_INTERVAL_S", "10"))
# A token whose signing key is not in the cached JWKS forces a re-fetch of
# the key set; this is how often that may happen, so a flood of bad tokens
# cannot turn into a flood of fetches.
JWKS_KID_MISS_COOLOFF_S: int = _env_int("OYSTER_JWKS_KID_MISS_COOLOFF_S", 30)

# ── Conversation-history context (follow-up questions) ──────────────────────
# Basic /chat was stateless — every turn was answered from the single prompt with
# no memory of the conversation, so follow-ups ("and the second one?", "fix it")
# landed with no context. The client now sends the prior turns and the router
# threads a trimmed transcript into the prompt. The window (OLLAMA_NUM_CTX, now
# 8192 tokens in the served config) is shared between system prompt + history +
# question + answer, so the history is BUDGETED, most-recent-first: keep at most
# CHAT_HISTORY_MAX_TURNS messages and CHAT_HISTORY_MAX_CHARS characters, dropping
# the oldest. Anonymous chat stays historyless (no stored context, lean prefill).
# Both env-overridable.
#
# The char budget was 4000 (~1000 tokens), sized for a long-gone 4096-ctx build.
# With the system prompt at ~1100 tokens and num_ctx at 8192, that left most of
# the window unused and silently dropped the *referenced* turn in ordinary
# multi-turn chats — e.g. a 6-turn conversation where "what was the first thing I
# asked?" fell outside the kept window, and the model confabulated an answer
# instead of recalling it (demonstrated 2026-10-13; see the Oyster-vs-Ollama
# comparison in AI_HANDOFF.md). 16000 chars (~4000 tokens) keeps far more history
# while staying well inside 8192 with room for the system prompt and the answer.
CHAT_HISTORY_MAX_TURNS: int = _env_int("OYSTER_CHAT_HISTORY_MAX_TURNS", 12)
CHAT_HISTORY_MAX_CHARS: int = _env_int("OYSTER_CHAT_HISTORY_MAX_CHARS", 16000)
# A safety cap keyed to OLLAMA_NUM_CTX is applied once that is defined below
# (search for _HISTORY_CHAR_CAP), so history can never crowd the window out.

# ── Priority access (sold by VoiceIQ, honoured here) ────────────────────────
# Red Orca sells "priority access to Oyster" on its paid plans. Oyster has its
# own database and cannot see VoiceIQ's `subscriptions` table, so it ASKS —
# services/entitlements.py forwards the caller's own Supabase token to
# VoiceIQ's GET /billing/entitlements. Empty URL = feature off, everyone
# ordinary: the queue must work perfectly with no billing API in existence.
BILLING_API_URL: str = _env("OYSTER_BILLING_API_URL", "").rstrip("/")
# SHORT. This sits in front of a chat request, so the worst case is a delay the
# user feels. 1.5s is generous for a single indexed lookup and small enough
# that a hung billing API is an annoyance rather than an outage.
BILLING_TIMEOUT_S: float = float(_env("OYSTER_BILLING_TIMEOUT_S", "1.5"))
# A plan does not change between two messages. Caching for minutes turns "one
# HTTP call per chat" into "one per user per 5 minutes"; the cost of being
# stale is that someone who just subscribed waits a few minutes for their lane.
BILLING_CACHE_TTL_S: int = _env_int("OYSTER_BILLING_CACHE_TTL_S", 300)
# After a failure we stop asking for this long. Without it, a billing API that
# is DOWN (not slow) would still cost every single chat request its full
# timeout — turning someone else's outage into our latency.
BILLING_FAILURE_COOLOFF_S: int = _env_int("OYSTER_BILLING_FAILURE_COOLOFF_S", 60)
# Hard ceiling on cached identities, so the cache cannot become a slow leak.
BILLING_CACHE_MAX: int = _env_int("OYSTER_BILLING_CACHE_MAX", 2000)
# THE ANTI-STARVATION KNOB. A priority job may jump ahead of ordinary jobs, but
# only those that have been waiting less than this. Past it, an ordinary job can
# never be overtaken again, which is what bounds its wait (see
# services/chat_queue.py::_enqueue). Set to 0 to disable overtaking entirely.
CHAT_PRIORITY_MAX_OVERTAKE_S: int = _env_int("OYSTER_CHAT_PRIORITY_MAX_OVERTAKE_S", 60)

# ---------------------------------------------------------------------------
# Upload limits — the disk is the resource most likely to run out.
# ---------------------------------------------------------------------------
# Counting uploads does NOT bound bytes: 20 uploads of 100 MB is still 2 GB.
# So there are three independent limits, and an upload must satisfy all of them:
#
#   1. per-file size      (MAX_VIDEO_SIZE_MB / MAX_IMAGE_SIZE_MB, above)
#   2. per-caller TOTAL   (…_MAX_STORAGE_MB, below) — the one that actually
#                          caps how much of the disk any one account can own
#   3. free-space floor   (MIN_FREE_DISK_GB) — a global backstop that holds
#                          even if the per-caller maths is wrong, because the
#                          failure it prevents (disk full) takes the whole box
#                          down, not just uploads
#
# Measured 2026-08-04: 96 GB disk, ~27 GB free. Operators are exempt from 1-2
# but NOT from 3 — nobody gets to fill the disk.
ANON_DAILY_UPLOADS: int = _env_int("OYSTER_ANON_DAILY_UPLOADS", 5)
USER_DAILY_UPLOADS: int = _env_int("OYSTER_USER_DAILY_UPLOADS", 20)
ANON_MAX_STORAGE_MB: int = _env_int("OYSTER_ANON_MAX_STORAGE_MB", 100)
USER_MAX_STORAGE_MB: int = _env_int("OYSTER_USER_MAX_STORAGE_MB", 500)
MIN_FREE_DISK_GB: float = float(_env("OYSTER_MIN_FREE_DISK_GB", "5"))
OLLAMA_NUM_THREAD: int = _env_int("OYSTER_OLLAMA_NUM_THREAD", 0)
OLLAMA_NUM_CTX: int = _env_int("OYSTER_OLLAMA_NUM_CTX", 2048)
OLLAMA_NUM_BATCH: int = _env_int("OYSTER_OLLAMA_NUM_BATCH", 64)
# The 27B Huihui model shares a 24 GB unified-memory Mac with macOS, the
# frontend/backend and the reranker, so it gets its own, smaller window than
# the 8B models until memory has been measured (see redbears/docs/MODELS.md).
HUIHUI_NUM_CTX: int = _env_int("OYSTER_HUIHUI_NUM_CTX", 4096)

# Cap the chat history budget to what the context window can actually hold, so
# history never crowds out the system prompt + current turn + answer regardless
# of how OLLAMA_NUM_CTX is set. Reserve ~2800 tokens for those; give the rest to
# history at ~4 chars/token. With num_ctx 8192 the cap is ~21.5k chars (the
# 16000 default stands); a small window shrinks it automatically.
_HISTORY_CHAR_CAP = max(1200, (OLLAMA_NUM_CTX - 2800) * 4)
CHAT_HISTORY_MAX_CHARS = min(CHAT_HISTORY_MAX_CHARS, _HISTORY_CHAR_CAP)

BACKEND_PORT: int = _env_int("OYSTER_BACKEND_PORT", 8001)
FRONTEND_PORT: int = _env_int("OYSTER_FRONTEND_PORT", 3001)

_cors_default = f"http://localhost:{FRONTEND_PORT},http://127.0.0.1:{FRONTEND_PORT}"
CORS_ORIGINS: list[str] = [
    o.strip()
    for o in _env("OYSTER_CORS_ORIGINS", _cors_default).split(",")
    if o.strip()
]


# ---------------------------------------------------------------------------
# Model registry — the ONE source of truth for available models.
#
#   key         -> the identifier used by the API / frontend
#   ollama      -> the actual model name passed to Ollama
#   label       -> human-friendly name
#   role        -> primary use ("chat" | "reasoning")
# ---------------------------------------------------------------------------

MODEL_REGISTRY: dict[str, dict] = {
    "oyster-1x":        {"ollama": "oyster-1x",       "label": "Oyster-1X",       "role": "chat"},
    # 2026-09-30 — genuinely transformed (refusal-ablated) Dolphin 3.0 Llama 3.1
    # 8B. Source dphn/Dolphin3.0-Llama3.1-8B @ f065677...007a0 (license
    # llama3.1); 64 nonzero tensor deltas (all 32 self_attn.o_proj + 32
    # mlp.down_proj), strength 0.65, Q4_K_M; Ollama digest b6e5d24c7da0. The
    # ablation removes the MODEL's own refusals, so the catastrophic-harm and
    # real-target boundaries are enforced at the application layer
    # (services/chat_policy.py) — see oyster/docs/AI_HANDOFF.md 2026-09-30 and
    # the model lab integration handoff. NOT abliteration-as-alias: real
    # transformed weights.
    "oyster-dolphin-v1": {"ollama": "oyster-dolphin-v1-q4", "label": "Oyster Dolphin V1 (transformed)", "role": "chat"},
    # 2026-10-08 — V2: the same refusal-ablated Dolphin 3.0 Llama 3.1 8B lineage
    # as V1, carried one generation further (11 nonzero o_proj deltas, layers
    # 21..31), then EXPORTED TO GGUF (convert_hf_to_gguf + llama-quantize
    # Q4_K_M) so it serves on the fast llama.cpp runner like V1 — NOT the
    # experimental MLX safetensors artifact (oyster-dolphin-v2-q4), which ran
    # ~1.85x slower (13.8 vs 25.5 tok/s) for the same weights. GGUF reports the
    # true 8.03B params; the MLX build's "2.4B" was a packed-shape counting
    # artifact (same 291-tensor set, verified). Held-out gate (96 cases, direct
    # Ollama) at parity with V1 (same 11 uncertainty misses + 1 baited
    # fabrication, 0 refuse/leak/empty; V1 had 1 transient empty) and equal/
    # better latency. Catastrophic-harm + real-target boundaries stay enforced
    # at the app layer (services/chat_policy.py). Ollama digest: see handoff.
    "oyster-dolphin-v2": {"ollama": "oyster-dolphin-v2-gguf-q4", "label": "Oyster Dolphin V2 (transformed, GGUF)", "role": "chat"},
    # 2026-10-18 (Red Bears hackathon) — UPSTREAM model integrated into Oyster,
    # NOT an Oyster-transformed model: huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF
    # (Apache-2.0; base Qwen/Qwen3.8-27B, GGUF arch qwen35), file
    # Huihui-Qwen3.8-27B-abliterated-<variant>.gguf @ HF rev 1c69098e...da07da89e.
    # Served through Ollama; the Oyster V2 entry above stays the default/fallback.
    # Provenance + checksum: redbears/docs/MODELS.md.
    "huihui-qwen3.8-27b": {"ollama": _env("OYSTER_HUIHUI_OLLAMA_TAG", "huihui-qwen3.8-27b-abliterated-ud-iq3xxs"),
                           "label": "Huihui Qwen3.8 27B abliterated (upstream)", "role": "chat"},
    # 2026-09-30 — the Oyster Edge (Q4/F16, 0.8B, qwen3.5-based) lineage failed
    # the quality gates in oyster/docs/AI_HANDOFF.md (invented tools/commands,
    # wrong technical facts, e.g. "16-bit MAC address" and fabricated CLI
    # flags) once conversation-handling bugs were ruled out as the cause —
    # confirmed by comparison against its own F16 source and against
    # dolphin3:latest. It is NOT Oyster's default; kept available, honestly
    # labelled, for anyone who wants the small/fast experimental model anyway.
    "oyster-edge-v1-q4": {"ollama": "oyster-edge-v1-q4", "label": "Oyster Edge V1 Q4 (experimental, lightweight)", "role": "chat"},
    "oyster-edge-v1-q4-v2": {"ollama": "oyster-edge-v1-q4-v2", "label": "Oyster Edge V1 Q4 v2 (experimental, lightweight)", "role": "chat"},
    "oyster-edge-v1-q4-v3": {"ollama": "oyster-edge-v1-q4-v3", "label": "Oyster Edge V1 Q4 v3 (experimental, lightweight)", "role": "chat"},
    # The small model is FIRST and is what signed-in accounts default to.
    # It was previously reachable only as PUBLIC_CHAT_MODEL (a raw Ollama
    # name outside this registry), so the picker could not offer it and every
    # signed-in account pulled a ~5 GB 8B instead. On a 7.8 GB box that does
    # not fit beside the pinned 2.5 GB public model: Ollama evicted one to
    # load the other, and a real signed-in chat failed mid-load under the
    # pressure. Heavier models stay available — they are now a deliberate
    # choice rather than the silent default.
    "llama3.2-3b":     {"ollama": "llama3.2:3b",    "label": "Llama 3.2 3B",    "role": "chat"},
    "dolphin3":        {"ollama": "dolphin3",       "label": "Dolphin 3",       "role": "chat"},
    "dolphin-mistral": {"ollama": "dolphin-mistral", "label": "Dolphin Mistral", "role": "chat"},
    "dolphin-llama3":  {"ollama": "dolphin-llama3",  "label": "Dolphin Llama 3", "role": "chat"},
    "hermes":          {"ollama": "nous-hermes2",    "label": "Nous Hermes 2",   "role": "chat"},
    "deepseek-r1":     {"ollama": "deepseek-r1",     "label": "DeepSeek R1",     "role": "reasoning"},
    # 2026-10-04 — Oyster's deep-reasoning engine, now running LOCALLY. On the
    # old 7.8 GB box this 9 GB model did not fit and lived only on the Tailscale
    # inference node (`requires_node`); on the current 24 GB Apple M5 it runs on
    # the GPU at ~9.5 GB resident. Benchmarked (tests/quality_eval_live.py, 101
    # cases) tied with oyster-dolphin-v1 on the mechanical gate (0 errors/leaks,
    # same single baited fabrication) but ~2.8× slower (16.4 s vs 5.8 s avg) and
    # NOT refusal-ablated, so it stays the selectable "Reasoning" option rather
    # than the interactive default (that remains oyster-dolphin-v1). License:
    # Apache-2.0. Production must `ollama pull qwen2.5:14b` for this option to
    # work there — see oyster/docs/AI_HANDOFF.md.
    "qwen-14b":        {"ollama": "qwen2.5:14b",     "label": "Qwen 2.5 14B",
                        "role": "reasoning"},
}

# key -> ollama name (mirrors the pre-refactor AVAILABLE_MODELS dict exactly)
AVAILABLE_MODELS: dict[str, str] = {k: v["ollama"] for k, v in MODEL_REGISTRY.items()}

DEFAULT_MODEL: str = _env("OYSTER_DEFAULT_MODEL", "oyster-1x")
REASONING_MODEL: str = _env("OYSTER_REASONING_MODEL", "deepseek-r1")


def resolve_model(key: str, default_key: str | None = None) -> str:
    """Resolve an API model key to its Ollama model name.

    Mirrors the historic ``AVAILABLE_MODELS.get(key, AVAILABLE_MODELS[DEFAULT])``
    behaviour: unknown keys fall back to ``default_key`` (or ``DEFAULT_MODEL``).
    """
    fallback = default_key or DEFAULT_MODEL
    return AVAILABLE_MODELS.get(key, AVAILABLE_MODELS[fallback])


def model_list() -> list[dict]:
    """Serialisable list for the ``/models`` endpoint."""
    return [{"key": k, "ollama_name": v["ollama"], "label": v["label"], "role": v["role"]}
            for k, v in MODEL_REGISTRY.items()]


# ---------------------------------------------------------------------------
# RAG / embeddings
# ---------------------------------------------------------------------------

EMBED_MODEL: str = _env("OYSTER_EMBED_MODEL", "all-MiniLM-L6-v2")
RAG_COLLECTION: str = _env("OYSTER_RAG_COLLECTION", "oyster_docs")
CHUNK_SIZE: int = _env_int("OYSTER_CHUNK_SIZE", 800)
CHUNK_OVERLAP: int = _env_int("OYSTER_CHUNK_OVERLAP", 100)

MAX_UPLOAD_BYTES: int = _env_int("OYSTER_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)  # 50 MB

# ---------------------------------------------------------------------------
# Artifact ingestion (project-scoped uploads)
# ---------------------------------------------------------------------------

ARTIFACTS_DIR: Path = DATA_DIR / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# Text-family extensions extracted by safe decode (chardet-assisted).
TEXT_EXTENSIONS: set[str] = {
    ".txt", ".md", ".markdown", ".rst", ".log", ".json", ".jsonl", ".csv", ".tsv",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".xml", ".html", ".htm",
    ".css", ".sql", ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rb",
    ".php", ".c", ".h", ".cpp", ".hpp", ".cc", ".cs", ".rs", ".swift", ".m", ".scala",
    ".pl", ".lua", ".r", ".dart", ".vue", ".svelte", ".dockerfile", ".gradle", ".make",
}
PDF_EXTENSIONS: set[str] = {".pdf"}
DOCX_EXTENSIONS: set[str] = {".docx"}

# All extensions the artifact "Upload Files" pipeline accepts.
ARTIFACT_ALLOWED_EXTENSIONS: set[str] = TEXT_EXTENSIONS | PDF_EXTENSIONS | DOCX_EXTENSIONS

# Folder upload guardrails
MAX_FOLDER_FILES: int = _env_int("OYSTER_MAX_FOLDER_FILES", 800)
MAX_FOLDER_BYTES: int = _env_int("OYSTER_MAX_FOLDER_BYTES", 250 * 1024 * 1024)  # 250 MB
MAX_ARTIFACT_TEXT_CHARS: int = _env_int("OYSTER_MAX_ARTIFACT_TEXT_CHARS", 400_000)

# Project-artifact retrieval (pure vector) over-fetches this multiple of top_k,
# then re-ranks with an exact-identifier boost so a doc that contains a query's
# literal IP/CVE/version (which embeddings separate poorly) is lifted into the
# returned top_k — fixes the reproduced miss where near-identical docs differing
# only by an IP returned the wrong one. Boost is additive, bounded (×≤3), and
# only fires on digit-bearing/id tokens, so ordinary queries are unchanged.
ARTIFACT_RETRIEVAL_OVERFETCH: int = _env_int("OYSTER_ARTIFACT_RETRIEVAL_OVERFETCH", 4)
ARTIFACT_EXACT_TOKEN_BOOST: float = float(_env("OYSTER_ARTIFACT_EXACT_TOKEN_BOOST", "0.12"))


# ---------------------------------------------------------------------------
# Media artifacts (image + video) — all processing is LOCAL:
#   images  → Pillow (metadata/thumbnail/EXIF) + optional Tesseract OCR + Ollama VLM
#   video   → ffmpeg/ffprobe (metadata/thumbnail/frames/audio) + faster-whisper
#             (local transcription) + Ollama VLM on sampled frames
# Nothing is sent to a cloud API.
# ---------------------------------------------------------------------------

# Ollama vision-language model used for image + video-frame understanding.
# Chosen after machine inspection (Apple M5 / 24 GB) — see CLAUDE.md. Kept
# SEPARATE from the chat model so routing stays: chat→dolphin, vision→VISION_MODEL.
VISION_MODEL: str = _env("OYSTER_VISION_MODEL", "qwen2.5vl:7b")
# Fallbacks tried (in order) if VISION_MODEL is not present in `ollama list`.
VISION_MODEL_FALLBACKS: list[str] = [
    m.strip() for m in _env(
        "OYSTER_VISION_MODEL_FALLBACKS", "qwen2.5vl:3b,llava:7b,llava:latest"
    ).split(",") if m.strip()
]

# OCR engine: "auto" (Tesseract if installed, else the VLM reads text itself),
# "tesseract", or "none" (rely on VLM visible_text only).
OCR_ENGINE: str = _env("OYSTER_OCR_ENGINE", "auto")

# Scanned / image-only PDF OCR fallback. A PDF whose text layer yields fewer
# than PDF_OCR_MIN_TEXT_CHARS characters is treated as a scan: its pages are
# rasterized (poppler via pdf2image) and run through Tesseract. Bounded so a
# huge scanned PDF can't monopolize the CPU box. A normal text PDF is never
# rasterized (its text layer is far larger than the threshold).
PDF_OCR_MIN_TEXT_CHARS: int = _env_int("OYSTER_PDF_OCR_MIN_TEXT_CHARS", 64)
PDF_OCR_MAX_PAGES: int = _env_int("OYSTER_PDF_OCR_MAX_PAGES", 20)
PDF_OCR_DPI: int = _env_int("OYSTER_PDF_OCR_DPI", 200)
# Explicit binary locations for OCR when the service PATH is minimal (launchd).
# Empty => resolve from PATH / Homebrew / MacPorts prefixes (see services/media/ocr.py).
TESSERACT_CMD: str = _env("OYSTER_TESSERACT_CMD", "")
POPPLER_BIN: str = _env("OYSTER_POPPLER_BIN", "")

# Local speech transcription (faster-whisper). Model size trades speed/accuracy.
WHISPER_MODEL: str = _env("OYSTER_WHISPER_MODEL", "base")
WHISPER_COMPUTE_TYPE: str = _env("OYSTER_WHISPER_COMPUTE_TYPE", "int8")

# Image limits / thumbnail
IMAGE_EXTENSIONS: set[str] = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tiff", ".svg"}
IMAGE_MIME_PREFIXES: tuple[str, ...] = ("image/",)
MAX_IMAGE_SIZE_MB: int = _env_int("OYSTER_MAX_IMAGE_SIZE_MB", 25)
IMAGE_THUMBNAIL_SIZE: int = _env_int("OYSTER_IMAGE_THUMBNAIL_SIZE", 512)

# Video limits / sampling
VIDEO_EXTENSIONS: set[str] = {".mp4", ".mov", ".webm", ".mkv", ".m4v", ".avi"}
VIDEO_MIME_PREFIXES: tuple[str, ...] = ("video/",)
# 500 MB was set when uploads were operator-only. Attachments are public now,
# and a 500 MB ceiling meant one signed-in account could write 50 GB in a day
# against ~27 GB of free disk. 100 MB still covers any realistic screen
# recording or evidence clip.
MAX_VIDEO_SIZE_MB: int = _env_int("OYSTER_MAX_VIDEO_SIZE_MB", 100)
MAX_VIDEO_DURATION_SECONDS: int = _env_int("OYSTER_MAX_VIDEO_DURATION_SECONDS", 1800)  # 30 min
VIDEO_FRAME_INTERVAL_SECONDS: int = _env_int("OYSTER_VIDEO_FRAME_INTERVAL_SECONDS", 20)
VIDEO_MAX_FRAMES: int = _env_int("OYSTER_VIDEO_MAX_FRAMES", 24)
VIDEO_PROCESSING_TIMEOUT_SECONDS: int = _env_int("OYSTER_VIDEO_PROCESSING_TIMEOUT_SECONDS", 1800)

# Media extensions the media pipeline accepts (kept distinct from text files).
MEDIA_ALLOWED_EXTENSIONS: set[str] = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS


# ---------------------------------------------------------------------------
# Knowledge Packs — curated, versioned, GLOBAL built-in cybersecurity knowledge.
# Each pack is a folder under KNOWLEDGE_PACKS_DIR with a pack.json manifest and
# one or more Markdown docs. Installing a pack chunks+embeds its docs into a
# dedicated Chroma collection with source attribution. The LLM reasons over this
# retrieved knowledge — it is not asked to be the database.
# ---------------------------------------------------------------------------

KNOWLEDGE_PACKS_DIR: Path = Path(_env("OYSTER_KNOWLEDGE_PACKS_DIR", str(BACKEND_DIR / "knowledge_packs")))
KNOWLEDGE_COLLECTION: str = _env("OYSTER_KNOWLEDGE_COLLECTION", "oyster_knowledge")

# Registries (disabled-by-default provider/lab/adversarial definitions) live as
# versioned JSON under this dir. They are DEFINITIONS ONLY — nothing is ingested,
# downloaded, or executed from them without explicit, separately-approved action.
KNOWLEDGE_REGISTRIES_DIR: Path = Path(
    _env("OYSTER_KNOWLEDGE_REGISTRIES_DIR", str(BACKEND_DIR / "knowledge_registries"))
)

# ---------------------------------------------------------------------------
# Hybrid retrieval (Knowledge Service)
#   final answer context is capped to a char budget; vector + lexical (FTS5)
#   results are fused (reciprocal-rank fusion) then re-weighted by source
#   trust + freshness, deduped, and diversified across packs.
# ---------------------------------------------------------------------------

KNOWLEDGE_CONTEXT_BUDGET_CHARS: int = _env_int("OYSTER_KNOWLEDGE_CONTEXT_BUDGET_CHARS", 6000)
KNOWLEDGE_DEFAULT_TOP_K: int = _env_int("OYSTER_KNOWLEDGE_TOP_K", 6)
KNOWLEDGE_CANDIDATE_POOL: int = _env_int("OYSTER_KNOWLEDGE_CANDIDATE_POOL", 24)
# Reciprocal-rank-fusion constant and the vector/lexical blend weights.
KNOWLEDGE_RRF_K: int = _env_int("OYSTER_KNOWLEDGE_RRF_K", 60)
KNOWLEDGE_VECTOR_WEIGHT: float = float(_env("OYSTER_KNOWLEDGE_VECTOR_WEIGHT", "1.0"))
# 2026-09-15: raised 0.8->1.0 after a parameter sweep on the development suite
# (retrieval_dev_v1.json, tuned independently of the historical 118-case
# suite) showed it neutral there (91.67% either way) while genuinely
# improving historical MRR (0.8427->0.8441, pass_rate unchanged at 97.46%) --
# a small, honestly-supported change, not one selected to maximize the
# historical score alone. A lexical-favored 0.9/1.0 split was also tried and
# was WORSE on the dev suite (88.89%, down from 91.67%) and rejected.
KNOWLEDGE_LEXICAL_WEIGHT: float = float(_env("OYSTER_KNOWLEDGE_LEXICAL_WEIGHT", "1.0"))
# Max chunks kept from any single pack before diversity fills the rest.
# 2026-09-15: lowered 3->2 after the accuracy diagnostic showed a single large,
# topically-broad pack (azure-security-docs-src, 0.6-0.7 similarity on almost
# any generic security query) consuming 3 of a top_k=5 window by itself,
# crowding out smaller topically-precise packs that were genuinely present
# deeper in the fused candidate pool (verified: generic-privesc-linux and
# generic-ransomware-response both went from failing to passing on the
# historical suite; new-domains and follow-up suites unaffected). A cap of 1
# was also tested and rejected on purpose despite scoring 100% on the
# historical suite -- it would force every real answer needing 2+ supporting
# chunks from the same source to lose one, which the eval doesn't measure
# but production quality depends on.
KNOWLEDGE_MAX_PER_PACK: int = _env_int("OYSTER_KNOWLEDGE_MAX_PER_PACK", 2)

# --- Surrounding-document context expansion ---------------------------------
# Ingest slices each document into ~800-char chunks, so a single retrieved chunk
# routinely ends mid-sentence and drops the rest of a command or procedure (a
# baseline probe found 63% of returned passages truncated mid-sentence). After
# selection, each citation's passage is stitched back together with the chunks
# that immediately surround it in the SAME document (same pack_id + doc_id, so
# source attribution and project isolation are preserved), nearest-neighbour
# first, bounded by a separate expanded-context budget. radius=0 disables it.
KNOWLEDGE_NEIGHBOR_RADIUS: int = _env_int("OYSTER_KNOWLEDGE_NEIGHBOR_RADIUS", 1)
# Ceiling for the stitched references block. Tuned 2026-10-07 from 11000 down
# to 8000 after an A/B on 8 identical questions on the same warm model: expansion
# at 11k raised fact-marker correctness 0.875->0.938 but cost +18% latency
# (14.4s->17.0s mean) on this 2-core CPU box. 8000 keeps a meaningful completeness
# gain (~+45% evidence vs an unexpanded ~5.5k) while trimming the latency the
# extra context added, rather than buying marginal correctness with every
# available character. Still well within num_ctx=8192 (~28k chars incl.
# generation), leaving room for the system instruction, history and the answer.
KNOWLEDGE_EXPAND_BUDGET_CHARS: int = _env_int("OYSTER_KNOWLEDGE_EXPAND_BUDGET_CHARS", 8000)

# --- Nemotron evidence reranking (Red Bears) ----------------------------------
# After hybrid retrieval, a cross-encoder (nvidia/llama-nemotron-rerank-1b-v2)
# rescoring query/passage pairs picks which retrieved passages reach the answer
# model. It is a RERANKER, not a chat/reasoning model. Speaks the NVIDIA NIM
# reranking schema (POST /v1/ranking). Any failure falls back to the existing
# retrieval order and says so (services/rerank_service.py).
# The NVIDIA-hosted endpoint for this model returned HTTP 410 (end-of-life
# 2026-08-25) when checked on 2026-10-18, so the default is the local server in
# redbears/rerank_server. Point NEMOTRON_RERANK_URL at a NIM to use that instead.
NEMOTRON_RERANK_ENABLED: bool = _env("NEMOTRON_RERANK_ENABLED", "true").lower() in ("1", "true", "yes")
NEMOTRON_RERANK_URL: str = _env("NEMOTRON_RERANK_URL", "http://127.0.0.1:8110/v1/ranking")
NEMOTRON_RERANK_MODEL: str = _env("NEMOTRON_RERANK_MODEL", "nvidia/llama-nemotron-rerank-1b-v2")
# Bearer token; only needed for NVIDIA-hosted / NIM endpoints that require one.
# Server-side only: never returned to the browser, never logged.
NVIDIA_API_KEY: str = _env("NVIDIA_API_KEY", "")
# Optional bearer for a self-run / private rerank endpoint (rerank_server's
# RERANK_SERVER_TOKEN). Deliberately separate from NVIDIA_API_KEY: the NVIDIA
# key is only ever sent to *.nvidia.com hosts, never to a local or third-party URL.
NEMOTRON_RERANK_API_KEY: str = _env("NEMOTRON_RERANK_API_KEY", "")
# Spending/abuse cap for any NON-local rerank endpoint (hosted NIM is metered):
# max rerank calls per UTC day, per process. 0 = block all remote calls.
NEMOTRON_RERANK_DAILY_CALL_LIMIT: int = _env_int("NEMOTRON_RERANK_DAILY_CALL_LIMIT", 500)
# Per-caller limit on the streaming knowledge endpoint (requests per minute).
KNOWLEDGE_STREAM_RATE_PER_MIN: int = _env_int("OYSTER_KNOWLEDGE_STREAM_RATE_PER_MIN", 12)
NEMOTRON_RERANK_TIMEOUT_S: float = float(_env("NEMOTRON_RERANK_TIMEOUT_S", "15"))
NEMOTRON_RERANK_CANDIDATES: int = _env_int("NEMOTRON_RERANK_CANDIDATES", 16)
NEMOTRON_RERANK_PASSAGE_CHARS: int = _env_int("NEMOTRON_RERANK_PASSAGE_CHARS", 1800)

# --- Investigation integrations (Red Bears) -----------------------------------
# Three SEPARATE providers, each with its own role. None of these is the
# Nemotron reranker above — that stays a cross-encoder with no generative role.
#
# 1) Nemotron REASONING — a generative chat model, used for research planning,
#    evidence analysis and investigation coordination (structured decision
#    summaries), via NVIDIA/Nebius Token Factory's OpenAI-compatible API.
#    Base URL + model id verified against docs.tokenfactory.nebius.com
#    2026-10-18: POST {base}/chat/completions, GET {base}/models.
NEBIUS_TOKEN_FACTORY_BASE_URL: str = _env(
    "NEBIUS_TOKEN_FACTORY_BASE_URL", "https://api.tokenfactory.nebius.com/v1")
# No credential on this machine as of 2026-10-18 (checked: not in env, shell
# profiles, or any .env file). Leave empty -> adapter reports "not_configured".
NEBIUS_API_KEY: str = _env("NEBIUS_API_KEY", "")
# Nebius model ids use a publisher prefix (e.g. "nvidia/..."); the exact
# Nemotron reasoning id must be read from GET {base}/models at connect time —
# model availability changes, and guessing one here would be exactly the
# "invented endpoint" the brief says not to do. Settable as an override once
# confirmed against a real account's model list.
NEMOTRON_REASONING_MODEL: str = _env("NEMOTRON_REASONING_MODEL", "")
NEBIUS_TIMEOUT_S: float = float(_env("NEBIUS_TIMEOUT_S", "30"))

# 2) Tavily — current web research, source extraction, follow-up search.
# Verified 2026-10-18 against docs.tavily.com: POST https://api.tavily.com/search
# and /extract, `Authorization: Bearer tvly-...`.
TAVILY_BASE_URL: str = _env("TAVILY_BASE_URL", "https://api.tavily.com")
TAVILY_API_KEY: str = _env("TAVILY_API_KEY", "")
TAVILY_TIMEOUT_S: float = float(_env("TAVILY_TIMEOUT_S", "20"))
# Juice Shop solutions/walkthroughs must never enter research retrieval (brief
# §5) — enforced as a domain blocklist on every Tavily call, not a prompt
# instruction. Add any domain hosting Juice Shop writeups if one is found.
TAVILY_EXCLUDE_DOMAINS: tuple[str, ...] = tuple(
    d.strip() for d in _env(
        "TAVILY_EXCLUDE_DOMAINS",
        "github.com/juice-shop,pwning-owasp-juice-shop.helmesjo.net,"
        "bkimminich.gitbooks.io,owasp-juice.shop",
    ).split(",") if d.strip()
)

# 3) Devin — code investigation + proposed fixes for VERIFIED findings only.
# Verified 2026-10-18 against docs.devin.ai: current API is v3,
# POST https://api.devin.ai/v3/organizations/{org_id}/sessions, Bearer key
# prefixed "cog_". Legacy v1 (apk_/apk_user_ keys) is deprecated and NOT used
# here. No credential, org id, or allowed repo is configured on this machine —
# the adapter must report not_configured and this implementation never starts
# a session on its own; a human reviews the evidence package first.
DEVIN_BASE_URL: str = _env("DEVIN_BASE_URL", "https://api.devin.ai")
DEVIN_API_KEY: str = _env("DEVIN_API_KEY", "")
DEVIN_ORG_ID: str = _env("DEVIN_ORG_ID", "")
# Allowlist of "owner/repo" Devin may ever be pointed at. Empty = Devin cannot
# be used at all, regardless of credentials — there is no default repo.
DEVIN_ALLOWED_REPOS: tuple[str, ...] = tuple(
    r.strip() for r in _env("DEVIN_ALLOWED_REPOS", "").split(",") if r.strip()
)
DEVIN_TIMEOUT_S: float = float(_env("DEVIN_TIMEOUT_S", "20"))

# --- Investigation lab (isolated Juice Shop) ----------------------------------
# Disposable instances of OWASP Juice Shop, pinned to one release, used ONLY as
# the scenario catalogue's target. No production system, real credential, or
# host resource is ever reachable from inside a lab instance (services/lab).
LAB_JUICE_SHOP_DIR: str = _env(
    "LAB_JUICE_SHOP_DIR", str(Path.home() / "redbears-assets" / "lab" / "juice-shop-src"))
LAB_JUICE_SHOP_VERSION: str = _env("LAB_JUICE_SHOP_VERSION", "v20.2.0")
# Pinned commit for the above tag (git rev-parse v20.2.0^{}, verified against
# the upstream repo 2026-10-18) — the provisioner refuses to use a checkout
# whose HEAD does not match this, so a silently-moved tag or a dirty checkout
# cannot change what scenarios run against.
LAB_JUICE_SHOP_COMMIT: str = _env(
    "LAB_JUICE_SHOP_COMMIT", "5658473cf8814459bf89000ce373b20ed0b4eb37")
LAB_PORT_RANGE_START: int = _env_int("LAB_PORT_RANGE_START", 31100)
LAB_PORT_RANGE_END: int = _env_int("LAB_PORT_RANGE_END", 31199)
LAB_MAX_INSTANCES: int = _env_int("LAB_MAX_INSTANCES", 2)
LAB_INSTANCE_TTL_S: int = _env_int("LAB_INSTANCE_TTL_S", 1800)
LAB_BOOT_TIMEOUT_S: float = float(_env("LAB_BOOT_TIMEOUT_S", "60"))
# Enforced OUTSIDE the model: a macOS sandbox profile (sandbox-exec) denies the
# lab process network egress other than its own loopback port, and file access
# other than its own working copy. See services/lab/sandbox.py. If sandbox-exec
# (or an equivalent on the deploy OS) is unavailable, LAB_ENABLED forces false
# at boot — execution stays disabled rather than falling back to an
# unrestricted host process.
LAB_ENABLED: bool = _env("LAB_ENABLED", "true").lower() in ("1", "true", "yes")

# --- OpenCVE (read-only CVE catalog; Security Intel "Latest intelligence") --
# Verified against the live OpenAPI v2 schema at
# https://app.opencve.io/api/v2/schema/?format=json (2026-10-18) — see
# services/integrations/opencve.py's module docstring for exactly which paths
# and params that schema confirms. API v1 is deprecated per docs.opencve.io and
# is not used.
OPENCVE_BASE_URL: str = _env("OPENCVE_BASE_URL", "https://app.opencve.io/api/v2")
# Organisation API token: "opc_org.<token_id>.<secret>" (OrganizationBearerAuth
# in the schema). Left empty until a real token is configured — the adapter
# reports "not_configured" rather than guessing one exists.
OPENCVE_API_TOKEN: str = _env("OPENCVE_API_TOKEN", "")
OPENCVE_TIMEOUT_S: float = float(_env("OPENCVE_TIMEOUT_S", "20"))
OPENCVE_PAGE_SIZE: int = _env_int("OPENCVE_PAGE_SIZE", 20)  # schema max is 100
# Cache lives outside git (REDBEARS_ASSETS), like the knowledge index.
OPENCVE_CACHE_PATH: str = _env(
    "OPENCVE_CACHE_PATH", str(Path.home() / "redbears-assets" / "data" / "opencve_feed_cache.json"))
OPENCVE_CACHE_MAX_ENTRIES: int = _env_int("OPENCVE_CACHE_MAX_ENTRIES", 200)
# A CVE whose OpenCVE created_at/updated_at falls within this window of "now"
# is shown as newly-published / recently-modified respectively (see
# services/intel/opencve_feed.py — these are OpenCVE catalog timestamps, not
# NVD publishedDate/lastModifiedDate, which the v2 schema does not expose).
OPENCVE_RECENT_WINDOW_S: int = _env_int("OPENCVE_RECENT_WINDOW_S", 7 * 86400)
# Disabled until deliberately enabled (brief: "configurable and disabled until
# deliberately enabled"). When true, a background task refreshes the cache
# every OPENCVE_SCHEDULED_REFRESH_INTERVAL_S; see app.py's startup hook. Never
# exercised against a live feed on this machine (no credential).
OPENCVE_SCHEDULED_REFRESH_ENABLED: bool = _env("OPENCVE_SCHEDULED_REFRESH_ENABLED", "false").lower() in ("1", "true", "yes")

# Fallback for the same "Latest intelligence" feed when OpenCVE has no token
# configured (its hosted API requires auth — verified live: GET /cves with no
# bearer returns 401 {"error":{"code":"not_authenticated",...}}). Reuses the
# same public CISA KEV JSON (config.KEV_FEED_URL, already used by the
# knowledge-base ingestion pipeline) but keeps its own cache file, since this
# UI feed's refresh cadence/shape is independent of that pipeline's sync job.
KEV_INTEL_CACHE_PATH: str = _env(
    "KEV_INTEL_CACHE_PATH", str(Path.home() / "redbears-assets" / "data" / "kev_intel_feed_cache.json"))
OPENCVE_SCHEDULED_REFRESH_INTERVAL_S: int = _env_int("OPENCVE_SCHEDULED_REFRESH_INTERVAL_S", 3600)

# --- Second-stage lexical reranker ------------------------------------------
# A bounded rescorer applied to the fused candidates BEFORE the exact-identifier
# boosts (so an exact CVE/ATT&CK/LOLBAS match still wins): it nudges up a
# candidate that covers MORE of the query's distinct content terms and contains
# query bigrams as exact phrases — signal that neither cosine similarity (bag of
# meaning) nor bm25 (bag of words, no phrase/coverage) captures directly. The
# factor is in [1.0, 1+RERANK_WEIGHT], so it only ever reorders near-ties and
# can never override trust/freshness or an exact-id injection. 0 disables it.
KNOWLEDGE_RERANK_WEIGHT: float = float(_env("OYSTER_KNOWLEDGE_RERANK_WEIGHT", "0.35"))

# Trust levels for a source (higher = weighted up in fusion). Packs declare a
# `trust_level`; unknown → "community".
KNOWLEDGE_TRUST_WEIGHTS: dict[str, float] = {
    "official": 1.00,     # vendor/standards body (OWASP, NIST, MITRE, Kali)
    "authoritative": 0.92,
    "community": 0.80,    # curated community wikis (HackTricks, GTFOBins)
    "unverified": 0.60,
}

# Risk classification for knowledge content. High-risk (payloads / active
# exploitation) is separated from ordinary guidance and gated behind scope +
# approval before any *tool* can act on it (the knowledge itself is read-only).
KNOWLEDGE_RISK_LEVELS: tuple[str, ...] = ("informational", "low", "medium", "high", "critical")

# ---------------------------------------------------------------------------
# Source Connectors — real ingestion of authorized upstream sources.
#   A connector acquires (git clone / archive / api / local), licence-validates,
#   normalizes, prompt-injection-scans, and MATERIALIZES an on-disk Knowledge
#   Pack, which then flows through the existing pack_service install pipeline.
#   Nothing is executed; imported content is untrusted DATA only. Every source
#   is an explicitly approved profile — there is no unrestricted web scraper.
# ---------------------------------------------------------------------------

# Working dir for transient source acquisition (shallow clones / downloads).
# Cleaned after each import; never served and never on the retrieval path.
KNOWLEDGE_CONNECTOR_WORKDIR: Path = Path(
    _env("OYSTER_KNOWLEDGE_CONNECTOR_WORKDIR", str(DATA_DIR / "knowledge_src"))
)
# Resource limits so an import can never exhaust the machine.
KNOWLEDGE_CONNECTOR_MAX_FILES: int = _env_int("OYSTER_KNOWLEDGE_CONNECTOR_MAX_FILES", 4000)
KNOWLEDGE_CONNECTOR_MAX_FILE_BYTES: int = _env_int("OYSTER_KNOWLEDGE_CONNECTOR_MAX_FILE_BYTES", 1_048_576)
KNOWLEDGE_CONNECTOR_MAX_TOTAL_BYTES: int = _env_int("OYSTER_KNOWLEDGE_CONNECTOR_MAX_TOTAL_BYTES", 64_000_000)
KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT: int = _env_int("OYSTER_KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT", 240)
KNOWLEDGE_CONNECTOR_NET_TIMEOUT: int = _env_int("OYSTER_KNOWLEDGE_CONNECTOR_NET_TIMEOUT", 30)

# ---------------------------------------------------------------------------
# Vulnerability Knowledge — CISA KEV, NVD CVE, FIRST EPSS, MITRE CWE, MITRE
# CAPEC, merged by CVE/CWE/CAPEC id (see services/knowledge/vulnerabilities/).
# Own dedicated Chroma collection so hundreds of thousands of terse CVE chunks
# never dilute general Knowledge Pack retrieval. The NVD API key, if any, is
# read from the environment only (never written, never logged, never read from
# a .env file directly) — its absence just means the conservative unauthenticated
# rate limit applies; nothing requires it to be present.
# ---------------------------------------------------------------------------

KNOWLEDGE_VULN_COLLECTION: str = _env("OYSTER_KNOWLEDGE_VULN_COLLECTION", "oyster_vulnerabilities")

# NVD CVE API 2.0 — https://nvd.nist.gov/developers/vulnerabilities
NVD_API_BASE_URL: str = _env("OYSTER_NVD_API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_RESULTS_PER_PAGE: int = _env_int("OYSTER_NVD_RESULTS_PER_PAGE", 2000)
NVD_WINDOW_DAYS: int = _env_int("OYSTER_NVD_WINDOW_DAYS", 120)  # NVD's hard per-call max
# Conservative: NVD documents 5 req/30s unauthenticated (=6.0s/req), 50 req/30s
# with a key (=0.6s/req). We pad both slightly rather than cut them exactly.
NVD_MIN_REQUEST_INTERVAL_NO_KEY_S: float = float(_env("OYSTER_NVD_MIN_REQUEST_INTERVAL_NO_KEY_S", "6.5"))
NVD_MIN_REQUEST_INTERVAL_WITH_KEY_S: float = float(_env("OYSTER_NVD_MIN_REQUEST_INTERVAL_WITH_KEY_S", "0.7"))
NVD_MAX_RETRIES: int = _env_int("OYSTER_NVD_MAX_RETRIES", 4)
NVD_NET_TIMEOUT_S: int = _env_int("OYSTER_NVD_NET_TIMEOUT_S", 30)
# Per-CVE attempts across separate enrich-kev *runs* (not the in-request retry
# above) before a persistently-failing lookup is marked permanently
# unavailable instead of being retried forever on every resume.
NVD_MAX_BACKFILL_ATTEMPTS: int = _env_int("OYSTER_NVD_MAX_BACKFILL_ATTEMPTS", 5)

# CISA CSAF — production incremental synchronizer. No fixed advisory cap: a
# run walks the full ROLIE feed index, skipping advisories whose feed
# `updated` timestamp hasn't changed since the last successful fetch (the
# resume/checkpoint mechanism), so a second run over an unchanged corpus does
# almost no network I/O. Bounded instead by wall-clock time and concurrency.
CISA_CSAF_MAX_CONCURRENCY: int = _env_int("OYSTER_CISA_CSAF_MAX_CONCURRENCY", 6)
CISA_CSAF_MAX_RETRIES: int = _env_int("OYSTER_CISA_CSAF_MAX_RETRIES", 4)
CISA_CSAF_MAX_RUNTIME_S: int = _env_int("OYSTER_CISA_CSAF_MAX_RUNTIME_S", 3600)

# CISA KEV — single JSON catalog, self-throttled rather than hammered.
KEV_FEED_URL: str = _env(
    "OYSTER_KEV_FEED_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
KEV_MIN_SYNC_INTERVAL_S: int = _env_int("OYSTER_KEV_MIN_SYNC_INTERVAL_S", 3600)

# FIRST EPSS — daily bulk CSV snapshot (redirects to the dated file).
EPSS_BULK_URL: str = _env("OYSTER_EPSS_BULK_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
EPSS_SCORE_EPSILON: float = float(_env("OYSTER_EPSS_SCORE_EPSILON", "0.0001"))

# MITRE CWE / CAPEC — single bulk downloads, refreshed in full but diffed
# per-record by content hash (cheap at CWE/CAPEC scale, unlike NVD).
CWE_CATALOG_URL: str = _env("OYSTER_CWE_CATALOG_URL", "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip")
CAPEC_CATALOG_URL: str = _env("OYSTER_CAPEC_CATALOG_URL", "https://capec.mitre.org/data/xml/capec_latest.xml")

# Storage-bounding caps (a single CVE's NVD payload can otherwise be huge).
# Ceiling on any single upstream feed download. These are third-party files that
# grow without asking us (NVD's bundle is already ~51 MB), and the fetchers buffer
# a whole response in memory inside a container capped at 3 GB that also serves
# chat. 192 MB is comfortably above every current feed and far below the point
# where a surprise costs anyone their session.
VULN_MAX_DOWNLOAD_BYTES: int = _env_int("OYSTER_VULN_MAX_DOWNLOAD_BYTES", 192 * 1024 * 1024)
VULN_MAX_REFERENCES_STORED: int = _env_int("OYSTER_VULN_MAX_REFERENCES_STORED", 15)
VULN_MAX_CPE_MATCHES_STORED: int = _env_int("OYSTER_VULN_MAX_CPE_MATCHES_STORED", 50)


# ---------------------------------------------------------------------------
# Response disclaimer footer — an operator-responsibility notice appended to
# offensive-security answers. This is a liability/authorization reminder, NOT a
# safety gate: the real boundary stays the deterministic Execution Engine.
# ---------------------------------------------------------------------------

# The footer is opt-in. It made ordinary answers read like a compliance notice
# and duplicated the conversational policy layer; deployments that require it
# can enable it explicitly with OYSTER_RESPONSE_DISCLAIMER_ENABLED=true.
RESPONSE_DISCLAIMER_ENABLED: bool = _env("OYSTER_RESPONSE_DISCLAIMER_ENABLED", "false").lower() in ("1", "true", "yes")
RESPONSE_DISCLAIMER_TEXT: str = _env(
    "OYSTER_RESPONSE_DISCLAIMER_TEXT",
    "— Authorization notice: you are responsible for ensuring you have explicit, "
    "written authorization for any system you act on. Use this only within an "
    "approved scope, lab, or engagement. Team Red Orca and Oyster provide this "
    "information for authorized security work and accept no liability for actions "
    "you take outside that authorization.",
)


# ---------------------------------------------------------------------------
# User Memory — long-term, per-project, encrypted-at-rest memory extracted from
# conversations (facts/preferences/decisions/instructions). Separate from the
# agent's session-scoped scratch memory (backend/memory/) and separate from RAG
# document/knowledge retrieval. This is context recall, never model training —
# see services/training/ for the distinct, consent-gated, disabled-by-default
# fine-tuning pipeline.
# ---------------------------------------------------------------------------

USER_MEMORY_COLLECTION: str = _env("OYSTER_USER_MEMORY_COLLECTION", "oyster_user_memory")
# Encryption key for memory content at rest. If unset, a key is generated on
# first use and persisted (0600) at MEMORY_KEY_FILE — never logged, never sent
# anywhere. Overridable so an operator can supply/rotate a key out-of-band.
MEMORY_ENCRYPTION_KEY: str | None = os.getenv("OYSTER_MEMORY_ENCRYPTION_KEY")
MEMORY_KEY_FILE: Path = DATA_DIR / ".memory_key"
# Cosine-similarity threshold above which a new candidate memory is treated as
# referring to the same subject as an existing one (update/dedup vs. new fact).
MEMORY_DEDUP_THRESHOLD: float = float(_env("OYSTER_MEMORY_DEDUP_THRESHOLD", "0.86"))
MEMORY_RETRIEVAL_TOP_K: int = _env_int("OYSTER_MEMORY_RETRIEVAL_TOP_K", 5)
MEMORY_EXTRACTION_MODEL: str = _env("OYSTER_MEMORY_EXTRACTION_MODEL", DEFAULT_MODEL)

# ---------------------------------------------------------------------------
# Dataset RAG — approved, licence-gated cybersecurity Q&A/instruction datasets
# ingested as a SEPARATE, clearly-labeled, evaluation-grounding collection.
# Distinct from curated Knowledge Packs (authoritative docs) and from project
# artifacts (user uploads). Governance lives in knowledge_registries/datasets.json;
# a dataset is only ever fetched once its own registry entry is marked
# rag_eligible + reviewed. Nothing here trains anything.
# ---------------------------------------------------------------------------

DATASET_RAG_COLLECTION: str = _env("OYSTER_DATASET_RAG_COLLECTION", "oyster_dataset_eval")
DATASET_MAX_ROWS: int = _env_int("OYSTER_DATASET_MAX_ROWS", 2000)
DATASET_HF_PAGE_SIZE: int = _env_int("OYSTER_DATASET_HF_PAGE_SIZE", 100)
DATASET_NET_TIMEOUT: int = _env_int("OYSTER_DATASET_NET_TIMEOUT", 30)

# ---------------------------------------------------------------------------
# Training pipeline — completely separate from RAG/memory. Disabled by default;
# requires explicit per-project opt-in consent. Only opted-in conversation/memory
# content may enter it; registry datasets and non-opted-in projects never do
# (enforced in code via services/evaluation/datasets_gate.assert_training_forbidden
# equivalents, not prose). The actual LoRA training step requires torch/
# transformers/peft; if they are not installed it honestly reports "unavailable"
# rather than fabricating a run — the same pattern used for nmap/semgrep in the
# Execution Engine.
# ---------------------------------------------------------------------------

TRAINING_DIR: Path = DATA_DIR / "training"
TRAINING_ADAPTERS_DIR: Path = TRAINING_DIR / "adapters"
TRAINING_DATASETS_DIR: Path = TRAINING_DIR / "datasets"
TRAINING_BASE_MODEL_HF_ID: str = _env("OYSTER_TRAINING_BASE_MODEL_HF_ID", "cognitivecomputations/dolphin-2.9-llama3-8b")
TRAINING_MIN_EXAMPLES: int = _env_int("OYSTER_TRAINING_MIN_EXAMPLES", 20)
TRAINING_VAL_SPLIT: float = float(_env("OYSTER_TRAINING_VAL_SPLIT", "0.1"))
TRAINING_TEST_SPLIT: float = float(_env("OYSTER_TRAINING_TEST_SPLIT", "0.1"))

# --- Training safety rails ---------------------------------------------------
# Added after an audit found that starting a job would load a ~16GB model into a
# 3GB container, OOM-killing uvicorn itself (a SIGKILL no ``except`` can catch),
# taking the API down and stranding the job row at "running" forever.
#
# ENABLED defaults TRUE on purpose: the owner's instruction was to keep training
# available and make it safe, not to switch it off. This is a kill-switch for an
# emergency, not a default-off gate — same shape as EXECUTION_ENGINE_ENABLED.
TRAINING_ENABLED: bool = _env("OYSTER_TRAINING_ENABLED", "true").lower() in ("1", "true", "yes")
# Ceiling the preflight enforces regardless of what the container allows, so a
# huge model is refused even on an unconstrained host.
TRAINING_MAX_MODEL_BYTES: int = _env_int("OYSTER_TRAINING_MAX_MODEL_BYTES", 24 * (1 << 30))
# Used only when the parameter count cannot be read from the model id.
TRAINING_DEFAULT_PARAMS: float = float(_env("OYSTER_TRAINING_DEFAULT_PARAMS", "7e9"))
# Wall-clock ceiling for one run. The codebase's own scripts call training
# "possibly hours", so this is generous — it exists to stop a wedged run, not to
# cut a healthy one short.
TRAINING_MAX_RUNTIME_S: int = _env_int("OYSTER_TRAINING_MAX_RUNTIME_S", 12 * 3600)
TRAINING_MAX_SEQ_LEN: int = _env_int("OYSTER_TRAINING_MAX_SEQ_LEN", 1024)
# Fail closed: an adapter whose post-training refusal probe did not pass cannot
# be approved for deployment. The probe was previously computed and ignored.
TRAINING_REQUIRE_SAFETY_PASS: bool = _env("OYSTER_TRAINING_REQUIRE_SAFETY_PASS", "true").lower() in ("1", "true", "yes")

for _d in (TRAINING_DIR, TRAINING_ADAPTERS_DIR, TRAINING_DATASETS_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Log file names (channel -> filename); consumed by log_config.py
# ---------------------------------------------------------------------------

LOG_FILES: dict[str, str] = {
    "audit":  "audit.log",
    "tools":  "tool_calls.jsonl",
    "agent":  "agent.jsonl",
    "memory": "memory.jsonl",
    "errors": "errors.jsonl",
}

# ---------------------------------------------------------------------------
# Deployment environment + auth — Oyster was built for one local operator with
# zero authentication. Any deployment reachable over a network (the Hostinger
# VPS, redorca.tech/oyster) MUST gate every route behind Supabase auth, and
# MUST restrict access to an explicit admin allow-list — this is a
# single-operator security tool, not a multi-tenant SaaS product. See
# services/auth_service.py for the verification logic and the production boot
# guard at the bottom of this file for the fail-closed check.
# ---------------------------------------------------------------------------

ENVIRONMENT: str = _env("OYSTER_ENVIRONMENT", "development")

# Local-dev convenience bypass — every request runs unauthenticated. Defaults
# true so `uvicorn main:app` still "just works" out of the box on a laptop.
# MUST be false in production (enforced below).
DISABLE_AUTH: bool = _env("OYSTER_DISABLE_AUTH", "true").lower() in ("1", "true", "yes")

# Same Supabase project already used by the Dolphin/VoiceIQ product — Oyster
# only ever VERIFIES the JWT Supabase issues; it never sees a password and the
# service_role key is used nowhere. New Supabase projects sign asymmetrically
# (verified via JWKS, only SUPABASE_URL needed); legacy projects sign HS256
# with the project JWT secret (SUPABASE_JWT_SECRET).
SUPABASE_URL: str = _env("OYSTER_SUPABASE_URL", "")
SUPABASE_JWT_SECRET: str = _env("OYSTER_SUPABASE_JWT_SECRET", "")
SUPABASE_AUD: str = _env("OYSTER_SUPABASE_AUD", "authenticated")
SUPABASE_JWKS_TTL_S: int = _env_int("OYSTER_SUPABASE_JWKS_TTL_S", 600)

# The allow-list. A verified Supabase token whose email is not in this set gets
# 403, regardless of how it was obtained — sign-up in Supabase is NOT enough to
# reach Oyster. Comma-separated, case-insensitive.
ADMIN_EMAILS: set[str] = {
    e.strip().lower() for e in _env("OYSTER_ADMIN_EMAILS", "").split(",") if e.strip()
}

# Kill-switch for the Execution Engine (real tool execution against
# self-declared "in scope" targets — see services/execution/). Recommended
# default for a public deployment is false: ship chat/RAG/knowledge live and
# turn this on later once it's being operated deliberately. routers/execution.py
# enforces this for every route in that router.
EXECUTION_ENGINE_ENABLED: bool = _env("OYSTER_EXECUTION_ENGINE_ENABLED", "true").lower() in ("1", "true", "yes")

# ── Public chat tiers ───────────────────────────────────────────────────────
# /chat (and ONLY /chat, plus /me) is open to the public: anonymous callers
# get a small daily allowance keyed by client IP; any verified Supabase
# account gets unlimited chat. Admins additionally keep memory injection and
# free model choice. Every other router keeps the admin allow-list gate —
# opening chat does not widen the execution/mcp/agent/knowledge surface.
PUBLIC_CHAT_ENABLED: bool = _env("OYSTER_PUBLIC_CHAT_ENABLED", "true").lower() in ("1", "true", "yes")
ANON_CHAT_DAILY_LIMIT: int = _env_int("OYSTER_ANON_CHAT_DAILY_LIMIT", 1)
# Model for non-operator chat. MEASURED on the 2-core VPS: an 8B model gives
# ~65s time-to-first-token — unusable for a public landing experience — while
# a 3B model answers in a few seconds. Operators keep the full 8B set (they
# accept the wait for depth); the public gets responsiveness. Set to a key in
# MODEL_REGISTRY, or empty to fall back to DEFAULT_MODEL.
PUBLIC_CHAT_MODEL: str = _env("OYSTER_PUBLIC_CHAT_MODEL", "llama3.2:3b")
# Ollama models kept resident between requests (keep_alive -1); everything
# else expires after OLLAMA_KEEP_ALIVE_OTHER. Default: the public chat model
# and the signed-in default — the two that answer nearly every request. Raw
# Ollama names, comma-separated. Their weights plus KV cache must fit the RAM
# rule in deploy/HARDENING.md (about 9 GB on the 15 GB VPS); pinning more is
# how the box once fell into swap at ~1 token/sec.
OLLAMA_PINNED_MODELS: frozenset[str] = frozenset(
    m.strip() for m in _env("OYSTER_OLLAMA_PINNED_MODELS", "").split(",") if m.strip()
) or frozenset({PUBLIC_CHAT_MODEL, AVAILABLE_MODELS.get(DEFAULT_MODEL, DEFAULT_MODEL)})
# Prompt-size ceiling for non-admin callers: a giant prompt is pure CPU
# prefill cost on this box. Admins are uncapped.
ANON_CHAT_MAX_PROMPT_CHARS: int = _env_int("OYSTER_ANON_CHAT_MAX_PROMPT_CHARS", 4000)

# 2026-09-16: ported from main (this branch never had it). services/
# ollama_service.py's pinning logic used to check `model == PUBLIC_CHAT_MODEL`
# only -- DEFAULT_MODEL (dolphin3, what the actual security-chat path in
# security_answer.py / pack_service.py generates with, the one exercised by
# nearly every interactive request) was never in the always-warm set, so a
# chat session more than OLLAMA_KEEP_ALIVE_OTHER (5m) apart paid a full cold
# model load, not just an idle Ollama. Raw Ollama names, comma-separated;
# defaults to the two models that answer nearly every request. Weights plus
# KV cache for everything pinned must fit available RAM -- pinning too much
# is how a box falls into swap (see OLLAMA_KEEP_ALIVE's own comment above).
OLLAMA_PINNED_MODELS: frozenset[str] = frozenset(
    m.strip() for m in _env("OYSTER_OLLAMA_PINNED_MODELS", "").split(",") if m.strip()
) or frozenset({PUBLIC_CHAT_MODEL, AVAILABLE_MODELS.get(DEFAULT_MODEL, DEFAULT_MODEL)})


# ---------------------------------------------------------------------------
# MCP Gateway — the governed Model Context Protocol server that exposes a
# CURATED, safe subset of Oyster's knowledge and tools to external AI clients
# (Claude Code, VS Code, and — over the HTTP transport — a future ChatGPT
# connector). It is a SEPARATE surface from the older /mcp REST facade and the
# Execution Engine: it reuses the same service layer (knowledge retrieval,
# vulnerability store, project isolation and the Execution Engine's approval
# pipeline) but never exposes raw shell, unrestricted files, or a database
# session. Every value here is env-driven so nothing machine-specific is baked
# into the code or the committed client templates. See backend/mcp_gateway/.
# ---------------------------------------------------------------------------

# Master kill-switch, same shape as EXECUTION_ENGINE_ENABLED. When false the
# gateway refuses every tool call (protocol handshake still answers so a client
# gets a clean "disabled" message rather than a dead socket).
MCP_GATEWAY_ENABLED: bool = _env("OYSTER_MCP_ENABLED", "true").lower() in ("1", "true", "yes")

# HTTP (Streamable HTTP) transport bind. Loopback by default — a laptop must
# never expose this to the network without an explicit, deliberate change and a
# TLS-terminating reverse proxy in front (see docs/MCP_GATEWAY.md).
MCP_HTTP_HOST: str = _env("OYSTER_MCP_HTTP_HOST", "127.0.0.1")
MCP_HTTP_PORT: int = _env_int("OYSTER_MCP_HTTP_PORT", 8765)

# Bearer credentials for the HTTP transport. Two independent schemes, checked in
# order: (1) any verified Supabase JWT whose email is on ADMIN_EMAILS (the same
# identity model as the rest of Oyster — this is the org/individual path), and
# (2) a set of explicit static tokens for local/dev/machine use, given as
# "token:email" pairs (email is the identity that token authenticates as; it
# still must be allow-listed in production). Anonymous is always refused.
MCP_HTTP_STATIC_TOKENS: dict[str, str] = {}
for _pair in _env("OYSTER_MCP_HTTP_TOKENS", "").split(","):
    _pair = _pair.strip()
    if _pair and ":" in _pair:
        _tok, _who = _pair.split(":", 1)
        if _tok.strip():
            MCP_HTTP_STATIC_TOKENS[_tok.strip()] = _who.strip().lower()

# Origin allow-list for the HTTP transport (DNS-rebinding / cross-site defence).
# Empty means "reject any request that carries a browser Origin header" — a
# native MCP client (Claude, an MCP test harness) sends none, so the default is
# safe and closed. Add explicit https:// origins to permit a browser client.
MCP_ALLOWED_ORIGINS: list[str] = [
    o.strip() for o in _env("OYSTER_MCP_ALLOWED_ORIGINS", "").split(",") if o.strip()
]

# Bounds. A single request body, a single tool result, and a per-token request
# rate — all capped so one client cannot exhaust the box or exfiltrate the KB in
# one call. Tool timeouts come from the Execution Engine risk profile for
# governed actions and from MCP_TOOL_TIMEOUT_S for read-only tools.
MCP_MAX_REQUEST_BYTES: int = _env_int("OYSTER_MCP_MAX_REQUEST_BYTES", 262_144)      # 256 KB
MCP_MAX_RESULT_BYTES: int = _env_int("OYSTER_MCP_MAX_RESULT_BYTES", 131_072)        # 128 KB
MCP_RATE_LIMIT_PER_MIN: int = _env_int("OYSTER_MCP_RATE_LIMIT_PER_MIN", 60)
MCP_TOOL_TIMEOUT_S: int = _env_int("OYSTER_MCP_TOOL_TIMEOUT_S", 30)
MCP_MAX_SEARCH_TOP_K: int = _env_int("OYSTER_MCP_MAX_SEARCH_TOP_K", 20)

# Local (stdio) identity. stdio is a local process the operator launched
# themselves, so it is trusted as the local operator; these name WHO that is for
# audit + project resolution. Defaults to the dev-local identity.
MCP_LOCAL_EMAIL: str = _env("OYSTER_MCP_LOCAL_EMAIL", "dev-local").strip().lower()
MCP_LOCAL_SUB: str = _env("OYSTER_MCP_LOCAL_SUB", "mcp-local-operator")


# ── Production safety guards ────────────────────────────────────────────────
# Fail LOUDLY at startup on a misconfigured deploy rather than silently serving
# a red-team tool to the open internet with no gate. Public access is now
# expressed through the TIERED chat surface (require_chat_access: anon
# allowance / signed-in unlimited) — auth itself stays ON in production, so
# DISABLE_AUTH=true remains the misconfiguration it always was.
if ENVIRONMENT.strip().lower() == "production":
    if DISABLE_AUTH:
        raise RuntimeError(
            "SECURITY: OYSTER_DISABLE_AUTH=true while OYSTER_ENVIRONMENT=production — "
            "refusing to start. Public access is provided by the tiered /chat surface, "
            "not by disabling auth. Set OYSTER_DISABLE_AUTH=false."
        )
    if not ADMIN_EMAILS:
        raise RuntimeError(
            "SECURITY: OYSTER_ENVIRONMENT=production requires at least one email in "
            "OYSTER_ADMIN_EMAILS — refusing to start with an unrestricted auth gate."
        )
    if not SUPABASE_URL:
        raise RuntimeError(
            "SECURITY: OYSTER_ENVIRONMENT=production requires OYSTER_SUPABASE_URL to "
            "verify tokens against — refusing to start."
        )
    # Browser access: production origins must be explicit HTTPS origins.
    if any(o == "*" or not o.lower().startswith("https://") for o in CORS_ORIGINS):
        raise RuntimeError(
            "SECURITY: OYSTER_ENVIRONMENT=production requires OYSTER_CORS_ORIGINS to be "
            "explicit https:// origins (no '*', no http://) — refusing to start."
        )
    # Authenticated/metered provider endpoints must be HTTPS, and NVIDIA-hosted
    # endpoints need a key (else reranking just falls back, which is a silent
    # degradation an operator should see at boot, not discover in the UI).
    if NEMOTRON_RERANK_ENABLED and not NEMOTRON_RERANK_URL.lower().startswith(
            ("https://", "http://127.0.0.1", "http://localhost")):
        raise RuntimeError(
            "SECURITY: NEMOTRON_RERANK_URL must be https:// (or loopback) in production."
        )
    # The MCP HTTP transport must not ship with weak/dev credentials in
    # production. Static bearer tokens are a local convenience only; a
    # network-reachable gateway must authenticate with real Supabase identities.
    _WEAK_MCP_TOKENS = {"", "changeme", "dev", "test", "local", "secret", "token"}
    if any(t.strip().lower() in _WEAK_MCP_TOKENS or len(t) < 24 for t in MCP_HTTP_STATIC_TOKENS):
        raise RuntimeError(
            "SECURITY: OYSTER_ENVIRONMENT=production forbids weak/short OYSTER_MCP_HTTP_TOKENS. "
            "Use Supabase-authenticated MCP clients, or set tokens of at least 24 random chars."
        )
