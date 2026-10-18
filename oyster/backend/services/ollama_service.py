import asyncio
import json
import sys
import time
from typing import AsyncGenerator

import httpx
from fastapi import HTTPException

import config
import log_config
from services import ollama_probe

OLLAMA_URL = config.OLLAMA_GENERATE_URL

# --- which Ollama do we talk to? -------------------------------------------
#
# Optionally two: a fast primary (a bigger machine over a private Tailscale
# link) and a fallback (the local one). The primary is not a datacentre — it can
# sleep or lose its connection — and that must degrade Oyster to SLOW, never to
# DOWN. So a connection failure moves traffic to the fallback, and the primary
# is re-probed after a cool-off so it is picked back up on its own once it
# returns. With no fallback configured this is inert: one endpoint, old
# behaviour, no extra work per request.
#
# Since 2026-09-14 the ORDER comes from services/ollama_probe.py whenever its
# background task has run: it already knows which node answers, so a request
# never pays a connect timeout to find out. The cool-off below is what decides
# before the prober's first round (the first seconds after boot) and in
# processes where it is not running (the standalone checks).
_primary_down_until: float = 0.0
_active_url: str = OLLAMA_URL


def _endpoints() -> list[str]:
    """Endpoints to try, in order. Never empty."""
    primary = config.OLLAMA_GENERATE_URL
    fallback = config.OLLAMA_FALLBACK_GENERATE_URL
    if not fallback or fallback == primary:
        return [primary]
    probed = ollama_probe.ordered()
    if probed is not None:
        return probed
    # Inside the cool-off we go straight to the fallback, but still keep the
    # primary as a last resort: if BOTH are unreachable we want the original
    # error, not a silent success on a stale assumption.
    if time.monotonic() < _primary_down_until:
        return [fallback, primary]
    return [primary, fallback]


def _note_failure(url: str) -> None:
    global _primary_down_until
    ollama_probe.mark_failed(url)
    if url == config.OLLAMA_GENERATE_URL and config.OLLAMA_FALLBACK_GENERATE_URL:
        _primary_down_until = time.monotonic() + config.OLLAMA_RETRY_PRIMARY_AFTER_S
        log_config.error(
            "ollama.failover",
            f"{url} unreachable — using the fallback for the next "
            f"{config.OLLAMA_RETRY_PRIMARY_AFTER_S}s",
            {"primary": url, "fallback": config.OLLAMA_FALLBACK_GENERATE_URL},
        )
        print(f"  [ollama] {url} unreachable — falling back to "
              f"{config.OLLAMA_FALLBACK_GENERATE_URL}", file=sys.stderr)


def _note_success(url: str) -> None:
    global _primary_down_until, _active_url
    ollama_probe.mark_ok(url)
    if url != _active_url:
        print(f"  [ollama] now generating via {url}", file=sys.stderr)
        _active_url = url
    if url == config.OLLAMA_GENERATE_URL:
        _primary_down_until = 0.0        # primary is back; stop avoiding it


def active_endpoint() -> str:
    """Which Ollama served the last successful generation (for the boot log
    and diagnostics)."""
    return _active_url


# --- what the user is told versus what the operator is told ------------------
#
# Every failure below used to put the machines involved in the HTTP response:
# the Tailscale address of the inference node, the docker-gateway alias for
# this box, the port, the software and a "run: ollama serve" hint. That text was
# rendered verbatim in the browser of whoever asked — anonymous visitors
# included. A user cannot act on any of it, and it hands a stranger a map of
# the private network behind the API. So the browser gets a sentence it can act
# on, and the addresses go where the operator looks: errors.jsonl and stderr.
# Nothing that names a host, a port, a URL or a product may go in `detail`.
USER_UNAVAILABLE = "The assistant is temporarily unavailable. Please try again in a moment."
USER_TIMEOUT = "The assistant took too long to answer. Please try again."
USER_INTERRUPTED = "The connection to the assistant was interrupted. Please try again."

# Every refusal carries a Retry-After the client can count down from: without
# one, a browser reads "try again in a moment" as "hammer the button". Seconds.
_RETRY_UNAVAILABLE = "30"
_RETRY_TIMEOUT = "30"
_RETRY_INTERRUPTED = "10"
_RETRY_NODE_OFFLINE = "60"


def _model_missing(model: str) -> HTTPException:
    """404 for a model no endpoint could serve — worded for whoever will read it.

    The biggest model only exists on the inference node, because it is 9 GB
    against this box's original 7.8 GB of RAM and could never run here. When
    that machine is asleep, a model marked ``requires_node`` gets a sentence the
    user can act on — switch to a lighter model. Any other missing model is a
    deployment gap; the ``ollama pull`` that fixes it is logged for the operator
    by ``_no_endpoint_answered`` and never sent to a browser, whose owner does
    not administer the machine.
    """
    entry = next(
        (m for m in config.MODEL_REGISTRY.values() if m.get("ollama") == model), {}
    )
    if entry.get("requires_node"):
        return HTTPException(
            status_code=503,
            detail=(
                f"{entry.get('label', model)} runs on a separate machine that is "
                "offline right now. Pick a lighter model — the faster ones are "
                "always available — or try again once it is back."
            ),
            headers={"Retry-After": _RETRY_NODE_OFFLINE},
        )
    return HTTPException(
        status_code=404,
        detail=f"Model '{model}' is not available right now. Please pick another model.",
    )


def _unreachable(last_error: Exception) -> HTTPException:
    """503 when no endpoint answered. Which ones were tried goes to the log only."""
    tried = _endpoints()
    kind = type(last_error).__name__
    log_config.error(
        "ollama.unreachable",
        f"no configured endpoint answered ({kind}) — is Ollama running, and bound "
        "on an address the container can reach?",
        {"tried": tried, "error": kind},
    )
    print(f"  [ollama] no endpoint reachable: {' and '.join(tried)} [{kind}]",
          file=sys.stderr)
    return HTTPException(status_code=503, detail=USER_UNAVAILABLE,
                         headers={"Retry-After": _RETRY_UNAVAILABLE})


def _bad_status(url: str, status: int) -> HTTPException:
    """502 when an endpoint answered with something other than 200 or 404."""
    log_config.error("ollama.bad_status", f"endpoint returned HTTP {status}",
                     {"url": url, "status": status})
    return HTTPException(status_code=502, detail=USER_UNAVAILABLE,
                         headers={"Retry-After": _RETRY_UNAVAILABLE})


def _timed_out(url: str) -> HTTPException:
    """504 when a connected endpoint went silent for longer than the read
    timeout — a wedged generation, not a dead network."""
    log_config.error("ollama.timeout", "request timed out", {"url": url})
    return HTTPException(status_code=504, detail=USER_TIMEOUT,
                         headers={"Retry-After": _RETRY_TIMEOUT})


def _no_endpoint_answered(last_error: Exception | None, model: str) -> HTTPException:
    """Every endpoint was tried. Decide what the user is told; log the rest.

    If they refused because the MODEL is missing, say that — "unavailable"
    would send someone debugging a network that is working perfectly.
    """
    if isinstance(last_error, HTTPException):
        if last_error.status_code == 404:
            log_config.error(
                "ollama.model_missing",
                f"model '{model}' is on no configured endpoint — run: ollama pull {model}",
                {"model": model, "endpoints": _endpoints()},
            )
        return last_error
    return _unreachable(last_error or RuntimeError("no endpoint"))

# --- one limit on everything that reaches Ollama ---------------------------
#
# chat_queue.py caps how many CHATS generate at once, which is what users see.
# But RAG answers, red-team panels, knowledge asks and background memory
# extraction all call generate() directly, holding no queue slot and counted by
# nothing. On a 2-vCPU box shared with Ollama that is how a "max 2 concurrent"
# promise quietly becomes four or five, and everyone's tokens slow to a crawl.
#
# This gate is the real ceiling: every call in this module passes through it,
# whoever made it. Chat still queues first, so its behaviour is unchanged — it
# is the background work that now waits its turn instead of oversubscribing.
# No deadlock is possible: a chat holds a queue slot then takes a gate slot,
# and gate slots are always released, so nothing waits on a chat.
# The size of this gate is NOT fixed. Failover moves generation between nodes
# with different slot counts (config.effective_max_concurrent), and an
# asyncio.Semaphore fixes its capacity at construction — resizing one in place
# is not possible. So admission is explicit, exactly like chat_queue._admit:
# the limit is re-read on every wait, and a change takes effect at the next
# admission without disturbing anything already running.
#
# Correctness rests on the same small thing _admit relies on: the condition is
# evaluated and the wake-up event captured with NO await in between, so a
# release can never slip past a waiter and leave it asleep on a stale event.
#
# One bounded lag is accepted deliberately: if the limit RISES while callers
# are waiting (failover to a faster node), the waiters are not woken until the
# next release, so the new capacity is taken up one generation later. Waking
# them eagerly would mean the prober reaching into this module on every
# transition, and the wait is already bounded by one generation.
_gate_running: int = 0
_gate_wake: asyncio.Event | None = None
_gate_loop: asyncio.AbstractEventLoop | None = None


def _gate_limit() -> int:
    """Slots on the node that would serve this call right now."""
    return config.effective_max_concurrent(ollama_probe.live_via())


class _OllamaGate:
    """Async context manager guarding every call that reaches Ollama."""

    async def __aenter__(self) -> "_OllamaGate":
        global _gate_running
        while True:
            if _gate_running < _gate_limit():
                _gate_running += 1
                return self
            ev = _gate_wake
            if ev is None:                      # never: _ollama_gate() binds it
                raise RuntimeError("ollama gate used before binding")
            await ev.wait()

    async def __aexit__(self, *_exc: object) -> bool:
        global _gate_running, _gate_wake
        _gate_running = max(0, _gate_running - 1)
        if _gate_wake is not None:
            # Wake every waiter: the limit may have changed under them, so the
            # presumed head is not necessarily the one that may now proceed.
            _gate_wake.set()
            _gate_wake = asyncio.Event()
        return False


_GATE = _OllamaGate()


def _ollama_gate() -> _OllamaGate:
    # Bound lazily and rebound if the loop changes: an Event binds to the
    # running loop, and this module is imported long before uvicorn starts one.
    global _gate_wake, _gate_loop, _gate_running
    loop = asyncio.get_running_loop()
    if _gate_wake is None or _gate_loop is not loop:
        _gate_wake = asyncio.Event()
        _gate_loop = loop
        _gate_running = 0
    return _GATE


def reset_gate_for_tests() -> None:
    """Forget the gate's loop binding and in-flight count. Tests only."""
    global _gate_wake, _gate_loop, _gate_running
    _gate_wake = None
    _gate_loop = None
    _gate_running = 0


def gate_state_for_tests() -> tuple[int, int]:
    """(in flight, current limit) — for assertions, never for control flow."""
    return _gate_running, _gate_limit()


# --- timeouts and the shared client ------------------------------------------
#
# A flat timeout=120 used to apply to READS as well, which made a slow first
# token indistinguishable from a dead server; then read became unbounded, which
# let a wedged generation hold a gate permit forever — two of them and every
# Ollama call in the process waits behind them, which is exactly what "the
# whole service hangs" looked like. Now: connect is short (the prober has
# already picked a live endpoint; this only fires when a node dies between two
# rounds), and READ is the longest silence tolerated between two streamed
# chunks — generous enough for a cold 8B load on CPU, finite so nothing can
# sit on a permit forever. The queue in chat_queue.py still bounds the WAIT;
# these bound the WORK.
def _stream_timeout() -> httpx.Timeout:
    return httpx.Timeout(
        connect=float(config.OLLAMA_CONNECT_TIMEOUT_S),
        read=float(config.OLLAMA_READ_TIMEOUT_S),
        write=30.0,
        pool=10.0,
    )


_STREAM_TIMEOUT = _stream_timeout()   # kept for anything that still reads the name

# One client per process, bound to the running loop the same way the gate is.
# Every generate used to open a fresh AsyncClient, so every request paid a new
# TCP handshake per endpoint it tried; the pool keeps the connection to Ollama
# warm between requests.
_client: httpx.AsyncClient | None = None
_client_loop: asyncio.AbstractEventLoop | None = None


def _get_client() -> httpx.AsyncClient:
    global _client, _client_loop
    loop = asyncio.get_running_loop()
    if _client is None or _client_loop is not loop:
        _client = httpx.AsyncClient(
            timeout=_stream_timeout(),
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        _client_loop = loop
    return _client


def reset_client_for_tests() -> None:
    """Forget the shared client so the next call builds one from the current
    ``httpx.AsyncClient`` — the standalone checks swap that name per section."""
    global _client, _client_loop
    _client = None
    _client_loop = None


async def aclose_client() -> None:
    """Close the pool on shutdown (called from the app lifespan)."""
    global _client, _client_loop
    client, _client, _client_loop = _client, None, None
    if client is not None:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 — shutdown must never fail on this
            pass


def _perf_payload(model: str | None = None) -> dict:
    """CPU-latency knobs applied to every generate call.

    keep_alive keeps a model resident between requests (the cold reload is the
    dominant time-to-first-token cost on a CPU box); num_ctx caps prefill work;
    num_thread only when explicitly configured (0 = Ollama decides).

    Only the models in ``config.OLLAMA_PINNED_MODELS`` are pinned indefinitely —
    by default the public chat model and the signed-in default. Pinning
    EVERYTHING was a real outage on the original 7.8 GB box (three models
    resident, 7 GB into swap, ~1 token/sec); the set is explicit so the RAM
    budget is a decision, not an accident: pinned weights plus their KV cache
    must stay under about 9 GB on the 15 GB VPS (deploy/HARDENING.md). Every
    other model expires after OLLAMA_KEEP_ALIVE_OTHER and gives the memory back.

    ``think: false`` is sent to thinking-capable models unless OLLAMA_THINK is
    on: on CPU their hidden monologue is seconds of first-token latency nobody
    sees. Older Ollama builds ignore the unknown field.
    """
    pinned = bool(model) and model in config.OLLAMA_PINNED_MODELS
    raw: object = config.OLLAMA_KEEP_ALIVE if pinned else config.OLLAMA_KEEP_ALIVE_OTHER
    try:
        keep_alive = int(raw)  # "-1" → -1 (forever); "300" → seconds
    except (TypeError, ValueError):
        keep_alive = raw  # duration strings like "5m" pass through as-is
    num_ctx = config.OLLAMA_NUM_CTX
    if model and model.lower().startswith("huihui"):
        num_ctx = config.HUIHUI_NUM_CTX
    options: dict = {"num_ctx": num_ctx, "num_batch": config.OLLAMA_NUM_BATCH}
    if config.OLLAMA_NUM_THREAD > 0:
        options["num_thread"] = config.OLLAMA_NUM_THREAD
    payload: dict = {"keep_alive": keep_alive, "options": options}
    if (
        not config.OLLAMA_THINK
        and model
        and config.OLLAMA_THINKING_MODEL_PREFIXES
        and model.lower().startswith(config.OLLAMA_THINKING_MODEL_PREFIXES)
    ):
        payload["think"] = False
    return payload


async def stream_generate(prompt: str, model: str, system: str = "") -> AsyncGenerator[str, None]:
    payload: dict = {"model": model, "prompt": prompt, "stream": True, **_perf_payload(model)}
    if system:
        payload["system"] = system

    last_error: Exception | None = None
    async with _ollama_gate():
        client = _get_client()
        for url in _endpoints():
            started = False          # once tokens flow we must NOT retry elsewhere
            try:
                async with client.stream("POST", url, json=payload) as response:
                    if response.status_code == 404:
                        # See the note in generate(): the two machines are
                        # pulled separately, so ask the other before
                        # telling the user the model does not exist.
                        last_error = _model_missing(model)
                        continue
                    if response.status_code != 200:
                        raise _bad_status(url, response.status_code)
                    _note_success(url)
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            token = data.get("response", "")
                            if token:
                                started = True
                                yield token
                            if data.get("done", False):
                                break
                        except json.JSONDecodeError:
                            continue
                return
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                # Could not reach this one at all — try the next endpoint. Only
                # safe before any token was emitted; re-running a half-streamed
                # answer elsewhere would duplicate text in the user's face.
                if started:
                    log_config.error("ollama.stream_lost", "connection lost mid-answer",
                                     {"url": url, "error": type(exc).__name__})
                    raise HTTPException(status_code=504, detail=USER_INTERRUPTED,
                                        headers={"Retry-After": _RETRY_INTERRUPTED})
                last_error = exc
                _note_failure(url)
                continue
            except httpx.TimeoutException:
                raise _timed_out(url)

    raise _no_endpoint_answered(last_error, model)


def _as_chat_url(generate_url: str) -> str:
    """The /api/chat sibling of a /api/generate endpoint (same host, same
    fallback/probe ordering — see config.OLLAMA_CHAT_URL for why chat exists
    at all)."""
    return generate_url.replace("/api/generate", "/api/chat")


async def stream_chat(messages: list[dict], model: str) -> AsyncGenerator[str, None]:
    """Like ``stream_generate``, but through /api/chat with a real messages[]
    array so Ollama applies the model's own chat template — role tags and
    stop tokens included — instead of Oyster hand-formatting history into one
    raw prompt string. Same endpoint fallback/probe/retry behaviour as
    ``stream_generate``; only the wire format and response field differ."""
    payload: dict = {"model": model, "messages": messages, "stream": True, **_perf_payload(model)}

    last_error: Exception | None = None
    async with _ollama_gate():
        client = _get_client()
        for generate_url in _endpoints():
            url = _as_chat_url(generate_url)
            started = False
            try:
                async with client.stream("POST", url, json=payload) as response:
                    if response.status_code == 404:
                        last_error = _model_missing(model)
                        continue
                    if response.status_code != 200:
                        raise _bad_status(url, response.status_code)
                    _note_success(generate_url)
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            token = (data.get("message") or {}).get("content", "")
                            if token:
                                started = True
                                yield token
                            if data.get("done", False):
                                break
                        except json.JSONDecodeError:
                            continue
                return
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                if started:
                    log_config.error("ollama.stream_lost", "connection lost mid-answer",
                                     {"url": url, "error": type(exc).__name__})
                    raise HTTPException(status_code=504, detail=USER_INTERRUPTED,
                                        headers={"Retry-After": _RETRY_INTERRUPTED})
                last_error = exc
                _note_failure(generate_url)
                continue
            except httpx.TimeoutException:
                raise _timed_out(url)

    raise _no_endpoint_answered(last_error, model)


async def chat(messages: list[dict], model: str, options: dict | None = None) -> str:
    """Non-streaming /api/chat — the RAG/Ask counterpart of ``generate``.

    Same endpoint fallback/probe behaviour and larger non-streaming timeout as
    ``generate``, but sends a real ``messages[]`` array so Ollama applies the
    model's own chat template (role tags, stop tokens) instead of Oyster
    flattening evidence + history + question into one raw prompt string. See
    ``stream_chat`` and oyster/docs/AI_HANDOFF.md 2026-09-30.

    ``options`` is merged over the default perf options (num_ctx/num_batch),
    letting a caller override sampling — e.g. the output-validator's corrective
    retry raises ``temperature`` so the second attempt genuinely differs from a
    temperature-0 model instead of reproducing the same deterministic output."""
    payload: dict = {"model": model, "messages": messages, "stream": False, **_perf_payload(model)}
    if options:
        payload["options"] = {**payload.get("options", {}), **options}
    timeout = httpx.Timeout(
        connect=float(config.OLLAMA_CONNECT_TIMEOUT_S),
        read=float(config.OLLAMA_GENERATE_TIMEOUT_S),
        write=30.0,
        pool=10.0,
    )
    last_error: Exception | None = None
    async with _ollama_gate():
        client = _get_client()
        for generate_url in _endpoints():
            url = _as_chat_url(generate_url)
            try:
                r = await client.post(url, json=payload, timeout=timeout)
                if r.status_code == 404:
                    last_error = _model_missing(model)
                    continue
                if r.status_code != 200:
                    raise _bad_status(url, r.status_code)
                _note_success(generate_url)
                return (r.json().get("message") or {}).get("content", "")
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc
                _note_failure(generate_url)
                continue
            except httpx.TimeoutException:
                raise _timed_out(url)

    raise _no_endpoint_answered(last_error, model)


async def generate(prompt: str, model: str, system: str = "") -> str:
    """Non-streaming generation — used by RAG to get a full answer.

    A non-streaming call sends nothing until it is completely finished, so the
    per-chunk read timeout would cut a long answer short: this one gets its
    own, larger ceiling (OLLAMA_GENERATE_TIMEOUT_S) instead of no ceiling.
    """
    payload: dict = {"model": model, "prompt": prompt, "stream": False, **_perf_payload(model)}
    if system:
        payload["system"] = system
    timeout = httpx.Timeout(
        connect=float(config.OLLAMA_CONNECT_TIMEOUT_S),
        read=float(config.OLLAMA_GENERATE_TIMEOUT_S),
        write=30.0,
        pool=10.0,
    )
    last_error: Exception | None = None
    async with _ollama_gate():
        client = _get_client()
        for url in _endpoints():
            try:
                r = await client.post(url, json=payload, timeout=timeout)
                if r.status_code == 404:
                    # This endpoint does not have the model. The other one
                    # might — the two machines are pulled separately and
                    # will drift. Only report "not found" once BOTH have
                    # been asked; otherwise a model missing from the fast
                    # box would 404 at the user even though the fallback
                    # could have answered.
                    last_error = _model_missing(model)
                    continue
                if r.status_code != 200:
                    raise _bad_status(url, r.status_code)
                _note_success(url)
                return r.json().get("response", "")
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc
                _note_failure(url)
                continue
            except httpx.TimeoutException:
                raise _timed_out(url)

    raise _no_endpoint_answered(last_error, model)
