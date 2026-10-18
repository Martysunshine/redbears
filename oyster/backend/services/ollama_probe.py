"""Background reachability probe for the Ollama endpoints.

Why this exists: failover used to be discovered INSIDE a user's request. The
primary node is a desktop reached over Tailscale, and when its Ollama is not
running the port is blackholed — the SYN is dropped, never refused — so the
first chat of every cool-off window paid the full connect timeout (10 s at the
time) before falling back, while holding one of the two Ollama permits. Users
read that as "Oyster hangs"; the log read it as a routine failover.

Now one task probes ``/api/tags`` on every configured endpoint every few
seconds, and ``ollama_service._endpoints()`` orders the endpoints from this
state: a dead primary is skipped and nobody pays for the discovery. A
request-time failure or success still updates the state instantly
(``mark_failed`` / ``mark_ok``), and ``/health`` reads the same state instead
of probing on every poll.

The state is process-local (one uvicorn worker). Only labels ("primary",
"fallback") leave this module through ``snapshot()`` — ``/health`` is public
and the URLs are private addresses.

Until the prober has ticked once (``has_data()`` is False — the first seconds
after boot, or the standalone checks, which never start it) ``ordered()``
returns None and the caller keeps its own cool-off logic, so nothing here
changes behaviour in a process where the probe is not running.
"""
from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

import config
import log_config


@dataclass
class EndpointState:
    name: str                          # "primary" | "fallback" — the only thing /health shows
    generate_url: str
    reachable: Optional[bool] = None   # None = never probed
    consecutive_failures: int = 0
    last_ok: Optional[float] = None
    last_fail: Optional[float] = None
    last_probe: Optional[float] = None
    latency_ms: Optional[float] = None
    models: set[str] = field(default_factory=set)


_states: dict[str, EndpointState] = {}   # keyed by generate URL, primary first
_task: Optional[asyncio.Task] = None
_last_tick: Optional[float] = None


def _configured() -> list[tuple[str, str]]:
    """(name, generate_url) for every distinct endpoint in config, primary first."""
    out = [("primary", config.OLLAMA_GENERATE_URL)]
    fb = config.OLLAMA_FALLBACK_GENERATE_URL
    if fb and fb != config.OLLAMA_GENERATE_URL:
        out.append(("fallback", fb))
    return out


def _tags_from_generate(gen: str) -> str:
    suffix = "/api/generate"
    return gen[: -len(suffix)] + "/api/tags" if gen.endswith(suffix) else gen


def _sync_states() -> None:
    """Keep the table aligned with config — the standalone checks rebind the URLs."""
    wanted: dict[str, EndpointState] = {}
    for name, gen in _configured():
        st = _states.get(gen)
        if st is None or st.name != name:
            st = EndpointState(name=name, generate_url=gen)
        wanted[gen] = st
    if list(wanted) != list(_states):
        _states.clear()
        _states.update(wanted)


def _log_transition(st: EndpointState, up: bool, why: str = "") -> None:
    word = "reachable again" if up else "unreachable"
    log_config.error(
        "ollama.probe",
        f"{st.name} endpoint is {word}" + (f" ({why})" if why else ""),
        {"endpoint": st.name, "url": st.generate_url, "reason": why},
    )
    print(f"  [ollama] {st.name} is {word}", file=sys.stderr)


def _set_up(st: EndpointState) -> None:
    was = st.reachable
    st.reachable = True
    st.consecutive_failures = 0
    st.last_ok = time.monotonic()
    if was is not True:
        _log_transition(st, True)


def _set_down(st: EndpointState, why: str) -> None:
    was = st.reachable
    st.reachable = False
    st.last_fail = time.monotonic()
    if was is not False:
        _log_transition(st, False, why)


def state_for(generate_url: str) -> Optional[EndpointState]:
    _sync_states()
    return _states.get(generate_url)


def mark_failed(generate_url: str) -> None:
    """A request just failed to CONNECT here. That is strong evidence — the
    request already paid a timeout for it — so the endpoint is marked down at
    once; the prober brings it back when it answers again."""
    st = state_for(generate_url)
    if st is None:
        return
    st.consecutive_failures += 1
    _set_down(st, "request-time connect failure")


def mark_ok(generate_url: str) -> None:
    """A request just got an answer from here."""
    st = state_for(generate_url)
    if st is not None:
        _set_up(st)


def has_data() -> bool:
    """True once the background prober has completed at least one round."""
    return _last_tick is not None


def ordered() -> Optional[list[str]]:
    """Endpoints in the order a request should try them, or None when the
    prober has no opinion (not started, or nothing probed yet) — the caller
    then keeps its own cool-off logic."""
    if not has_data():
        return None
    _sync_states()
    sts = list(_states.values())
    if len(sts) < 2:
        return None
    primary, fallback = sts[0], sts[1]
    if primary.reachable is None:
        return None
    if primary.reachable:
        return [primary.generate_url, fallback.generate_url]
    return [fallback.generate_url, primary.generate_url]


def live_via() -> Optional[str]:
    """Which endpoint generation would use right now: "primary", "fallback" or
    None when neither is known to answer."""
    _sync_states()
    for st in _states.values():
        if st.reachable:
            return st.name
    return None


def snapshot() -> dict:
    """Public-safe view for /health: labels, ages and counts. Never a URL."""
    _sync_states()
    now = time.monotonic()
    endpoints = {}
    for st in _states.values():
        endpoints[st.name] = {
            "reachable": st.reachable,
            "latency_ms": None if st.latency_ms is None else round(st.latency_ms),
            "last_ok_age_s": None if st.last_ok is None else round(now - st.last_ok),
            "consecutive_failures": st.consecutive_failures,
        }
    return {
        "probe_age_s": None if _last_tick is None else round(now - _last_tick, 1),
        "endpoints": endpoints,
    }


async def _probe(client: httpx.AsyncClient, st: EndpointState) -> None:
    t0 = time.monotonic()
    st.last_probe = t0
    try:
        r = await client.get(_tags_from_generate(st.generate_url))
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        try:
            st.models = {m.get("name", "") for m in (r.json().get("models") or [])}
        except Exception:  # noqa: BLE001 — the model list is a bonus, not the point
            pass
        st.latency_ms = (time.monotonic() - t0) * 1000
        _set_up(st)
    except Exception as exc:  # noqa: BLE001 — unreachable is an answer, not an error
        st.consecutive_failures += 1
        st.last_fail = time.monotonic()
        if st.consecutive_failures >= config.OLLAMA_PROBE_FAILS_TO_DOWN:
            _set_down(st, type(exc).__name__)


async def probe_once(client: httpx.AsyncClient) -> None:
    """One round over every endpoint. A DOWN endpoint is re-probed only every
    OLLAMA_PROBE_DOWN_INTERVAL_S — the blackholed primary should not eat a
    connect timeout on every tick."""
    global _last_tick
    _sync_states()
    now = time.monotonic()
    due = [
        st for st in _states.values()
        if not (
            st.reachable is False
            and st.last_probe is not None
            and now - st.last_probe < config.OLLAMA_PROBE_DOWN_INTERVAL_S
        )
    ]
    if due:
        await asyncio.gather(*(_probe(client, st) for st in due), return_exceptions=True)
    _last_tick = time.monotonic()


async def run_forever() -> None:
    t = float(config.OLLAMA_PROBE_CONNECT_S)
    timeout = httpx.Timeout(connect=t, read=t, write=5.0, pool=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            try:
                await probe_once(client)
            except Exception as exc:  # noqa: BLE001 — the loop must outlive any one failure
                log_config.error("ollama.probe", f"probe round failed: {type(exc).__name__}",
                                 {"error": str(exc)[:200]})
            await asyncio.sleep(max(1, int(config.OLLAMA_PROBE_INTERVAL_S)))


def start() -> None:
    """Start the prober on the running loop (called from the app lifespan)."""
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(run_forever(), name="ollama-probe")


async def stop() -> None:
    global _task
    if _task is not None:
        _task.cancel()
        try:
            await _task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        _task = None


def reset_for_tests() -> None:
    global _last_tick
    _states.clear()
    _last_tick = None


def simulate_tick_for_tests() -> None:
    """Pretend the prober has run, so ordered() trusts the marked state."""
    global _last_tick
    _sync_states()
    _last_tick = time.monotonic()
