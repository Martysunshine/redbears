"""Concurrency follows the node that is actually serving.

Oyster generates on one of two machines and which one changes at runtime
(services/ollama_probe.py): this box's own Ollama serves one generation at a
time, the desktop inference node is configured for four. Until 2026-09-15 the
ceilings were single static numbers, which is wrong for whichever node is not
serving:

  * pinned low, the fast node is throttled to the slow node's width and the
    whole point of having it is lost;
  * pinned high, the slow node reproduces the 2026-09-14 incident — surplus
    callers stop queueing VISIBLY and sit inside Ollama's own queue emitting
    zero bytes until OLLAMA_READ_TIMEOUT_S kills them, which is the "they paid
    the wait AND got nothing" failure the chat queue exists to prevent.

So the limits are read per node, and re-read while callers wait. These tests
pin that, and equally pin the conservative half: with no opinion from the
prober the old static value is used, because the standalone checks and the
first seconds after boot rely on it.

The prober is never started here; `live_via` is monkeypatched.
"""
from __future__ import annotations

import asyncio

import pytest

import config
from services import chat_queue, ollama_probe, ollama_service


@pytest.fixture(autouse=True)
def _clean_gate():
    ollama_service.reset_gate_for_tests()
    yield
    ollama_service.reset_gate_for_tests()


def _serving(monkeypatch, node: str | None) -> None:
    """Pretend the prober says this node is live."""
    monkeypatch.setattr(ollama_probe, "live_via", lambda: node)


def _limits(monkeypatch, *, ollama=1, primary=None, fallback=None,
            chat=1, chat_primary=None, chat_fallback=None) -> None:
    monkeypatch.setattr(config, "OLLAMA_MAX_CONCURRENT", ollama)
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", chat)
    monkeypatch.setattr(config, "OLLAMA_MAX_CONCURRENT_PRIMARY",
                        ollama if primary is None else primary)
    monkeypatch.setattr(config, "OLLAMA_MAX_CONCURRENT_FALLBACK",
                        ollama if fallback is None else fallback)
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT_PRIMARY",
                        chat if chat_primary is None else chat_primary)
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT_FALLBACK",
                        chat if chat_fallback is None else chat_fallback)


# ---------------------------------------------------------------------------
# The limit functions
# ---------------------------------------------------------------------------

def test_the_limit_is_the_serving_node_s_limit(monkeypatch):
    _limits(monkeypatch, ollama=2, primary=4, fallback=1)
    assert config.effective_max_concurrent("primary") == 4
    assert config.effective_max_concurrent("fallback") == 1


def test_no_opinion_keeps_the_static_ceiling(monkeypatch):
    """Before the prober's first round — and in the standalone checks, which
    never start it — nothing may change."""
    _limits(monkeypatch, ollama=2, primary=4, fallback=1)
    assert config.effective_max_concurrent(None) == 2
    assert config.effective_chat_concurrent(None) == 1


def test_defaults_leave_behaviour_identical(monkeypatch):
    """With no per-node env set, every path returns the static value — this is
    what makes the change safe to deploy while the primary node is offline."""
    monkeypatch.setattr(config, "OLLAMA_MAX_CONCURRENT", 3)
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 3)
    for attr in ("OLLAMA_MAX_CONCURRENT_PRIMARY", "OLLAMA_MAX_CONCURRENT_FALLBACK"):
        monkeypatch.setattr(config, attr, 3)
    for attr in ("CHAT_MAX_CONCURRENT_PRIMARY", "CHAT_MAX_CONCURRENT_FALLBACK"):
        monkeypatch.setattr(config, attr, 3)
    for via in ("primary", "fallback", None):
        assert config.effective_max_concurrent(via) == 3
        assert config.effective_chat_concurrent(via) == 3


def test_chat_can_never_exceed_the_node_ceiling(monkeypatch):
    """Chat shares the machine with RAG, the panels and memory extraction, so
    admitting more chats than the box may run at all would re-open the same
    hole by a different door."""
    _limits(monkeypatch, ollama=1, primary=4, chat=1, chat_primary=8)
    assert config.effective_chat_concurrent("primary") == 4


def test_a_limit_below_one_is_still_one(monkeypatch):
    """A zero or negative override must not wedge the box shut."""
    _limits(monkeypatch, ollama=0, primary=0, chat=0, chat_primary=-5)
    assert config.effective_max_concurrent("primary") == 1
    assert config.effective_chat_concurrent("primary") == 1


# ---------------------------------------------------------------------------
# The Ollama gate
# ---------------------------------------------------------------------------

async def _hold(entered: asyncio.Event, release: asyncio.Event) -> None:
    async with ollama_service._ollama_gate():
        entered.set()
        await release.wait()


async def _start_holders(n: int):
    """Start n callers; return (tasks, entered events, one shared release)."""
    release = asyncio.Event()
    entered = [asyncio.Event() for _ in range(n)]
    tasks = [asyncio.create_task(_hold(e, release)) for e in entered]
    await asyncio.sleep(0.05)
    return tasks, entered, release


async def _finish(tasks, release) -> None:
    release.set()
    await asyncio.gather(*tasks, return_exceptions=True)


async def test_the_gate_admits_exactly_the_live_limit(monkeypatch):
    _serving(monkeypatch, "fallback")
    _limits(monkeypatch, ollama=4, fallback=2)
    tasks, entered, release = await _start_holders(4)
    try:
        assert sum(e.is_set() for e in entered) == 2, "fallback allows 2"
        running, limit = ollama_service.gate_state_for_tests()
        assert (running, limit) == (2, 2)
    finally:
        await _finish(tasks, release)
    assert ollama_service.gate_state_for_tests()[0] == 0, "slots leaked"


async def test_the_faster_node_admits_more(monkeypatch):
    _serving(monkeypatch, "primary")
    _limits(monkeypatch, ollama=1, primary=4, fallback=1)
    tasks, entered, release = await _start_holders(4)
    try:
        assert sum(e.is_set() for e in entered) == 4, "primary allows 4"
    finally:
        await _finish(tasks, release)


async def test_failover_to_the_slow_node_does_not_disturb_those_running(monkeypatch):
    """In-flight callers drain against the limit they were admitted under.

    Cutting them off would be worse than the oversubscription: their answers
    are already streaming to someone.
    """
    _serving(monkeypatch, "primary")
    _limits(monkeypatch, ollama=1, primary=4, fallback=1)
    tasks, entered, release = await _start_holders(3)
    try:
        assert sum(e.is_set() for e in entered) == 3
        _serving(monkeypatch, "fallback")          # primary just died
        await asyncio.sleep(0.05)
        assert sum(e.is_set() for e in entered) == 3, "running work was disturbed"
        assert ollama_service.gate_state_for_tests()[1] == 1, "new limit is in force"
    finally:
        await _finish(tasks, release)


async def test_a_waiter_is_admitted_at_the_new_width_after_a_release(monkeypatch):
    """The documented one-generation lag: a limit that RISES while callers wait
    takes effect at the next release, not instantly."""
    _serving(monkeypatch, "fallback")
    _limits(monkeypatch, ollama=1, primary=4, fallback=1)

    release_first = asyncio.Event()
    first_in = asyncio.Event()
    first = asyncio.create_task(_hold(first_in, release_first))
    await asyncio.sleep(0.05)
    assert first_in.is_set()

    waiters_in = [asyncio.Event() for _ in range(2)]
    release_rest = asyncio.Event()
    waiters = [asyncio.create_task(_hold(e, release_rest)) for e in waiters_in]
    await asyncio.sleep(0.05)
    assert not any(e.is_set() for e in waiters_in), "fallback allows only 1"

    _serving(monkeypatch, "primary")               # the fast node came back
    await asyncio.sleep(0.05)
    assert not any(e.is_set() for e in waiters_in), "no wake-up without a release"

    release_first.set()
    await first
    await asyncio.sleep(0.05)
    assert all(e.is_set() for e in waiters_in), "both admitted at the new width"

    release_rest.set()
    await asyncio.gather(*waiters, return_exceptions=True)
    assert ollama_service.gate_state_for_tests()[0] == 0


async def test_a_waiter_is_never_stranded(monkeypatch):
    """Every release wakes every waiter, so nobody sleeps on a stale event
    after the limit moved under them."""
    _serving(monkeypatch, "fallback")
    _limits(monkeypatch, ollama=1, fallback=1)
    tasks, entered, release = await _start_holders(5)
    try:
        assert sum(e.is_set() for e in entered) == 1
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5)
    assert all(e.is_set() for e in entered), "a caller was left waiting forever"
    assert ollama_service.gate_state_for_tests()[0] == 0


# ---------------------------------------------------------------------------
# The chat queue sizes itself the same way
# ---------------------------------------------------------------------------

def test_queue_sizing_follows_the_node(monkeypatch):
    """Admission, queue depth and the ETA must all read one source — if they
    disagreed, the queue would promise a position it cannot honour."""
    q = chat_queue.ChatQueue()
    q._durations.extend([60.0] * 5)
    monkeypatch.setattr(config, "CHAT_MAX_QUEUE_WAIT_S", 300)
    _limits(monkeypatch, ollama=4, primary=4, fallback=1,
            chat=4, chat_primary=4, chat_fallback=1)

    _serving(monkeypatch, "fallback")
    assert q._slots() == 1
    slow_cap = q.max_queue_len()

    _serving(monkeypatch, "primary")
    assert q._slots() == 4
    assert q.max_queue_len() > slow_cap, "a wider node should hold a longer line"


async def test_the_queue_admits_at_the_live_width(monkeypatch):
    _serving(monkeypatch, "primary")
    _limits(monkeypatch, ollama=4, primary=4, chat=1, chat_primary=3)
    monkeypatch.setattr(config, "CHAT_MAX_PER_USER", 99)
    q = chat_queue.ChatQueue()
    release = asyncio.Event()

    async def run(job):
        await release.wait()

    jobs = [q.submit("sub:alice", run) for _ in range(5)]
    await asyncio.sleep(0.05)
    try:
        assert sum(j.status == chat_queue.RUNNING for j in jobs) == 3
    finally:
        release.set()
        await asyncio.gather(*[j._task for j in jobs], return_exceptions=True)
