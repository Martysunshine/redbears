"""A streaming chat view must never be silent for longer than
CHAT_STREAM_HEARTBEAT_S.

Waiting in line and a model's cold load both produce no tokens. Before
2026-09-14 that was zero bytes on the wire, which any proxy with an idle
timeout in front of the API (Cloudflare: 100 s) treats as a dead connection
and severs. The heartbeat lives in chat_queue.watch(), so both views — NDJSON
frames and the legacy raw text — are covered by the same mechanism.

Each test gets its own ChatQueue (routers.chat resolves ``chat_queue.queue``
at call time), its own owners, and releases every blocking job at the end, so
nothing leaks between tests or into the module singleton.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import config
from routers import chat as chat_router
from services import chat_queue


@pytest.fixture
def queue(monkeypatch):
    monkeypatch.setattr(config, "CHAT_STREAM_HEARTBEAT_S", 0.05)
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)
    fresh = chat_queue.ChatQueue()
    monkeypatch.setattr(chat_queue, "queue", fresh)
    return fresh


def _blocking_job(queue: chat_queue.ChatQueue, owner: str):
    """Submit a job whose generation hangs until the returned event is set."""
    release = asyncio.Event()

    async def run(job):
        await release.wait()

    return queue.submit(owner, run), release


async def _collect(view, seconds: float) -> list:
    frames: list = []

    async def drain():
        async for f in view:
            frames.append(f)

    task = asyncio.create_task(drain())
    await asyncio.sleep(seconds)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return frames


async def _finish(*releases: asyncio.Event) -> None:
    for r in releases:
        r.set()
    await asyncio.sleep(0.1)


async def test_ndjson_view_keeps_talking_while_a_running_job_is_silent(queue):
    job, release = _blocking_job(queue, "hb-running")
    try:
        await asyncio.sleep(0.05)  # let _guard admit it → RUNNING
        raw = await _collect(chat_router._ndjson_view(job), 0.5)
    finally:
        await _finish(release)
    frames = [json.loads(line) for line in raw]
    types = [f["type"] for f in frames]
    assert types[:2] == ["job", "start"], types
    assert types.count("keepalive") >= 3, types
    assert "token" not in types


async def test_ndjson_view_repeats_the_queue_frame_while_waiting(queue):
    a, release_a = _blocking_job(queue, "hb-slot-a")
    b, release_b = _blocking_job(queue, "hb-slot-b")
    try:
        await asyncio.sleep(0.05)  # both slots taken
        queued, release_q = _blocking_job(queue, "hb-waiting")
        try:
            raw = await _collect(chat_router._ndjson_view(queued), 0.5)
        finally:
            await _finish(release_q)
    finally:
        await _finish(release_a, release_b)
    frames = [json.loads(line) for line in raw]
    queue_frames = [f for f in frames if f["type"] == "queue"]
    assert len(queue_frames) >= 3, [f["type"] for f in frames]
    assert all(f["position"] >= 1 for f in queue_frames)


async def test_raw_view_sends_whitespace_only_before_the_first_token(queue):
    job, release = _blocking_job(queue, "hb-raw")
    try:
        await asyncio.sleep(0.05)
        chunks = await _collect(chat_router._raw_view(job), 0.5)
    finally:
        await _finish(release)
    assert chunks, "no keepalive bytes while the job was silent"
    assert set("".join(chunks)) == {" "}


# ---------------------------------------------------------------------------
# Cancellation (2026-09-14): the frame carries a code, and the route is
# owner-only.
# ---------------------------------------------------------------------------

async def _drain_all(view) -> list:
    frames: list = []
    async for f in view:
        frames.append(f)
    return frames


async def test_ndjson_view_ends_a_cancelled_job_with_the_cancelled_code(queue):
    job, release = _blocking_job(queue, "cancel-code")
    await asyncio.sleep(0.05)                    # RUNNING
    drain = asyncio.create_task(_drain_all(chat_router._ndjson_view(job)))
    await asyncio.sleep(0.1)                     # the view is attached
    queue.cancel(job)
    raw = await asyncio.wait_for(drain, timeout=2)
    release.set()
    frames = [json.loads(line) for line in raw]
    last = frames[-1]
    assert last["type"] == "error", frames
    assert last["detail"] == "cancelled", last          # unchanged for old clients
    assert last["code"] == "cancelled", last            # new, additive
    assert job.status == chat_queue.CANCELLED


async def test_cancel_route_stops_the_owners_job_and_releases_the_slot(queue):
    job, release = _blocking_job(queue, "sub:owner-1")
    await asyncio.sleep(0.05)
    assert job.status == chat_queue.RUNNING and queue._running == 1
    snap = await chat_router.cancel_chat_job(job.id, identity={"tier": "user", "sub": "owner-1"})
    assert snap["status"] == chat_queue.CANCELLED
    await asyncio.sleep(0.05)                    # let the task unwind
    assert queue._running == 0
    # Idempotent: a second cancel is a no-op that still answers.
    snap2 = await chat_router.cancel_chat_job(job.id, identity={"tier": "user", "sub": "owner-1"})
    assert snap2["status"] == chat_queue.CANCELLED
    release.set()


async def test_cancel_route_is_404_for_anyone_else(queue):
    from fastapi import HTTPException

    job, release = _blocking_job(queue, "sub:owner-2")
    try:
        await asyncio.sleep(0.05)
        with pytest.raises(HTTPException) as exc:
            await chat_router.cancel_chat_job(job.id, identity={"tier": "user", "sub": "someone-else"})
        assert exc.value.status_code == 404          # never 403: no oracle
        with pytest.raises(HTTPException) as exc_anon:
            await chat_router.cancel_chat_job(job.id, identity={"tier": "anon", "ip": "203.0.113.9"})
        assert exc_anon.value.status_code == 404
        assert job.status == chat_queue.RUNNING, "a stranger's cancel must change nothing"
    finally:
        await _finish(release)


async def test_one_at_a_time_refusal_names_the_job_in_the_way(queue, monkeypatch):
    """chat_one_at_a_time carries X-Oyster-Job so the client can re-attach
    or cancel it instead of guessing. Exercised at the queue level: the
    router turns TooManyForOwner into the 429 with that header."""
    monkeypatch.setattr(config, "CHAT_MAX_PER_USER", 1)
    first, release = _blocking_job(queue, "sub:busy")
    try:
        with pytest.raises(chat_queue.TooManyForOwner) as exc:
            queue.submit("sub:busy", lambda job: asyncio.sleep(0))
        assert exc.value.existing.id == first.id
    finally:
        await _finish(release)
