"""A handler that only does synchronous SQLite work must be a plain ``def``.

FastAPI runs ``async def`` handlers on the event loop and plain ``def``
handlers in a threadpool. A handler that awaits nothing but calls into the
SQLite-backed services gains nothing from ``async`` and costs everyone else:
one contended write (up to the store's 5 s ``busy_timeout``) freezes every
chat stream's heartbeats and tokens for its duration. The conversations
router was the one place this rule was broken — every one of its handlers
was ``async`` — and was fixed on 2026-09-14. This test makes the fix
permanent.

Handlers that DO await (the chat submit, the cancel route, account deletion)
must stay ``async``: the queue's cancel and the job registry are event-loop
objects and are not safe to touch from a thread. That side of the rule is
pinned too, so nobody "fixes" this test by making everything sync.
"""
from __future__ import annotations

import inspect

from fastapi.routing import APIRoute

from routers import chat, conversations, user_findings


def _routes(router) -> dict[tuple[str, str], object]:
    out = {}
    for r in router.routes:
        if isinstance(r, APIRoute):
            for m in r.methods:
                out[(m, r.path)] = r.endpoint
    return out


def test_every_conversations_handler_is_sync():
    routes = _routes(conversations.router)
    assert routes, "no routes found — did the router move?"
    offenders = [k for k, fn in routes.items() if inspect.iscoroutinefunction(fn)]
    assert not offenders, f"async handlers doing sync SQLite work: {offenders}"


def test_every_user_findings_handler_is_sync():
    routes = _routes(user_findings.router)
    assert routes
    offenders = [k for k, fn in routes.items() if inspect.iscoroutinefunction(fn)]
    assert not offenders, offenders


def test_chat_router_splits_sync_and_async_on_purpose():
    routes = _routes(chat.router)
    sync_expected = {
        ("GET", "/me"),
        ("GET", "/me/training-consent"),
        ("PUT", "/me/training-consent"),
    }
    # These touch the in-memory job registry (asyncio events, tasks, the
    # waiting deque) or await something; they belong on the loop.
    async_expected = {
        ("POST", "/chat"),
        ("DELETE", "/me"),
        ("GET", "/chat/jobs/{job_id}"),
        ("GET", "/chat/jobs/{job_id}/stream"),
        ("POST", "/chat/jobs/{job_id}/cancel"),
    }
    missing = (sync_expected | async_expected) - set(routes)
    assert not missing, f"routes missing from the chat router: {missing}"
    for key in sync_expected:
        assert not inspect.iscoroutinefunction(routes[key]), f"{key} should be plain def"
    for key in async_expected:
        assert inspect.iscoroutinefunction(routes[key]), f"{key} must stay async"


def test_conversations_background_tasks_are_async_and_offload_their_reads():
    """The two background tasks await the memory service, so they are
    coroutines — and their own SQLite read goes through asyncio.to_thread
    rather than blocking the loop after the response has been sent."""
    for fn in (conversations._capture_memory, conversations._remember_correction):
        assert inspect.iscoroutinefunction(fn)
        src = inspect.getsource(fn)
        assert "asyncio.to_thread(conversation_service.get" in src, fn.__name__
