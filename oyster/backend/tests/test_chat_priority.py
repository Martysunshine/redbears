"""Paid priority in the chat queue — the ordering, and the way it fails.

Two things are tested here, and the second matters more than the first:

  1. ORDERING. A subscriber is served ahead of ordinary callers who are still
     waiting, without ever exceeding the concurrency limit, and without a
     subscriber being able to starve anyone: an ordinary job that has waited
     past CHAT_PRIORITY_MAX_OVERTAKE_S can never be overtaken again.

  2. FAIL-OPEN. The entitlement lives in a DIFFERENT application. If that
     application is down, slow, moved, misconfigured or was never deployed,
     Oyster must carry on serving chat with everybody in the ordinary lane. A
     billing outage that becomes a chat outage would be a far worse bug than
     the feature is a good one.

No network: every HTTP call is replaced with a fake. Async tests are driven
through asyncio.run() rather than pytest-asyncio, which is not installed here.
"""

from __future__ import annotations

import asyncio

import pytest

import config
from services import chat_queue, entitlements


# --- helpers ----------------------------------------------------------------


def _runner(tag: str, order: list, duration: float = 0.0):
    """A fake generation that records when it actually started."""

    async def run(job: chat_queue.ChatJob) -> None:
        order.append(tag)
        if duration:
            await asyncio.sleep(duration)
        job.text = f"answer-{tag}"

    return run


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, raw: str | None = None):
        self.status_code = status_code
        self._payload = payload
        self._raw = raw

    def json(self):
        if self._raw is not None:
            raise ValueError("not json")
        return self._payload


class _FakeHttpx:
    """Stands in for the httpx module inside services/entitlements.

    `behaviour(url, headers)` either returns a _FakeResponse or raises, which is
    how a timeout / connection refusal is expressed.
    """

    def __init__(self, behaviour):
        self.behaviour = behaviour
        self.calls: list[str] = []

    def AsyncClient(self, *args, **kwargs):  # noqa: N802 — mirrors httpx's name
        return _FakeSession(self)


class _FakeSession:
    def __init__(self, parent: _FakeHttpx):
        self.parent = parent

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None):
        self.parent.calls.append(url)
        return self.parent.behaviour(url, headers or {})


@pytest.fixture()
def billing(monkeypatch):
    """Configure a billing API and hand back a switchable fake transport."""
    entitlements.reset_for_tests()
    monkeypatch.setattr(config, "BILLING_API_URL", "https://billing.test")
    monkeypatch.setattr(config, "BILLING_CACHE_TTL_S", 300)
    monkeypatch.setattr(config, "BILLING_FAILURE_COOLOFF_S", 60)

    holder = {}

    def install(behaviour):
        fake = _FakeHttpx(behaviour)
        monkeypatch.setattr(entitlements, "httpx", fake)
        holder["fake"] = fake
        return fake

    yield install
    entitlements.reset_for_tests()


USER = {"tier": "user", "email": "buyer@example.com", "sub": "sb-user-1"}


# --- ordering ---------------------------------------------------------------


def test_priority_job_is_served_before_ordinary_jobs_already_waiting(monkeypatch):
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)
    monkeypatch.setattr(config, "CHAT_PRIORITY_MAX_OVERTAKE_S", 60)

    async def scenario():
        Q = chat_queue.ChatQueue()
        order: list[str] = []

        # Fill both slots so everything after this genuinely waits in line.
        blockers = [
            Q.submit(f"sub:block{i}", _runner(f"block{i}", order, 0.15))
            for i in range(2)
        ]
        await asyncio.sleep(0.02)
        assert Q.waiting_count() == 0        # both are running, not queued

        free = [Q.submit(f"sub:free{i}", _runner(f"free{i}", order)) for i in range(3)]
        paid = Q.submit("sub:paid", _runner("paid", order), priority=True)

        # Straight to the front of the waiting line — but not in front of the
        # two already generating, which nothing preempts.
        assert Q.position_of(paid.id) == 1
        assert Q.snapshot(paid)["priority"] is True

        await asyncio.gather(*[j._task for j in blockers + free + [paid]])
        assert order[:2] == ["block0", "block1"]
        assert order[2] == "paid"
        assert sorted(order[3:]) == ["free0", "free1", "free2"]

    asyncio.run(scenario())


def test_without_priority_the_queue_is_still_plain_fifo(monkeypatch):
    """The default path must be byte-for-byte the behaviour it always had."""
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)

    async def scenario():
        Q = chat_queue.ChatQueue()
        order: list[str] = []
        jobs = [Q.submit(f"sub:u{i}", _runner(f"u{i}", order, 0.02)) for i in range(6)]
        await asyncio.gather(*[j._task for j in jobs])
        assert order == [f"u{i}" for i in range(6)]

    asyncio.run(scenario())


def test_priority_peers_are_first_come_first_served(monkeypatch):
    """Paying twice does not buy a way past another payer."""
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)
    monkeypatch.setattr(config, "CHAT_PRIORITY_MAX_OVERTAKE_S", 60)

    async def scenario():
        Q = chat_queue.ChatQueue()
        order: list[str] = []
        blockers = [
            Q.submit(f"sub:block{i}", _runner(f"block{i}", order, 0.15))
            for i in range(2)
        ]
        await asyncio.sleep(0.02)

        free = Q.submit("sub:free", _runner("free", order))
        first = Q.submit("sub:paid1", _runner("paid1", order), priority=True)
        second = Q.submit("sub:paid2", _runner("paid2", order), priority=True)

        assert list(Q._waiting) == [first.id, second.id, free.id]
        await asyncio.gather(*[j._task for j in Q._jobs.values()])
        assert order[2:] == ["paid1", "paid2", "free"]

    asyncio.run(scenario())


def test_priority_never_widens_the_concurrency_limit(monkeypatch):
    """Priority decides ORDER. It must not decide how much of the box is used —
    the whole reason the cap exists is that throughput here is flat."""
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)
    monkeypatch.setattr(config, "CHAT_PRIORITY_MAX_OVERTAKE_S", 60)

    async def scenario():
        Q = chat_queue.ChatQueue()
        live = 0
        peak = 0

        def make():
            async def run(job):
                nonlocal live, peak
                live += 1
                peak = max(peak, live)
                await asyncio.sleep(0.03)
                live -= 1

            return run

        jobs = [
            Q.submit(f"sub:p{i}", make(), priority=(i % 2 == 0)) for i in range(8)
        ]
        await asyncio.gather(*[j._task for j in jobs])
        assert peak == 2
        assert Q._running == 0
        assert all(j.status == chat_queue.DONE for j in jobs)

    asyncio.run(scenario())


# --- the starvation guarantee ----------------------------------------------


def test_an_ordinary_job_that_has_waited_long_enough_is_never_overtaken(monkeypatch):
    """THE anti-starvation property.

    Once an ordinary job has waited CHAT_PRIORITY_MAX_OVERTAKE_S, the set of
    work ahead of it is frozen: no arriving subscriber may be inserted before
    it, so it can only move up. Without this a free user on a busy box waits
    without any bound at all.
    """
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)
    monkeypatch.setattr(config, "CHAT_PRIORITY_MAX_OVERTAKE_S", 30)

    async def scenario():
        Q = chat_queue.ChatQueue()
        order: list[str] = []
        blockers = [
            Q.submit(f"sub:block{i}", _runner(f"block{i}", order, 0.2))
            for i in range(2)
        ]
        await asyncio.sleep(0.02)

        old = Q.submit("sub:old", _runner("old", order))
        # Pretend this one has been in line for a minute.
        old.created_at -= 60.0
        fresh = Q.submit("sub:fresh", _runner("fresh", order))

        # Ten subscribers arrive in a burst. Not one of them may pass `old`.
        for i in range(10):
            Q.submit(f"sub:paid{i}", _runner(f"paid{i}", order), priority=True)
            assert Q.position_of(old.id) == 1, "an aged job was overtaken"

        # `fresh` is still young, so it IS overtaken — that is the trade, and it
        # is bounded: in 30 seconds it becomes untouchable too.
        assert Q.position_of(fresh.id) == 12
        assert list(Q._waiting)[0] == old.id

        await asyncio.gather(*[j._task for j in Q._jobs.values()])
        assert order[2] == "old"

    asyncio.run(scenario())


def test_overtaking_can_be_switched_off_entirely(monkeypatch):
    """N=0 makes every ordinary job a barrier — the honest kill-switch."""
    monkeypatch.setattr(config, "CHAT_MAX_CONCURRENT", 2)
    monkeypatch.setattr(config, "CHAT_PRIORITY_MAX_OVERTAKE_S", 0)

    async def scenario():
        Q = chat_queue.ChatQueue()
        order: list[str] = []
        blockers = [
            Q.submit(f"sub:block{i}", _runner(f"block{i}", order, 0.15))
            for i in range(2)
        ]
        await asyncio.sleep(0.02)

        free = Q.submit("sub:free", _runner("free", order))
        paid = Q.submit("sub:paid", _runner("paid", order), priority=True)
        assert Q.position_of(free.id) == 1
        assert Q.position_of(paid.id) == 2

        await asyncio.gather(*[j._task for j in Q._jobs.values()])
        assert order[2:] == ["free", "paid"]

    asyncio.run(scenario())


# --- fail-open --------------------------------------------------------------


def test_priority_is_granted_when_billing_says_so(billing):
    fake = billing(lambda url, headers: _FakeResponse(200, {"oyster_priority": True}))
    assert asyncio.run(entitlements.is_priority(USER, "tok")) is True
    assert fake.calls == ["https://billing.test/billing/entitlements"]


def test_a_non_subscriber_is_ordinary(billing):
    billing(lambda url, headers: _FakeResponse(
        200, {"plan": None, "active": False, "oyster_priority": False,
              "email_plugin_points": 0}))
    assert asyncio.run(entitlements.is_priority(USER, "tok")) is False


@pytest.mark.parametrize(
    "behaviour",
    [
        pytest.param(lambda url, headers: (_ for _ in ()).throw(TimeoutError()),
                     id="timeout"),
        pytest.param(lambda url, headers: (_ for _ in ()).throw(OSError("refused")),
                     id="connection-refused"),
        pytest.param(lambda url, headers: _FakeResponse(500), id="server-error"),
        pytest.param(lambda url, headers: _FakeResponse(502), id="bad-gateway"),
        pytest.param(lambda url, headers: _FakeResponse(200, raw="<html>not json"),
                     id="unparseable"),
        pytest.param(lambda url, headers: _FakeResponse(200, ["not", "a", "dict"]),
                     id="wrong-shape"),
        pytest.param(lambda url, headers: _FakeResponse(401), id="unauthorized"),
        pytest.param(lambda url, headers: _FakeResponse(404), id="route-missing"),
    ],
)
def test_every_billing_failure_falls_open_to_ordinary(billing, behaviour):
    """Not one of these may raise, hang, or grant priority."""
    billing(behaviour)
    assert asyncio.run(entitlements.is_priority(USER, "tok")) is False


def test_an_outage_stops_being_asked_about(billing):
    """A DOWN billing API must not cost every chat request a timeout — after one
    failure we stop calling until the cool-off expires."""
    fake = billing(lambda url, headers: (_ for _ in ()).throw(TimeoutError()))

    async def scenario():
        assert await entitlements.is_priority(USER, "tok") is False
        for _ in range(5):
            other = dict(USER, sub=f"sb-{_}")
            assert await entitlements.is_priority(other, "tok") is False

    asyncio.run(scenario())
    assert len(fake.calls) == 1, f"kept calling a dead API: {fake.calls}"


def test_an_outage_is_not_remembered_as_a_fact_about_the_user(billing, monkeypatch):
    """The cool-off is about the API, not the account: once it lifts, the very
    next lookup is real, so a subscriber is not demoted for the cache TTL."""
    state = {"down": True}

    def behaviour(url, headers):
        if state["down"]:
            raise TimeoutError()
        return _FakeResponse(200, {"oyster_priority": True})

    billing(behaviour)
    assert asyncio.run(entitlements.is_priority(USER, "tok")) is False

    state["down"] = False
    monkeypatch.setattr(config, "BILLING_FAILURE_COOLOFF_S", 0)
    entitlements._cooloff_until = 0.0        # the cool-off has expired
    assert asyncio.run(entitlements.is_priority(USER, "tok")) is True


def test_the_answer_is_cached_so_chat_is_not_one_http_call_per_message(billing):
    fake = billing(lambda url, headers: _FakeResponse(200, {"oyster_priority": True}))

    async def scenario():
        for _ in range(4):
            assert await entitlements.is_priority(USER, "tok") is True

    asyncio.run(scenario())
    assert len(fake.calls) == 1


def test_the_cache_cannot_grow_without_bound(billing, monkeypatch):
    monkeypatch.setattr(config, "BILLING_CACHE_MAX", 10)
    billing(lambda url, headers: _FakeResponse(200, {"oyster_priority": True}))

    async def scenario():
        for i in range(50):
            await entitlements.is_priority(dict(USER, sub=f"sb-{i}"), "tok")

    asyncio.run(scenario())
    assert len(entitlements._cache) <= 10


def test_anonymous_callers_are_ordinary_without_any_lookup(billing):
    fake = billing(lambda url, headers: _FakeResponse(200, {"oyster_priority": True}))
    anon = {"tier": "anon", "ip": "203.0.113.9"}
    assert asyncio.run(entitlements.is_priority(anon, None)) is False
    assert fake.calls == []


def test_the_operator_is_priority_without_any_lookup(billing):
    fake = billing(lambda url, headers: _FakeResponse(500))
    admin = {"tier": "admin", "email": "op@example.com", "sub": "sb-op"}
    assert asyncio.run(entitlements.is_priority(admin, "tok")) is True
    assert fake.calls == []


def test_with_no_billing_api_configured_nobody_is_priority(monkeypatch):
    """The default deployment. Nothing is called and nothing waits."""
    entitlements.reset_for_tests()
    monkeypatch.setattr(config, "BILLING_API_URL", "")

    def explode(*a, **kw):
        raise AssertionError("must not touch the network")

    monkeypatch.setattr(entitlements, "httpx", type("X", (), {"AsyncClient": explode})())
    assert asyncio.run(entitlements.is_priority(USER, "tok")) is False


def test_a_caller_with_no_token_is_ordinary(billing):
    fake = billing(lambda url, headers: _FakeResponse(200, {"oyster_priority": True}))
    assert asyncio.run(entitlements.is_priority(USER, None)) is False
    assert fake.calls == []


def test_the_users_own_token_is_what_is_forwarded(billing):
    seen = {}

    def behaviour(url, headers):
        seen.update(headers)
        return _FakeResponse(200, {"oyster_priority": True})

    billing(behaviour)
    asyncio.run(entitlements.is_priority(USER, "the-users-token"))
    # No service key, no shared secret: Oyster can only ever ask about the
    # person who is standing in front of it.
    assert seen["Authorization"] == "Bearer the-users-token"
