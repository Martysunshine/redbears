"""The chat queue — one job registry, watched two different ways.

WHY THIS EXISTS. Generation throughput on this box is flat at ~8 tokens/sec no
matter how many people chat (measured: 1 caller 7.6 tok/s, 2 callers 4.3 each,
3 callers 2.7 each — 2 vCPU, llama.cpp already uses both). Concurrency buys
nothing; it only decides who waits versus who gets an answer so slow the
request dies. Before this, the 5th simultaneous chatter simply timed out after
waiting ~95 seconds, which is the worst possible outcome: they paid the wait
AND got nothing.

So we run a small number of generations at once and make everyone else wait in
an honest, visible line.

THE SHAPE. A job registry is the source of truth. Generation runs in a
background task owned by the JOB, never by the HTTP request, which is what
makes a dropped connection survivable:

    POST /chat ─> create job ─> enqueue ─> stream a live view of the job
                                   ├─ GET /chat/jobs/{id}          (poll)
                                   └─ GET /chat/jobs/{id}/stream   (re-attach)

Both endpoints are views over the same job. There is deliberately no second
implementation that could disagree with the first.

TWO RULES THAT MATTER MORE THAN THEY LOOK:

1. **A slot is held only around the generation itself.** Sitting in the chat,
   reading, or typing costs nothing — no slot, no queue position. The instant
   one generation finishes the next person starts. (This is why the semaphore
   wraps `_run` and not the request lifetime.)

2. **The queue depth is derived from a maximum acceptable WAIT, not a fixed
   number.** At ~19s per answer, telling person #100 they are in line is a lie
   dressed as politeness — they would wait half an hour. Past the cap we say
   "too busy, come back in a few minutes", which is information they can act
   on. The ETA comes from a rolling average of real recent generations, so it
   stays truthful as the box speeds up or slows down.

PRIORITY, AND WHY IT IS NOT A PRIORITY QUEUE. Red Orca sells "priority access
to Oyster" on its paid plans, and `submit(..., priority=True)` is how that is
honoured. It is deliberately NOT a strict priority queue: under sustained paid
load, strict priority passes the free user at the back forever, and an unbounded
wait is a worse product than a slow one. Instead a paid job may overtake an
ordinary job only during that job's first `CHAT_PRIORITY_MAX_OVERTAKE_S` seconds
of waiting; after that the ordinary job is a barrier nobody may pass, so the set
of work ahead of it is frozen and can only drain. See `_enqueue`.

ADMISSION IS EXPLICIT (`_admit`), not an asyncio.Semaphore. A semaphore hands
out slots in the order `acquire()` was called, which is arrival order — the one
thing priority has to be able to override. So the waiting line IS the deque, and
a job may take a slot only when it is at the head of it.
"""

from __future__ import annotations

import asyncio
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import AsyncGenerator, Callable, Optional

from fastapi import HTTPException

import config
import log_config
from services import ollama_probe

# Status values the API surfaces. "queued" and "running" are live; the rest are
# terminal and the job is retained briefly so a refresh can still collect it.
QUEUED = "queued"
RUNNING = "running"
DONE = "done"
ERROR = "error"
CANCELLED = "cancelled"
TERMINAL = {DONE, ERROR, CANCELLED}

# The sentence a job ends with when it hits the wall clock. Identical to the
# one ollama_service uses for a stalled model, on purpose: to the person
# reading it, "the model went quiet" and "the model rambled for ten minutes"
# are the same event — the answer is not coming, try again.
JOB_TIMEOUT_MESSAGE = "The assistant took too long to answer. Please try again."

# Why a job was cancelled. Only ever read by logs and tests; the wire says
# "cancelled" for all of them, because the client that asked for the cancel
# already knows why and the client that did not cannot act on the difference.
CANCEL_BY_OWNER = "owner"            # POST /chat/jobs/{id}/cancel, the Stop button
CANCEL_ABANDONED_QUEUED = "abandoned_queued"    # nobody watched while it waited
CANCEL_ABANDONED_RUNNING = "abandoned_running"  # nobody watched while it generated


class TooManyForOwner(Exception):
    """This account already has a generation in flight.

    Carries the existing job so the caller can tell the user what it is waiting
    on ("your message is still generating, about N seconds left") rather than
    just refusing.
    """

    def __init__(self, existing: "ChatJob") -> None:
        super().__init__("This account already has a generation in progress.")
        self.existing = existing


@dataclass
class ChatJob:
    id: str
    owner: str                      # supabase sub, or hashed IP for anonymous
    # Bought and paid for, via VoiceIQ's plan catalog. Resolved once at submit
    # time and never re-read: a job's place in line must not change under it
    # because a cache expired mid-wait.
    priority: bool = False
    status: str = QUEUED
    text: str = ""                  # accumulated answer so far
    error: Optional[str] = None
    created_at: float = field(default_factory=time.monotonic)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    # Number of clients currently watching. 0 means the tab is gone — see the
    # detach grace in the reaper.
    viewers: int = 0
    last_detached_at: Optional[float] = None
    # Set by cancel(); one of the CANCEL_* constants. Diagnostic only.
    cancel_reason: Optional[str] = None
    # Bumped on every state change so streaming views can wake up cheaply
    # instead of polling their own job in a sleep loop.
    _event: asyncio.Event = field(default_factory=asyncio.Event)
    _task: Optional[asyncio.Task] = None

    def touch(self) -> None:
        self._event.set()
        self._event = asyncio.Event()

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL


class ChatQueue:
    def __init__(self) -> None:
        self._jobs: dict[str, ChatJob] = {}
        # THE waiting line. Ordered, and the order is authoritative: a job runs
        # when it reaches the head, not when its acquire() call happens to be
        # served. Priority is expressed by WHERE a job is inserted (_enqueue).
        self._waiting: deque[str] = deque()
        # Slots currently spent on a generation. Replaces the old semaphore,
        # which could only grant in arrival order.
        self._running: int = 0
        # Bumped whenever the line or the running count changes, so waiting
        # jobs re-check their turn instead of polling.
        self._wake: asyncio.Event = asyncio.Event()
        self._durations: deque[float] = deque(maxlen=20)
        self._reaper: Optional[asyncio.Task] = None

    # -- sizing -----------------------------------------------------------

    def avg_generation_seconds(self) -> float:
        """A deliberately PESSIMISTIC estimate of how long one answer takes.

        The 75th percentile of recent generations, not the mean. Answer lengths
        vary enormously — a "say OK" reply finishes in 2s, a real question takes
        70s — and a mean is dragged down by the short ones. Measured live: the
        mean told a queued user "about 3 seconds" and then made them wait 72,
        and the estimate rose as they moved UP the line, which reads as broken.

        Under-promising a wait is the expensive mistake: someone told 3s leaves
        angry at 30s, while someone told 90s who waits 60 is pleasantly
        surprised. So bias high, and seed high until we have real data.
        """
        if not self._durations:
            return 25.0
        ordered = sorted(self._durations)
        idx = min(len(ordered) - 1, int(len(ordered) * 0.75))
        return ordered[idx]

    def _slots(self) -> int:
        """How many chats may generate at once, right now.

        Not a constant: which node serves a generation changes at runtime and
        the nodes have different slot counts (config.effective_chat_concurrent,
        services/ollama_probe.py). Every sizing decision in this class —
        admission, queue depth, ETA — goes through here rather than reading the
        static config value, so they cannot drift apart from each other or from
        what the box will actually run.
        """
        return config.effective_chat_concurrent(ollama_probe.live_via())

    def max_queue_len(self) -> int:
        """How many may wait before we start refusing, from the wait budget."""
        per = max(1.0, self.avg_generation_seconds())
        slots = self._slots()
        return max(1, int((config.CHAT_MAX_QUEUE_WAIT_S * slots) / per))

    def waiting_count(self) -> int:
        return len(self._waiting)

    def position_of(self, job_id: str) -> int:
        """1-based place in line; 0 once it is no longer waiting."""
        try:
            return self._waiting.index(job_id) + 1
        except ValueError:
            return 0

    def eta_seconds(self, job_id: str) -> int:
        pos = self.position_of(job_id)
        if pos <= 0:
            return 0
        slots = self._slots()
        # Everyone ahead has to clear first, `slots` at a time.
        rounds = (pos + slots - 1) // slots
        return int(rounds * self.avg_generation_seconds())

    def eta_seconds_for_new(self) -> int:
        """How long a caller arriving right now would wait. Used for the
        Retry-After we send when the queue is full, so 'come back later' is an
        actual number rather than a shrug."""
        slots = self._slots()
        rounds = (len(self._waiting) + slots) // slots
        return int(rounds * self.avg_generation_seconds())

    def snapshot(self, job: ChatJob) -> dict:
        pos = self.position_of(job.id)
        return {
            "id": job.id,
            "status": job.status,
            "position": pos,
            "ahead": max(0, pos - 1),
            "eta_seconds": self.eta_seconds(job.id),
            "text": job.text,
            "error": job.error,
            # Surfaced so the effect of a paid plan is observable rather than
            # only inferable from a wait that felt shorter.
            "priority": job.priority,
        }

    # -- lifecycle --------------------------------------------------------

    def get(self, job_id: str) -> Optional[ChatJob]:
        return self._jobs.get(job_id)

    def is_full(self) -> bool:
        return len(self._waiting) >= self.max_queue_len()

    def live_for(self, owner: str) -> list[ChatJob]:
        """This account's jobs that are still queued or running."""
        return [j for j in self._jobs.values()
                if j.owner == owner and not j.is_terminal]

    def submit(
        self,
        owner: str,
        run: Callable[[ChatJob], "asyncio.Future"],
        *,
        priority: bool = False,
    ) -> ChatJob:
        """Register a job and start its worker.

        `run` receives the job and does the actual generating; it is started as
        a task owned by the job so the HTTP request can come and go freely.

        `priority` is the paid-plan lane (see `_enqueue`). It defaults to False
        so every existing caller, and anything that cannot resolve an
        entitlement, keeps exactly today's behaviour.

        Raises ``TooManyForOwner`` when this account already has
        ``CHAT_MAX_PER_USER`` generations in flight. With only a couple of slots
        on the box, one enthusiastic tab (or a retry loop) could otherwise hold
        both and the whole waiting line, starving everyone else. Refusing here
        is kinder than enqueueing: the caller learns immediately, and their
        existing generation is still running and still theirs to watch. This cap
        applies to paying accounts too — priority buys a better place in line,
        not the right to hold more of the box.
        """
        live = self.live_for(owner)
        if len(live) >= max(1, config.CHAT_MAX_PER_USER):
            raise TooManyForOwner(live[0])
        job = ChatJob(id=uuid.uuid4().hex[:16], owner=owner, priority=priority)
        self._jobs[job.id] = job
        self._enqueue(job)
        job._task = asyncio.create_task(self._guard(job, run))
        self._ensure_reaper()
        self._notify()
        return job

    def _enqueue(self, job: ChatJob) -> None:
        """Put a job in the line — the only place priority is expressed.

        An ordinary job joins the back, always. A priority job walks forward
        from the back and stops at the first BARRIER it meets:

          * another priority job — paying peers are served first-come,
            first-served, so a second subscriber cannot leapfrog the first; and
          * an ordinary job that has already waited
            ``CHAT_PRIORITY_MAX_OVERTAKE_S`` — past that point nobody may pass
            it again, ever.

        THE SECOND RULE IS THE WHOLE STARVATION STORY, and it is why this is not
        a strict priority queue. Under strict priority, a free user at the back
        of a busy box is overtaken by every arriving subscriber forever: their
        wait has no bound at all, which is a worse experience than a slow answer
        and eventually a worse one than a refusal. Here an ordinary job is
        overtakeable for exactly the first N seconds of its wait; after that the
        set of jobs ahead of it is FROZEN and can only drain, so it is
        guaranteed to be served. Its worst case is therefore

            N  +  (whatever was ahead of it when it aged)

        and that second term is already bounded by the queue depth, which is
        derived from ``CHAT_MAX_QUEUE_WAIT_S``. So the guarantee is concrete:
        no ordinary caller waits longer than roughly N + the wait budget the
        queue already promises everyone.

        N = 0 disables overtaking entirely (every ordinary job is instantly a
        barrier), which is the honest kill-switch if the lane ever misbehaves.
        """
        if not job.priority:
            self._waiting.append(job.id)
            return
        cutoff = max(0.0, float(config.CHAT_PRIORITY_MAX_OVERTAKE_S))
        now = time.monotonic()
        idx = len(self._waiting)
        for i in range(len(self._waiting) - 1, -1, -1):
            other = self._jobs.get(self._waiting[i])
            if other is None:
                idx = i
                continue
            if other.priority or (now - other.created_at) >= cutoff:
                break                      # barrier — insert just after it
            idx = i
        self._waiting.insert(idx, job.id)

    async def _admit(self, job: ChatJob) -> bool:
        """Block until this job may run; reserve a slot and leave the line.

        Returns False when the job must not run at all. That check lives HERE,
        at the moment we are about to spend the slot, not only in the reaper:
        the reaper wakes every 10s, and relying on it alone let an abandoned job
        win a slot in the gap — precisely the resource it must never get.

        Correctness rests on one small thing: the condition is evaluated and the
        wake-up event is captured with no `await` between them, so a `_notify`
        can never slip past a waiter and leave it asleep on a stale event.
        Waking every waiter on each change is O(queue) and deliberate — the
        queue is a handful of entries on a 2-core box, and the alternative
        (waking only the presumed head) breaks the moment priority reorders it.
        """
        while True:
            if job.status == CANCELLED or self.is_abandoned(job):
                return False
            # Re-read on every pass, because the answer can change while this
            # job waits: failover moves generation between nodes with
            # different slot counts (config.effective_chat_concurrent). A job
            # that arrived while the slow node was serving is admitted at the
            # faster node's width the moment it takes over.
            slots = self._slots()
            if self._running < slots and self._waiting and self._waiting[0] == job.id:
                self._running += 1
                self._waiting.popleft()
                # Everyone still waiting just moved up a place — and the next in
                # line may be able to take a second free slot right now.
                self._notify()
                return True
            ev = self._wake
            await ev.wait()

    async def _guard(self, job: ChatJob, run) -> None:
        """Wait for a slot, then generate. Records timing for the ETA.

        The generation runs under a wall clock (``CHAT_JOB_MAX_RUNTIME_S``).
        Nothing bounded it before: the read timeout in ollama_service only
        caps the silence BETWEEN chunks, so a model that kept producing
        tokens — a runaway 8B on a CPU box does exactly that — held a slot
        and an Ollama permit indefinitely, and with CHAT_MAX_PER_USER its
        owner was locked out with 429 for as long as it ran. ``wait_for``
        cancels the inner coroutine on expiry, which unwinds the httpx stream
        and releases the permit the same way a user cancel does; the job then
        ends as ERROR with the timeout sentence rather than CANCELLED, because
        to the owner it is a failure they did not ask for.
        """
        admitted = False
        try:
            admitted = await self._admit(job)
            if not admitted:
                job.status = CANCELLED
                job.touch()
                return

            job.status = RUNNING
            job.started_at = time.monotonic()
            job.touch()

            try:
                await asyncio.wait_for(
                    run(job), timeout=max(1.0, float(config.CHAT_JOB_MAX_RUNTIME_S))
                )
            except asyncio.TimeoutError:
                log_config.error(
                    "chat_queue.job_timeout",
                    f"generation exceeded {config.CHAT_JOB_MAX_RUNTIME_S}s and was stopped",
                    {"job": job.id, "chars": len(job.text)},
                )
                job.status = ERROR
                job.error = JOB_TIMEOUT_MESSAGE
                return

            if not job.is_terminal:
                job.status = DONE
        except asyncio.CancelledError:
            job.status = CANCELLED
            raise
        except HTTPException as exc:
            # Raised on purpose, with a detail written for the browser (see
            # services/ollama_service.py). That sentence is the whole message:
            # the status code adds nothing a chat user can act on.
            job.status = ERROR
            job.error = str(exc.detail)
        except Exception as exc:  # noqa: BLE001 — a failed job must not kill the queue
            job.status = ERROR
            # Anything else is a bug or an infrastructure failure. Its text —
            # paths, hosts, SQL — belongs in the log, not in a stranger's chat.
            log_config.error(
                "chat_queue.job_failed",
                f"{type(exc).__name__}: {exc}",
                {"job": job.id, "traceback": traceback.format_exc()},
            )
            job.error = "Oyster couldn't finish that answer. Please try again."
        finally:
            # Releasing the slot is the first thing done and is guarded by
            # `admitted`, so neither a cancellation while waiting nor an
            # exploding generation can leak one.
            if admitted:
                self._running = max(0, self._running - 1)
            if job.started_at and job.status in (DONE, ERROR):
                self._durations.append(max(0.5, time.monotonic() - job.started_at))
            job.finished_at = time.monotonic()
            try:
                self._waiting.remove(job.id)
            except ValueError:
                pass
            job.touch()
            self._notify()

    def _notify(self) -> None:
        """Wake every waiting job (its turn may have come) and every viewer of
        one (its position may have changed)."""
        self._wake.set()
        self._wake = asyncio.Event()
        self._touch_waiting()

    def _touch_waiting(self) -> None:
        for jid in list(self._waiting):
            j = self._jobs.get(jid)
            if j:
                j.touch()

    def is_abandoned(self, job: ChatJob) -> bool:
        """Nobody has been watching for longer than the grace period.

        The grace exists because a brief disconnect (tab switch on mobile, a
        flaky network, a refresh) is not abandonment — the job should survive
        it. Only a sustained absence forfeits the place in line.
        """
        if job.viewers > 0 or job.last_detached_at is None:
            return False
        return (time.monotonic() - job.last_detached_at) > config.CHAT_JOB_DETACH_GRACE_S

    def is_abandoned_running(self, job: ChatJob) -> bool:
        """A RUNNING job nobody has watched for ``CHAT_RUNNING_DETACH_GRACE_S``.

        Deliberately a longer grace than the queued one. A queued job that
        loses its viewer has cost nothing yet, so dropping it after a short
        absence is cheap and safe. A running job has an answer in progress
        that a phone put in a pocket mid-stream will come back for — and the
        frontend resumes it from ``GET /chat/jobs/{id}/stream`` — so the
        absence has to be long enough to be a real departure before the slot
        is taken back. Until this existed, a closed tab burned the whole
        generation and locked its owner out (CHAT_MAX_PER_USER) until it
        finished on its own.
        """
        if job.status != RUNNING or job.viewers > 0 or job.last_detached_at is None:
            return False
        return (time.monotonic() - job.last_detached_at) > config.CHAT_RUNNING_DETACH_GRACE_S

    def cancel(self, job: ChatJob, reason: str = CANCEL_BY_OWNER) -> None:
        """Stop a job wherever it is. Idempotent; a terminal job is untouched.

        Must be called on the event loop (it cancels the job's task and sets
        an asyncio.Event), so the cancel route stays ``async def`` on purpose.
        For a RUNNING job the task cancellation lands inside ``_guard``'s
        ``wait_for``, which unwinds the generation — the httpx stream closes
        and the Ollama permit is released — before ``finally`` gives the slot
        back. The owner can submit again the moment the view reports
        ``cancelled``; nothing is held.
        """
        if job.is_terminal:
            return
        job.status = CANCELLED
        job.cancel_reason = reason
        if job._task and not job._task.done():
            job._task.cancel()
        job.touch()
        # A cancelled job at the head would otherwise hold the line until its
        # task's finally clause happens to run.
        self._notify()

    # -- viewers ----------------------------------------------------------

    def attach(self, job: ChatJob) -> None:
        job.viewers += 1
        job.last_detached_at = None

    def detach(self, job: ChatJob) -> None:
        job.viewers = max(0, job.viewers - 1)
        if job.viewers == 0:
            job.last_detached_at = time.monotonic()

    async def watch(self, job: ChatJob) -> AsyncGenerator[dict, None]:
        """Yield a snapshot on every state change until the job is terminal.

        Used by both the POST /chat stream and the re-attach stream, so the two
        paths cannot drift apart.
        """
        self.attach(job)
        try:
            last: Optional[tuple] = None
            last_yield = time.monotonic()
            while True:
                snap = self.snapshot(job)
                key = (snap["status"], snap["position"], len(snap["text"]))
                now = time.monotonic()
                # A snapshot goes out on every state change — and ALSO when
                # nothing has changed for CHAT_STREAM_HEARTBEAT_S. Waiting in
                # line, or a model still loading before its first token, used
                # to be total silence on the wire, which any proxy with an idle
                # timeout (Cloudflare: 100 s) treats as a dead connection and
                # severs. The views turn a stale snapshot into a keepalive.
                stale = (now - last_yield) >= config.CHAT_STREAM_HEARTBEAT_S
                if key != last or stale:
                    yield {**snap, "heartbeat": key == last}
                    last = key
                    last_yield = now
                if job.is_terminal:
                    return
                ev = job._event
                try:
                    # The timeout is a heartbeat, not a poll: it refreshes the
                    # ETA while a long generation runs ahead of us — bounded by
                    # the stream heartbeat so a short interval (the tests use
                    # 50 ms) is honoured instead of being rounded up to 2 s.
                    tick = max(0.01, min(2.0, float(config.CHAT_STREAM_HEARTBEAT_S)))
                    await asyncio.wait_for(ev.wait(), timeout=tick)
                except asyncio.TimeoutError:
                    pass
        finally:
            self.detach(job)

    # -- reaper -----------------------------------------------------------

    def _ensure_reaper(self) -> None:
        if self._reaper is None or self._reaper.done():
            self._reaper = asyncio.create_task(self._reap_loop())

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(max(0.05, float(config.CHAT_REAPER_INTERVAL_S)))
            now = time.monotonic()
            for jid, job in list(self._jobs.items()):
                # Abandoned while queued → drop before it costs a slot.
                if job.status == QUEUED and self.is_abandoned(job):
                    self.cancel(job, CANCEL_ABANDONED_QUEUED)
                # Abandoned while running → take the slot back. Logged, so a
                # pattern of these (a client that never resumes) is visible.
                elif self.is_abandoned_running(job):
                    log_config.error(
                        "chat_queue.job_abandoned",
                        f"running job unwatched for {config.CHAT_RUNNING_DETACH_GRACE_S}s, cancelled",
                        {"job": job.id, "chars": len(job.text),
                         "ran_s": round(now - (job.started_at or now), 1)},
                    )
                    self.cancel(job, CANCEL_ABANDONED_RUNNING)
                # Terminal and old → forget it.
                if job.is_terminal and job.finished_at and \
                        now - job.finished_at > config.CHAT_JOB_RETENTION_S:
                    self._jobs.pop(jid, None)
            if not self._jobs:
                return  # nothing left to watch; submit() restarts us


queue = ChatQueue()
