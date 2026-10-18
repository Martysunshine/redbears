"""Offline checks for the chat queue. RUN DIRECTLY, not via pytest:

    cd oyster/backend && python tests/standalone_chat_queue_check.py

Named standalone_* on purpose: it rebinds config at import time, which would
leak into any other test sharing a pytest session.

The invariants here are the ones that fail silently in production — the
semaphore letting 3 through when it should let 2, a slot not being released,
or one user reading another user's job. None of those raise; they just quietly
misbehave under load, which is exactly when nobody is watching.
"""
import asyncio, sys, time, types
from pathlib import Path

sys.path.insert(0, ".")
import config as cfg
cfg.CHAT_MAX_CONCURRENT = 2
cfg.CHAT_MAX_QUEUE_WAIT_S = 300
cfg.CHAT_JOB_DETACH_GRACE_S = 1        # shortened so the test is quick
cfg.CHAT_JOB_RETENTION_S = 600
# The sections below exercise QUEUE mechanics (cap, FIFO, ETA, abandonment) and
# use a single synthetic owner for convenience, so the per-account fairness cap
# is lifted here. Section 9 sets it back to 1 and tests it properly.
cfg.CHAT_MAX_PER_USER = 99
cfg.CHAT_PRIORITY_MAX_OVERTAKE_S = 60
# Sections 10-12 exercise the reaper and the wall clock; a fast reaper tick is
# harmless to the earlier sections (the RUNNING grace stays at its default
# until section 10 shortens it, and restores it after).
cfg.CHAT_REAPER_INTERVAL_S = 0.1
cfg.CHAT_JOB_MAX_RUNTIME_S = 600

from services import chat_queue as q                                  # noqa: E402

checks = []
def ck(name, ok, detail=""):
    checks.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'} | {name}{('  ' + detail) if detail else ''}")


async def main():
    Q = q.ChatQueue()

    # ---- 1. concurrency cap + slot release ------------------------------
    live = 0
    peak = 0
    order = []

    def make(tag, dur=0.25):
        async def run(job):
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            order.append(tag)
            await asyncio.sleep(dur)
            job.text = f"answer-{tag}"
            live -= 1
        return run

    jobs = [Q.submit("sub:alice", make(i)) for i in range(6)]
    await asyncio.gather(*[j._task for j in jobs])

    ck("never exceeds CHAT_MAX_CONCURRENT", peak == 2, f"peak={peak} limit=2")
    ck("all jobs completed", all(j.status == q.DONE for j in jobs))
    ck("slots released (all 6 ran)", len(order) == 6)
    ck("FIFO order preserved", order == sorted(order), f"order={order}")
    ck("answers captured", all(j.text == f"answer-{i}" for i, j in enumerate(jobs)))
    ck("queue drains to empty", Q.waiting_count() == 0)

    # ---- 2. an idle/finished job holds nothing ---------------------------
    ck("no slot held after completion", Q._running == 0,
       f"running={Q._running}")

    # ---- 3. rolling average feeds the ETA --------------------------------
    avg = Q.avg_generation_seconds()
    ck("avg learned from real runs", 0.1 < avg < 2.0, f"avg={avg:.2f}s")

    # ---- 4. queue cap derives from the wait budget -----------------------
    Q2 = q.ChatQueue()
    Q2._durations.extend([60.0] * 5)          # pretend answers take 60s
    cap = Q2.max_queue_len()                   # 300s budget * 2 slots / 60s
    ck("cap derived from wait budget", cap == 10, f"cap={cap} (expect 10)")
    Q2._durations.clear(); Q2._durations.extend([5.0] * 5)   # faster box
    ck("cap grows when box is faster", Q2.max_queue_len() > cap,
       f"cap now {Q2.max_queue_len()}")

    # ---- 5. position + eta while waiting ---------------------------------
    Q3 = q.ChatQueue()
    Q3._durations.extend([10.0] * 5)
    async def slow(job):
        await asyncio.sleep(0.6)
        job.text = "x"
    q3jobs = [Q3.submit("sub:bob", slow) for _ in range(5)]
    await asyncio.sleep(0.05)
    pos_last = Q3.position_of(q3jobs[-1].id)
    eta_last = Q3.eta_seconds(q3jobs[-1].id)
    ck("last in line has a real position", pos_last >= 1, f"position={pos_last}")
    ck("eta is non-zero while waiting", eta_last > 0, f"eta={eta_last}s")
    ck("eta grows with position",
       Q3.eta_seconds(q3jobs[-1].id) >= Q3.eta_seconds(q3jobs[0].id))
    await asyncio.gather(*[j._task for j in q3jobs])

    # ---- 6. abandoned job is dropped before it costs a slot --------------
    Q4 = q.ChatQueue()
    ran = []
    async def note(job):
        ran.append(job.id)
        await asyncio.sleep(0.2)
    # Blockers must outlast the grace period, otherwise the ghost reaches a
    # slot while still inside it and SHOULD run (a 0.2s disconnect is not
    # abandonment). Grace is 1s here, so hold the slots for 1.8s.
    async def hold(job):
        ran.append(job.id)
        await asyncio.sleep(1.8)
    blockers = [Q4.submit("sub:carol", hold) for _ in range(2)]   # fill both slots
    ghost = Q4.submit("sub:carol", note)                          # this one waits
    Q4.attach(ghost); Q4.detach(ghost)                            # tab opened then closed
    await asyncio.gather(*[b._task for b in blockers], ghost._task,
                         return_exceptions=True)
    ck("abandoned job never ran", ghost.id not in ran)
    ck("abandoned job is cancelled", ghost.status == q.CANCELLED, f"status={ghost.status}")

    # ---- 6b. a BRIEF disconnect is forgiven ------------------------------
    # The opposite failure matters just as much: dropping someone because
    # their phone slept for two seconds would be its own bug.
    Q4b = q.ChatQueue()
    ran_b = []
    async def note_b(job):
        ran_b.append(job.id)
    blinker = Q4b.submit("sub:carol", note_b)
    Q4b.attach(blinker); Q4b.detach(blinker)      # detached, but only just now
    await blinker._task
    ck("brief disconnect still runs", blinker.id in ran_b, f"status={blinker.status}")

    # ---- 7. ownership -----------------------------------------------------
    Q5 = q.ChatQueue()
    async def quick(job): job.text = "hi"
    alice = Q5.submit("sub:alice", quick)
    await alice._task
    ck("owner recorded", alice.owner == "sub:alice")
    ck("job lookup by id works", Q5.get(alice.id) is not None)
    ck("a different owner does not match", Q5.get(alice.id).owner != "sub:bob")

    # ---- 8. a failing job must not poison the queue -----------------------
    Q6 = q.ChatQueue()
    async def boom(job): raise RuntimeError("ollama exploded")
    async def fine(job): job.text = "ok"
    bad = Q6.submit("sub:dave", boom)
    good = Q6.submit("sub:dave", fine)
    await asyncio.gather(bad._task, good._task, return_exceptions=True)
    ck("failed job marked error", bad.status == q.ERROR, f"error={bad.error}")
    ck("queue still works after a failure", good.status == q.DONE and good.text == "ok")
    ck("slot released after failure", Q6._running == 0)

    # ---- 9. fairness: one generation per ACCOUNT -------------------------
    # The point of the queue is that nobody can be starved by somebody else.
    # Without a per-owner cap, one tab firing retries can hold both slots AND
    # the waiting line, which is exactly the head-of-line blocking the queue
    # exists to prevent.
    cfg.CHAT_MAX_PER_USER = 1
    try:
        Q7 = q.ChatQueue()
        async def busy(job):
            await asyncio.sleep(0.4)
            job.text = "done"

        first = Q7.submit("sub:erin", busy)
        refused = None
        try:
            Q7.submit("sub:erin", busy)
        except q.TooManyForOwner as exc:
            refused = exc
        ck("second generation from the same account is refused", refused is not None)
        ck("refusal points at the job already running",
           refused is not None and refused.existing.id == first.id)

        # A DIFFERENT account is unaffected — this is fairness, not a global lock.
        other = Q7.submit("sub:frank", busy)
        ck("a different account can still start", other.id != first.id)

        await asyncio.gather(first._task, other._task)

        # Once it finishes, the account is free again.
        again = Q7.submit("sub:erin", busy)
        ck("same account can submit again once finished", again.status in (q.QUEUED, q.RUNNING))
        await again._task
        ck("no slot leaked by the refusal", Q7._running == 0)
    finally:
        cfg.CHAT_MAX_PER_USER = 99

    # ---- 10. a RUNNING job nobody watches is reaped; a watched one is not --
    # Before 2026-09-14 the reaper only looked at QUEUED jobs. A closed tab
    # mid-answer therefore burned the entire generation, and — because of the
    # per-account cap — its owner got 429 until it finished on its own.
    cfg.CHAT_RUNNING_DETACH_GRACE_S = 0.3
    try:
        Q8 = q.ChatQueue()
        unwound = []
        async def long_gen(job):
            try:
                await asyncio.sleep(5)
                job.text = "should never finish"
            finally:
                unwound.append(job.id)          # cancellation reached the generator
        gone = Q8.submit("sub:gina", long_gen)     # slot 1
        stays = Q8.submit("sub:hank", long_gen)    # slot 2
        await asyncio.sleep(0.05)
        ck("both running", gone.status == q.RUNNING and stays.status == q.RUNNING)
        Q8.attach(gone); Q8.detach(gone)           # tab closed on the first
        Q8.attach(stays)                           # second is being watched
        t0 = time.monotonic()
        await asyncio.gather(gone._task, return_exceptions=True)
        took = time.monotonic() - t0
        ck("abandoned RUNNING job is cancelled", gone.status == q.CANCELLED, f"status={gone.status}")
        ck("…within grace + a reaper tick", took < 1.5, f"took={took:.2f}s")
        ck("…reason recorded", gone.cancel_reason == q.CANCEL_ABANDONED_RUNNING,
           f"reason={gone.cancel_reason}")
        ck("…generation actually unwound", gone.id in unwound)
        ck("…slot released", Q8._running == 1, f"running={Q8._running}")
        await asyncio.sleep(0.6)                   # well past the grace
        ck("a WATCHED running job is left alone", stays.status == q.RUNNING,
           f"status={stays.status}")
        # The owner of the reaped job can submit again straight away.
        again = Q8.submit("sub:gina", long_gen)
        ck("owner can submit again immediately", again.status in (q.QUEUED, q.RUNNING))
        Q8.detach(stays)
        for j in (stays, again):
            Q8.cancel(j)
        await asyncio.gather(stays._task, again._task, return_exceptions=True)
    finally:
        cfg.CHAT_RUNNING_DETACH_GRACE_S = 180

    # ---- 11. cancel() on a RUNNING job ends it promptly --------------------
    # This is what the Stop button and POST /chat/jobs/{id}/cancel rely on:
    # the task is cancelled, the generator unwinds (which is what releases the
    # Ollama permit and closes the httpx stream), and the slot comes back.
    Q9 = q.ChatQueue()
    unwound9 = []
    async def long9(job):
        try:
            await asyncio.sleep(5)
        finally:
            unwound9.append(job.id)
    victim = Q9.submit("sub:ivan", long9)
    await asyncio.sleep(0.05)
    ck("victim is running", victim.status == q.RUNNING)
    t0 = time.monotonic()
    Q9.cancel(victim)
    await asyncio.gather(victim._task, return_exceptions=True)
    took = time.monotonic() - t0
    ck("cancelled status", victim.status == q.CANCELLED)
    ck("cancel is prompt", took < 0.3, f"took={took:.3f}s")
    ck("generator unwound on cancel", victim.id in unwound9)
    ck("slot released after cancel", Q9._running == 0, f"running={Q9._running}")
    ck("default cancel reason is the owner", victim.cancel_reason == q.CANCEL_BY_OWNER)
    Q9.cancel(victim)                              # idempotent on a terminal job
    ck("cancelling twice is harmless", victim.status == q.CANCELLED)

    # ---- 12. the wall clock ends a runaway generation ---------------------
    # Nothing bounded a RUNNING job before. The read timeout in ollama_service
    # only caps silence between chunks; a model that keeps emitting tokens held
    # the slot for ever.
    cfg.CHAT_JOB_MAX_RUNTIME_S = 1            # _guard clamps to ≥ 1 s
    try:
        Q10 = q.ChatQueue()
        unwound10 = []
        async def runaway(job):
            try:
                while True:                    # never stops on its own
                    job.text += "x"
                    job.touch()
                    await asyncio.sleep(0.02)
            finally:
                unwound10.append(job.id)
        Q10.attach                              # (watched or not makes no difference)
        rr = Q10.submit("sub:judy", runaway)
        t0 = time.monotonic()
        await asyncio.gather(rr._task, return_exceptions=True)
        took = time.monotonic() - t0
        ck("runaway job ends as ERROR", rr.status == q.ERROR, f"status={rr.status}")
        ck("…with the timeout sentence", rr.error == q.JOB_TIMEOUT_MESSAGE, f"error={rr.error!r}")
        ck("…at the wall clock", 0.9 < took < 2.0, f"took={took:.2f}s")
        ck("…partial text kept", len(rr.text) > 10, f"chars={len(rr.text)}")
        ck("…generator unwound", rr.id in unwound10)
        ck("…slot released", Q10._running == 0, f"running={Q10._running}")
        ck("…duration recorded for the ETA", len(Q10._durations) == 1)
        # And the queue still works afterwards.
        async def quick10(job): job.text = "ok"
        nxt = Q10.submit("sub:judy", quick10)
        await nxt._task
        ck("queue healthy after a timeout", nxt.status == q.DONE and nxt.text == "ok")
    finally:
        cfg.CHAT_JOB_MAX_RUNTIME_S = 600

    failed = [n for n, ok in checks if not ok]
    print(f"\n{len(checks)-len(failed)}/{len(checks)} passed")
    return 1 if failed else 0


sys.exit(asyncio.run(main()))
