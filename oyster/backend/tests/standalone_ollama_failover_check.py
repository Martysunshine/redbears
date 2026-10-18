"""Offline checks for Ollama failover. RUN DIRECTLY, not via pytest:

    cd oyster/backend && python tests/standalone_ollama_failover_check.py

Named standalone_* like the queue check: it rebinds config at import time,
which would leak into any other test sharing a pytest session.

Why this matters: generation is moving to a bigger machine reached over a
private Tailscale link. That machine can sleep, and the home connection can
drop. "The fast box is asleep" must mean Oyster is SLOW, never that Oyster is
DOWN — and when the fast box wakes up it must be picked back up on its own,
with nobody redeploying anything.

Sections 7-11 (2026-09-14) cover what production actually does that the
first six never exercised: the primary's port is BLACKHOLED (the SYN is
dropped, never refused), so a probe there costs the full connect timeout —
which is why the background prober exists, and why a request must never be
the thing that discovers a dead node.
"""
import asyncio
import json
import sys
import time

sys.path.insert(0, ".")
import config as cfg                                                   # noqa: E402

PRIMARY = "http://minipc:11434"
FALLBACK = "http://local:11434"
cfg.OLLAMA_BASE_URL = PRIMARY
cfg.OLLAMA_GENERATE_URL = f"{PRIMARY}/api/generate"
cfg.OLLAMA_FALLBACK_BASE_URL = FALLBACK
cfg.OLLAMA_FALLBACK_GENERATE_URL = f"{FALLBACK}/api/generate"
cfg.OLLAMA_RETRY_PRIMARY_AFTER_S = 1        # shortened so the test is quick
cfg.OLLAMA_MAX_CONCURRENT = 4

from services import ollama_probe as probe                             # noqa: E402
from services import ollama_service as osvc                            # noqa: E402

checks = []


def ck(name, ok, detail=""):
    checks.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'} | {name}{('  ' + detail) if detail else ''}")


class Resp:
    status_code = 200

    def json(self):
        return {"response": "hello"}


def use(client_cls):
    """Swap the httpx client class AND drop the shared instance built from the
    previous one — the service keeps one client per process now."""
    osvc.httpx.AsyncClient = client_cls
    osvc.reset_client_for_tests()


def client_where(reachable: set[str], seen: list[str]):
    """Fake httpx.AsyncClient whose POSTs only succeed for `reachable` hosts."""
    class C:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, **kw):
            seen.append(url)
            if not any(h in url for h in reachable):
                raise osvc.httpx.ConnectError("refused")
            return Resp()

    return C


async def main():
    probe.reset_for_tests()   # sections 1-6 run with the prober NOT running

    # ---- 1. primary healthy -> primary is used, fallback untouched -------
    seen: list[str] = []
    use(client_where({"minipc"}, seen))
    out = await osvc.generate("p", "m")
    ck("primary used when healthy", seen == [cfg.OLLAMA_GENERATE_URL], f"tried={seen}")
    ck("answer returned", out == "hello")

    # ---- 2. primary down -> falls back, NO error surfaced ----------------
    seen.clear()
    use(client_where({"local"}, seen))
    out = await osvc.generate("p", "m")
    ck("falls back when primary is unreachable", out == "hello", f"tried={seen}")
    ck("tried primary first, then fallback",
       seen == [cfg.OLLAMA_GENERATE_URL, cfg.OLLAMA_FALLBACK_GENERATE_URL], f"tried={seen}")

    # ---- 3. during cool-off it goes STRAIGHT to the fallback -------------
    seen.clear()
    await osvc.generate("p", "m")
    ck("cool-off skips the dead primary", seen[0] == cfg.OLLAMA_FALLBACK_GENERATE_URL,
       f"first={seen[0] if seen else None}")

    # ---- 4. primary returns -> picked back up automatically --------------
    await asyncio.sleep(1.1)                       # cool-off expires
    seen.clear()
    use(client_where({"minipc", "local"}, seen))
    await osvc.generate("p", "m")
    ck("primary re-probed after the cool-off", seen[0] == cfg.OLLAMA_GENERATE_URL,
       f"first={seen[0] if seen else None}")
    ck("active endpoint reports the primary", osvc.active_endpoint() == cfg.OLLAMA_GENERATE_URL,
       f"active={osvc.active_endpoint()}")

    # ---- 5. BOTH down -> a real 503, not a silent hang -------------------
    seen.clear()
    use(client_where(set(), seen))
    raised = None
    try:
        await osvc.generate("p", "m")
    except Exception as exc:                       # HTTPException
        raised = exc
    ck("both down raises 503", raised is not None and getattr(raised, "status_code", None) == 503,
       f"raised={type(raised).__name__ if raised else None}")
    ck("both endpoints were attempted", len(seen) == 2, f"tried={seen}")
    # The 503 is rendered verbatim in the browser of whoever asked, anonymous
    # visitors included. It once listed both endpoints — the inference node's
    # private address, the docker-gateway alias, the port, the software — which
    # is a map of the network behind the API. Those go to the log, never here.
    detail = str(getattr(raised, "detail", ""))
    ck("the 503 names no endpoint, host, port or product",
       bool(detail) and not any(
           s in detail for s in ("minipc", "local", "11434", "http", "ollama", "Ollama", "serve")
       ),
       f"detail={detail}")
    # ---- 11 (early). ...and tells the client when to come back -----------
    headers = getattr(raised, "headers", None) or {}
    ck("the 503 carries Retry-After", bool(headers.get("Retry-After")),
       f"headers={headers}")

    # ---- 5b. model missing on the primary -> the OTHER one is asked ------
    # The two machines are pulled separately and WILL drift: the fast box may
    # not have every model. A 404 there must not reach the user while the
    # fallback could have answered.
    class Missing:
        status_code = 404

        def json(self):
            return {"error": "model not found"}

    def client_missing_on(missing: set[str], seen: list[str]):
        class C:
            def __init__(self, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, url, **kw):
                seen.append(url)
                return Missing() if any(h in url for h in missing) else Resp()

        return C

    osvc._primary_down_until = 0.0
    cfg.OLLAMA_FALLBACK_GENERATE_URL = f"{FALLBACK}/api/generate"
    seen.clear()
    use(client_missing_on({"minipc"}, seen))
    out = await osvc.generate("p", "dolphin3")
    ck("model missing on primary falls back", out == "hello", f"tried={seen}")
    ck("both endpoints asked for the model", len(seen) == 2, f"tried={seen}")

    # ---- 5c. missing EVERYWHERE -> a 404 that names the model ------------
    seen.clear()
    use(client_missing_on({"minipc", "local"}, seen))
    raised = None
    try:
        await osvc.generate("p", "dolphin3")
    except Exception as exc:
        raised = exc
    ck("missing on both raises 404, not 503",
       getattr(raised, "status_code", None) == 404, f"status={getattr(raised, 'status_code', None)}")
    ck("the 404 names the model", "dolphin3" in str(getattr(raised, "detail", "")),
       f"detail={getattr(raised, 'detail', None)}")

    # ---- 5d. a node-only model missing everywhere -> a HUMAN message -----
    # Qwen 14B is 9 GB against a 7.8 GB server, so it can only ever live on the
    # inference node. When that machine sleeps, telling an end user to "run:
    # ollama pull" is advice about a computer they do not administer.
    osvc._primary_down_until = 0.0
    seen.clear()
    use(client_missing_on({"minipc", "local"}, seen))
    raised = None
    try:
        await osvc.generate("p", "qwen2.5:14b")
    except Exception as exc:
        raised = exc
    detail = str(getattr(raised, "detail", ""))
    ck("node-only model gives 503, not 404",
       getattr(raised, "status_code", None) == 503, f"status={getattr(raised,'status_code',None)}")
    ck("...and says the machine is offline, in words a user can act on",
       "offline" in detail and "pull" not in detail, f"detail={detail}")

    # An ORDINARY missing model is named, so the user can pick another — but
    # the "ollama pull" that fixes it is an instruction for the operator and is
    # logged, not shown: the browser belongs to someone who does not administer
    # the machine, and the message must not name the software either.
    seen.clear()
    raised = None
    try:
        await osvc.generate("p", "some-model-nobody-pulled")
    except Exception as exc:
        raised = exc
    detail = str(getattr(raised, "detail", ""))
    ck("ordinary missing model is named, without operator commands",
       getattr(raised, "status_code", None) == 404
       and "some-model-nobody-pulled" in detail
       and "pull" not in detail.replace("some-model-nobody-pulled", "")
       and "http" not in detail and "ollama" not in detail.lower(),
       f"detail={detail}")

    # ---- 6. no fallback configured -> single endpoint, old behaviour -----
    cfg.OLLAMA_FALLBACK_GENERATE_URL = ""
    osvc._primary_down_until = 0.0
    seen.clear()
    use(client_where({"minipc"}, seen))
    await osvc.generate("p", "m")
    ck("no fallback configured = one endpoint only", seen == [cfg.OLLAMA_GENERATE_URL],
       f"tried={seen}")

    # ---- 7. the BLACKHOLED primary: ConnectTimeout, not ConnectError -----
    # Production's dead primary drops the SYN, so the failure is a timeout
    # after the full connect budget, not an instant refusal. The fallback must
    # still answer, and the primary must still have been the first attempt
    # when nothing else is known.
    cfg.OLLAMA_FALLBACK_GENERATE_URL = f"{FALLBACK}/api/generate"
    osvc._primary_down_until = 0.0
    probe.reset_for_tests()

    def client_blackhole(reachable: set[str], seen: list[str]):
        class C:
            def __init__(self, **kw):
                pass

            async def post(self, url, **kw):
                seen.append(url)
                if not any(h in url for h in reachable):
                    await asyncio.sleep(0.05)      # the budget being spent
                    raise osvc.httpx.ConnectTimeout("blackholed")
                return Resp()

        return C

    seen.clear()
    use(client_blackhole({"local"}, seen))
    out = await osvc.generate("p", "m")
    ck("blackholed primary still falls back", out == "hello", f"tried={seen}")
    ck("...after paying for the primary once, when nothing is known yet",
       seen == [cfg.OLLAMA_GENERATE_URL, cfg.OLLAMA_FALLBACK_GENERATE_URL], f"tried={seen}")

    # ---- 8. with the prober running, a dead primary is NEVER tried -------
    # The request-time failure above already marked it; once the prober has
    # ticked, requests trust that state instead of paying to re-learn it.
    probe.simulate_tick_for_tests()
    seen.clear()
    t0 = time.monotonic()
    out = await osvc.generate("p", "m")
    elapsed = time.monotonic() - t0
    ck("dead primary skipped entirely", seen == [cfg.OLLAMA_FALLBACK_GENERATE_URL], f"tried={seen}")
    ck("...and the request paid nothing for it", elapsed < 0.2, f"elapsed={elapsed:.3f}s")

    # ---- 9. mark_ok flips the order back at once, no cool-off wait -------
    probe.mark_ok(cfg.OLLAMA_GENERATE_URL)
    seen.clear()
    use(client_where({"minipc", "local"}, seen))
    await osvc.generate("p", "m")
    ck("primary used again the moment it is marked reachable",
       seen[0] == cfg.OLLAMA_GENERATE_URL, f"first={seen[0] if seen else None}")

    # ---- 10. a generation that goes silent mid-stream is BOUNDED ---------
    # read=None used to let a wedged model hold an Ollama permit forever. Now
    # a ReadTimeout between chunks ends the job with the timeout message and
    # a Retry-After, and the tokens already sent were real.
    probe.reset_for_tests()
    osvc._primary_down_until = 0.0

    class StreamResp:
        status_code = 200

        async def aiter_lines(self):
            yield json.dumps({"response": "a"})
            yield json.dumps({"response": "b"})
            raise osvc.httpx.ReadTimeout("silent")

    class StreamCtx:
        async def __aenter__(self):
            return StreamResp()

        async def __aexit__(self, *a):
            return False

    def client_stream_silent(seen: list[str]):
        class C:
            def __init__(self, **kw):
                pass

            def stream(self, method, url, **kw):
                seen.append(url)
                return StreamCtx()

        return C

    seen.clear()
    use(client_stream_silent(seen))
    tokens: list[str] = []
    raised = None
    try:
        async for t in osvc.stream_generate("p", "m"):
            tokens.append(t)
    except Exception as exc:
        raised = exc
    ck("tokens before the silence were delivered", tokens == ["a", "b"], f"tokens={tokens}")
    ck("silence past the read timeout is a 504",
       getattr(raised, "status_code", None) == 504, f"status={getattr(raised, 'status_code', None)}")
    ck("...with the timeout sentence, not an exception's words",
       getattr(raised, "detail", None) == osvc.USER_TIMEOUT, f"detail={getattr(raised, 'detail', None)}")
    headers = getattr(raised, "headers", None) or {}
    ck("...and a Retry-After", bool(headers.get("Retry-After")), f"headers={headers}")

    failed = [n for n, ok in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} passed")
    return 1 if failed else 0


sys.exit(asyncio.run(main()))
