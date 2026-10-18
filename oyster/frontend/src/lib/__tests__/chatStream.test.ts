import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// authFetch is the only thing chatStream pulls from the request layer — mock
// it directly so every test controls exactly what "the network" does,
// including honouring the AbortSignal the way a real fetch would.
vi.mock("@/lib/request", () => ({ authFetch: vi.fn() }));

import { authFetch } from "@/lib/request";
import {
  FIRST_FRAME_MS,
  WATCHDOG_MS,
  cancelChatJob,
  resumeJob,
  startChat,
} from "@/lib/chatStream";

const mockedFetch = authFetch as unknown as ReturnType<typeof vi.fn>;

/** A ReadableStream whose bytes we push by hand (no timers involved), wired
 *  to error like a real fetch body does when its AbortController fires — so
 *  the watchdog/abort tests exercise the same failure shape production sees. */
function controllableStream(signal?: AbortSignal) {
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      ctrl = c;
      signal?.addEventListener("abort", () => {
        try {
          ctrl.error(Object.assign(new Error("aborted"), { name: "AbortError" }));
        } catch {
          /* already closed/errored */
        }
      });
    },
  });
  const enc = new TextEncoder();
  return {
    stream,
    push: (line: string) => ctrl.enqueue(enc.encode(line)),
    close: () => {
      try {
        ctrl.close();
      } catch {
        /* already closed */
      }
    },
  };
}

/** authFetch resolves at once with a 200 whose body is a controllableStream
 *  wired to the signal the caller passed in. Returns the push/close handle. */
function streamingResponse(): ReturnType<typeof controllableStream> {
  let handle!: ReturnType<typeof controllableStream>;
  mockedFetch.mockImplementation(async (_url: string, init?: RequestInit) => {
    handle = controllableStream(init?.signal ?? undefined);
    return new Response(handle.stream, { status: 200 });
  });
  return new Proxy({} as ReturnType<typeof controllableStream>, {
    get(_t, prop) {
      return (handle as unknown as Record<string, unknown>)[prop as string];
    },
  });
}

function frame(obj: Record<string, unknown>): string {
  return JSON.stringify(obj) + "\n";
}

beforeEach(() => {
  mockedFetch.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("startChat — frame handling", () => {
  it("splits a frame across chunk boundaries without dropping it", async () => {
    const s = streamingResponse();
    const tokens: string[] = [];
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" }, { onToken: (t) => tokens.push(t) });
    s.push('{"type":"jo');
    s.push('b","id":"abc"}\n{"type":"start"}\n{"type":"tok');
    s.push('en","t":"Hel');
    s.push('lo"}\n{"type":"done"}\n');
    s.close();
    await expect(h.result).resolves.toEqual({ kind: "done" });
    expect(tokens.join("")).toBe("Hello");
  });

  it("calls onJob, onQueue, onStart, onToken in order", async () => {
    const s = streamingResponse();
    const calls: string[] = [];
    const h = startChat(
      { prompt: "hi", systemPrompt: "", model: "m" },
      {
        onJob: (id) => calls.push(`job:${id}`),
        onQueue: (p, a, e) => calls.push(`queue:${p}/${a}/${e}`),
        onStart: () => calls.push("start"),
        onToken: (t) => calls.push(`token:${t}`),
      }
    );
    s.push(frame({ type: "job", id: "j1" }));
    s.push(frame({ type: "queue", position: 2, ahead: 1, eta_seconds: 10 }));
    s.push(frame({ type: "start" }));
    s.push(frame({ type: "token", t: "hi" }));
    s.push(frame({ type: "done" }));
    s.close();
    await h.result;
    expect(calls).toEqual(["job:j1", "queue:2/1/10", "start", "token:hi"]);
  });

  it("EOF without a terminal frame is a truncation, never done", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "job", id: "j1" }));
    s.push(frame({ type: "start" }));
    s.push(frame({ type: "token", t: "partial answer" }));
    s.close(); // server hung up mid-stream — no done, no error
    const outcome = await h.result;
    expect(outcome).toEqual({ kind: "interrupted", reason: "truncated", receivedChars: "partial answer".length });
  });

  it("a cancelled error frame (with code) ends the stream as cancelled", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "job", id: "j1" }));
    s.push(frame({ type: "error", detail: "cancelled", code: "cancelled" }));
    s.close();
    await expect(h.result).resolves.toEqual({ kind: "cancelled" });
  });

  it("a legacy cancelled frame (no code field) still maps to cancelled", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "error", detail: "cancelled" }));
    s.close();
    await expect(h.result).resolves.toEqual({ kind: "cancelled" });
  });

  it("an unknown error detail becomes a plain server ApiError with that message", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "error", detail: "Oyster couldn't finish that answer. Please try again." }));
    s.close();
    const outcome = await h.result;
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.error.kind).toBe("server");
      expect(outcome.error.message).toBe("Oyster couldn't finish that answer. Please try again.");
      expect(outcome.error.code).toBeUndefined();
    }
  });

  it("a known rate-limit code becomes a rate_limited ApiError with that code", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "error", detail: "chat_busy" }));
    s.close();
    const outcome = await h.result;
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.error.kind).toBe("rate_limited");
      expect(outcome.error.code).toBe("chat_busy");
    }
  });

  it("a malformed line is skipped rather than killing the stream", async () => {
    const s = streamingResponse();
    const tokens: string[] = [];
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" }, { onToken: (t) => tokens.push(t) });
    s.push("not json at all\n");
    s.push(frame({ type: "token", t: "ok" }));
    s.push(frame({ type: "done" }));
    s.close();
    await h.result;
    expect(tokens).toEqual(["ok"]);
  });
});

describe("resumeJob — onReset", () => {
  it("fires onReset once, before the first token, and never on a fresh start", async () => {
    const s = streamingResponse();
    const events: string[] = [];
    const h = resumeJob("job-1", {
      onReset: () => events.push("reset"),
      onToken: (t) => events.push(`token:${t}`),
    });
    s.push(frame({ type: "start" }));
    s.push(frame({ type: "token", t: "Hel" }));
    s.push(frame({ type: "token", t: "lo" }));
    s.push(frame({ type: "done" }));
    s.close();
    await h.result;
    expect(events).toEqual(["reset", "token:Hel", "token:lo"]);
  });

  it("startChat never fires onReset, even with tokens", async () => {
    const s = streamingResponse();
    const events: string[] = [];
    const h = startChat(
      { prompt: "hi", systemPrompt: "", model: "m" },
      { onReset: () => events.push("reset"), onToken: (t) => events.push(`token:${t}`) }
    );
    s.push(frame({ type: "token", t: "x" }));
    s.push(frame({ type: "done" }));
    s.close();
    await h.result;
    expect(events).toEqual(["token:x"]);
  });
});

describe("watchdog", () => {
  it("declares the stream stalled after true silence, resolving without waiting for close", async () => {
    vi.useFakeTimers();
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "job", id: "j1" }));
    s.push(frame({ type: "start" }));
    const assertion = expect(h.result).resolves.toEqual({
      kind: "interrupted",
      reason: "stalled",
      receivedChars: 0,
    });
    await vi.advanceTimersByTimeAsync(WATCHDOG_MS - 1);
    await vi.advanceTimersByTimeAsync(1);
    await assertion;
  });

  it("a keepalive resets the watchdog so a long wait never stalls", async () => {
    vi.useFakeTimers();
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "job", id: "j1" }));
    for (let i = 0; i < 4; i++) {
      await vi.advanceTimersByTimeAsync(WATCHDOG_MS - 5_000);
      s.push(frame({ type: "keepalive" })); // total elapsed would exceed WATCHDOG_MS without this
    }
    s.push(frame({ type: "done" }));
    s.close();
    await vi.runAllTimersAsync();
    await expect(h.result).resolves.toEqual({ kind: "done" });
  });
});

describe("abort()", () => {
  it("ends the stream as interrupted:aborted without waiting on any timer", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "job", id: "j1" }));
    h.abort();
    await expect(h.result).resolves.toEqual({ kind: "interrupted", reason: "aborted", receivedChars: 0 });
  });

  it("does not call cancelChatJob itself — the caller decides that separately", async () => {
    const s = streamingResponse();
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    s.push(frame({ type: "job", id: "j1" }));
    h.abort();
    await h.result;
    // Only the one streaming call was ever made — abort() made no second request.
    expect(mockedFetch).toHaveBeenCalledTimes(1);
  });
});

describe("the request never opens (hung POST)", () => {
  it("gives up after FIRST_FRAME_MS as interrupted:stalled", async () => {
    vi.useFakeTimers();
    mockedFetch.mockImplementation(
      (_url: string, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(Object.assign(new Error("aborted"), { name: "AbortError" }))
          );
        })
    );
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    const assertion = expect(h.result).resolves.toEqual({
      kind: "interrupted",
      reason: "stalled",
      receivedChars: 0,
    });
    await vi.advanceTimersByTimeAsync(FIRST_FRAME_MS);
    await assertion;
  });
});

describe("HTTP-level failure (never reaches the stream)", () => {
  it("a non-OK response becomes an ApiError, Retry-After included", async () => {
    mockedFetch.mockResolvedValue(
      new Response(JSON.stringify({ detail: "chat_one_at_a_time" }), {
        status: 429,
        headers: { "Content-Type": "application/json", "Retry-After": "5" },
      })
    );
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    const outcome = await h.result;
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") {
      expect(outcome.error.kind).toBe("rate_limited");
      expect(outcome.error.code).toBe("chat_one_at_a_time");
      expect(outcome.error.retryAfter).toBe(5);
    }
  });

  it("a rejected fetch (offline, DNS, CORS) becomes a network error", async () => {
    mockedFetch.mockRejectedValue(new TypeError("Failed to fetch"));
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    const outcome = await h.result;
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") expect(outcome.error.kind).toBe("network");
  });

  it("a body-less response cannot be streamed and surfaces as a network error", async () => {
    mockedFetch.mockResolvedValue(new Response(null, { status: 200 }));
    const h = startChat({ prompt: "hi", systemPrompt: "", model: "m" });
    const outcome = await h.result;
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") expect(outcome.error.kind).toBe("network");
  });
});

describe("resumeJob — job-not-found", () => {
  it("a 404 (job finished or gone) is a not_found ApiError, not a generic one", async () => {
    mockedFetch.mockResolvedValue(new Response(JSON.stringify({ detail: "job_not_found" }), { status: 404 }));
    const h = resumeJob("gone");
    const outcome = await h.result;
    expect(outcome.kind).toBe("error");
    if (outcome.kind === "error") expect(outcome.error.kind).toBe("not_found");
  });
});

describe("cancelChatJob", () => {
  it("posts to the cancel route for that job", async () => {
    mockedFetch.mockResolvedValue(new Response("{}", { status: 200 }));
    await cancelChatJob("job-9");
    expect(mockedFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockedFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/chat/jobs/job-9/cancel");
    expect(init.method).toBe("POST");
  });

  it("never throws — a failed cancel is not the caller's problem", async () => {
    mockedFetch.mockRejectedValue(new TypeError("network down"));
    await expect(cancelChatJob("job-9")).resolves.toBeUndefined();
  });
});
