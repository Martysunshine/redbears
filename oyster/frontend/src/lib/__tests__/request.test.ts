import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const session = { current: null as null | { access_token: string } };
vi.mock("@/lib/supabase", () => ({
  supabase: {
    auth: {
      getSession: async () => ({ data: { session: session.current } }),
    },
  },
}));

import { _resetInflightForTests, onUnauthorized, request } from "@/lib/request";
import { ApiError } from "@/lib/apiErrors";

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

beforeEach(() => {
  _resetInflightForTests();
  session.current = null;
  onUnauthorized(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("request", () => {
  it("shares one fetch between identical concurrent GETs", async () => {
    const fetchMock = vi.fn(async () => json(200, { ok: 1 }));
    vi.stubGlobal("fetch", fetchMock);
    const [a, b] = await Promise.all([request("/x"), request("/x")]);
    expect(a).toEqual({ ok: 1 });
    expect(b).toEqual({ ok: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries a GET after exactly Retry-After seconds", async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(503, { detail: "chat_busy" }, { "Retry-After": "2" }))
      .mockResolvedValueOnce(json(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);
    const p = request("/y");
    await vi.advanceTimersByTimeAsync(1_999);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await expect(p).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("never retries a mutation", async () => {
    const fetchMock = vi.fn(async () => json(503, { detail: "chat_busy" }, { "Retry-After": "1" }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(request("/m", { method: "POST" })).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("gives up on a hung request after the timeout as a network error", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: string, init?: RequestInit) =>
          new Promise((_, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(Object.assign(new Error("aborted"), { name: "AbortError" }))
            );
          })
      )
    );
    const p = request("/hang", {}, { timeoutMs: 1_000, retry: false });
    const assertion = expect(p).rejects.toMatchObject({ kind: "network" });
    await vi.advanceTimersByTimeAsync(1_000);
    await assertion;
  });

  it("raises onUnauthorized once when a token was attached and refused", async () => {
    session.current = { access_token: "tok" };
    const fetchMock = vi.fn(async () => json(401, { detail: "Not authenticated" }));
    vi.stubGlobal("fetch", fetchMock);
    const handler = vi.fn();
    onUnauthorized(handler);
    await request("/a", {}, { retry: false }).catch(() => {});
    await request("/b", {}, { retry: false }).catch(() => {});
    expect(handler).toHaveBeenCalledTimes(1);
    const sentHeaders = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Headers;
    expect(sentHeaders.get("Authorization")).toBe("Bearer tok");
  });

  it("a 401 without a token is just unauthorized, not a session signal", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(401, { detail: "Not authenticated" })));
    const handler = vi.fn();
    onUnauthorized(handler);
    await expect(request("/anon", {}, { retry: false })).rejects.toMatchObject({ kind: "unauthorized" });
    expect(handler).not.toHaveBeenCalled();
  });
});
