import { describe, expect, it } from "vitest";
import { explainChatError, fromFetchFailure, parseRetryAfter, toApiError } from "@/lib/apiErrors";
import { GENERIC_SERVER_ERROR } from "@/lib/errors";

function res(status: number, body?: unknown, headers: Record<string, string> = {}, raw = false): Response {
  const init: ResponseInit = {
    status,
    headers: { "Content-Type": raw ? "text/html" : "application/json", ...headers },
  };
  const payload = body === undefined ? null : raw ? String(body) : JSON.stringify(body);
  return new Response(payload, init);
}

describe("toApiError", () => {
  it("401 is unauthorized", async () => {
    const e = await toApiError(res(401, { detail: "Not authenticated" }));
    expect(e.kind).toBe("unauthorized");
    expect(e.status).toBe(401);
  });

  it("403 keeps the backend's short code", async () => {
    const e = await toApiError(res(403, { detail: "terms_acceptance_required" }));
    expect(e.kind).toBe("forbidden");
    expect(e.code).toBe("terms_acceptance_required");
  });

  it("404 is not_found (the API hides other people's rows this way)", async () => {
    const e = await toApiError(res(404, { detail: "job_not_found" }));
    expect(e.kind).toBe("not_found");
    expect(e.code).toBe("job_not_found");
  });

  it("429 with a code and Retry-After is rate_limited with both", async () => {
    const e = await toApiError(res(429, { detail: "chat_one_at_a_time" }, { "Retry-After": "42" }));
    expect(e.kind).toBe("rate_limited");
    expect(e.code).toBe("chat_one_at_a_time");
    expect(e.retryAfter).toBe(42);
    expect(e.retryable).toBe(true);
  });

  it("an nginx 429 with no JSON body is still rate_limited, code rate_limited", async () => {
    const e = await toApiError(res(429, "<html>429</html>", { "Retry-After": "1" }, true));
    expect(e.kind).toBe("rate_limited");
    expect(e.code).toBe("rate_limited");
    expect(e.retryAfter).toBe(1);
  });

  it("503 with Retry-After (chat_busy) is rate_limited; 503 without is server", async () => {
    const busy = await toApiError(res(503, { detail: "chat_busy" }, { "Retry-After": "30" }));
    expect(busy.kind).toBe("rate_limited");
    expect(busy.code).toBe("chat_busy");
    const down = await toApiError(res(503, { detail: "unavailable" }));
    expect(down.kind).toBe("server");
  });

  it("a 500 never shows an exception's own words", async () => {
    const e = await toApiError(res(500, { detail: "ConnectionError: http://host.docker.internal:11434" }));
    expect(e.kind).toBe("server");
    expect(e.message).toBe(GENERIC_SERVER_ERROR);
    expect(e.message).not.toContain("11434");
  });

  it("other 4xx keep their validation text", async () => {
    const e = await toApiError(res(413, { detail: "That prompt is too long." }));
    expect(e.kind).toBe("bad_request");
    expect(e.message).toBe("That prompt is too long.");
  });
});

describe("fromFetchFailure", () => {
  it("maps a failed fetch to network and an abort to aborted", () => {
    expect(fromFetchFailure(new TypeError("Failed to fetch")).kind).toBe("network");
    const abort = Object.assign(new Error("x"), { name: "AbortError" });
    expect(fromFetchFailure(abort).kind).toBe("aborted");
  });
});

describe("parseRetryAfter", () => {
  it("reads seconds and HTTP dates", () => {
    expect(parseRetryAfter(res(429, undefined, { "Retry-After": "7" }))).toBe(7);
    const later = new Date(Date.now() + 90_000).toUTCString();
    const n = parseRetryAfter(res(429, undefined, { "Retry-After": later }));
    expect(n).toBeGreaterThanOrEqual(88);
    expect(n).toBeLessThanOrEqual(90);
    expect(parseRetryAfter(res(429))).toBeUndefined();
  });
});

describe("explainChatError", () => {
  it("turns codes into sentences with the real wait", async () => {
    const one = await toApiError(res(429, { detail: "chat_one_at_a_time" }, { "Retry-After": "120" }));
    expect(explainChatError(one)).toContain("about 2 minutes");
    const nginx = await toApiError(res(429, "429", { "Retry-After": "1" }, true));
    expect(explainChatError(nginx)).toContain("about 1 second");
    const expired = await toApiError(res(401));
    expect(explainChatError(expired)).toMatch(/session has expired/i);
    const busy = await toApiError(res(503, { detail: "chat_busy" }, { "Retry-After": "45" }));
    expect(explainChatError(busy)).toContain("about 45 seconds");
  });
});
