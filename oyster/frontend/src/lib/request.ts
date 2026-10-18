/**
 * The one way JSON requests leave the app.
 *
 *   - attaches the Supabase bearer when there is a session (authFetch)
 *   - a real timeout on every request (AbortController — AbortSignal.timeout
 *     is missing on older iOS builds, and getMe() had no timeout at all,
 *     which is how the app could sit on a blank pane forever)
 *   - identical in-flight GETs share one fetch (the boot sequence and the
 *     health poll used to fan out duplicates on every re-render)
 *   - GETs retry on network / 5xx / 429 with exponential backoff that
 *     honours Retry-After; mutations never retry (a POST is not idempotent)
 *   - non-OK responses become an ApiError with a kind the caller can branch on
 *   - a 401 that arrives while a bearer was attached is the "session expired"
 *     signal, raised once through onUnauthorized so AuthGate can show it
 */
import { supabase } from "@/lib/supabase";
import { ApiError, fromFetchFailure, toApiError } from "@/lib/apiErrors";

export interface RequestOptions {
  /** Milliseconds before the request is abandoned. Default 10 000. */
  timeoutMs?: number;
  /** Share the in-flight promise with other callers using the same key
   *  (GET only). Defaults to `${method} ${url}`. */
  dedupeKey?: string;
  /** Retry on network / 5xx / 429. Default: true for GET, false otherwise. */
  retry?: boolean;
  /** Caller-owned abort. Aborting this never triggers a retry. */
  signal?: AbortSignal;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_ATTEMPTS = 3;
const MAX_RETRY_DELAY_MS = 30_000;

let unauthorizedHandler: (() => void) | null = null;
let unauthorizedRaised = false;

/** AuthGate registers here; the callback fires once per expired session. */
export function onUnauthorized(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
  unauthorizedRaised = false;
}

/** Called by AuthGate when a fresh session arrives, so a later expiry can fire again. */
export function resetUnauthorized(): void {
  unauthorizedRaised = false;
}

/** Attach the current Supabase access token (if any) as a Bearer header.
 *  Returns whether a token was attached, which is what makes a 401 mean
 *  "expired" rather than "anonymous". */
export async function authFetchWithInfo(
  url: string,
  options: RequestInit = {}
): Promise<{ res: Response; authed: boolean }> {
  if (!supabase) return { res: await fetch(url, options), authed: false };
  let token: string | undefined;
  try {
    const { data } = await supabase.auth.getSession();
    token = data.session?.access_token;
  } catch {
    token = undefined;
  }
  if (!token) return { res: await fetch(url, options), authed: false };
  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return { res: await fetch(url, { ...options, headers }), authed: true };
}

/** The historic helper, kept for callers that need the raw Response. */
export async function authFetch(url: string, options: RequestInit = {}): Promise<Response> {
  return (await authFetchWithInfo(url, options)).res;
}

const inflight = new Map<string, Promise<unknown>>();

function delayFor(err: ApiError, attempt: number): number {
  if (err.retryAfter !== undefined) return Math.min(err.retryAfter * 1000, MAX_RETRY_DELAY_MS);
  const base = 500 * 2 ** attempt;
  return Math.min(base + Math.random() * 250, MAX_RETRY_DELAY_MS);
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new ApiError("aborted", "The request was cancelled."));
      },
      { once: true }
    );
  });
}

async function attempt(url: string, init: RequestInit, opts: RequestOptions): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const onCallerAbort = () => controller.abort();
  opts.signal?.addEventListener("abort", onCallerAbort, { once: true });
  try {
    const { res, authed } = await authFetchWithInfo(url, { ...init, signal: controller.signal });
    if (res.ok) {
      if (authed) unauthorizedRaised = false;
      return res;
    }
    const err = await toApiError(res);
    if (err.kind === "unauthorized" && authed && !unauthorizedRaised) {
      unauthorizedRaised = true;
      unauthorizedHandler?.();
    }
    throw err;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    const err = fromFetchFailure(e);
    // Our own timeout is a network-class failure worth retrying; the
    // caller's abort is final.
    if (err.kind === "aborted" && !opts.signal?.aborted) {
      throw new ApiError("network", "Oyster took too long to respond. Please try again.");
    }
    throw err;
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onCallerAbort);
  }
}

/** Perform a JSON request. Resolves to the parsed body (undefined for 204). */
export async function request<T>(
  url: string,
  init: RequestInit = {},
  opts: RequestOptions = {}
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const retry = opts.retry ?? method === "GET";
  const key = method === "GET" ? (opts.dedupeKey ?? `${method} ${url}`) : null;

  if (key && inflight.has(key)) return inflight.get(key) as Promise<T>;

  const run = (async (): Promise<T> => {
    let lastErr: ApiError | null = null;
    for (let n = 0; n < (retry ? MAX_ATTEMPTS : 1); n++) {
      try {
        const res = await attempt(url, init, opts);
        if (res.status === 204) return undefined as T;
        return (await res.json()) as T;
      } catch (e) {
        const err = e instanceof ApiError ? e : fromFetchFailure(e);
        lastErr = err;
        const canRetry = retry && err.retryable && n < MAX_ATTEMPTS - 1 && !opts.signal?.aborted;
        if (!canRetry) throw err;
        await sleep(delayFor(err, n), opts.signal);
      }
    }
    throw lastErr ?? new ApiError("network", "Request failed.");
  })();

  if (key) {
    inflight.set(key, run);
    run.finally(() => inflight.delete(key)).catch(() => {});
  }
  return run;
}

/** Test hook: forget every in-flight promise. */
export function _resetInflightForTests(): void {
  inflight.clear();
  unauthorizedRaised = false;
}
