/**
 * One error type for everything the API layer can throw.
 *
 * Until 2026-09-14 the readers in lib/api.ts turned every non-OK response into
 * `[]` or `null` — a 429 storm, an expired session and an empty workspace all
 * rendered as the same friendly, empty Oyster, and the only way out was a
 * browser refresh. Callers now get a typed reason they can branch on, and the
 * request layer (lib/request.ts) can decide what is worth retrying.
 *
 * `message` is always fit for a person: it goes through friendlyError, so an
 * exception's own words (hosts, ports, paths) never reach the screen.
 */
import { friendlyError } from "@/lib/errors";

export type ApiErrorKind =
  | "unauthorized"   // 401 — the session is gone or was never there
  | "forbidden"      // 403 — signed in, but not allowed (e.g. terms_acceptance_required)
  | "not_found"      // 404 — including "someone else's row", which the API hides as 404
  | "rate_limited"   // 429, or 503 with a Retry-After — come back in a bit
  | "bad_request"    // other 4xx — validation text meant for the user
  | "server"         // 5xx
  | "network"        // fetch itself failed: offline, DNS, CORS, a severed connection
  | "aborted";       // we cancelled it (timeout or an explicit abort)

const RETRYABLE: ReadonlySet<ApiErrorKind> = new Set<ApiErrorKind>(["rate_limited", "server", "network"]);

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status?: number;
  /** The backend's short code when it sent one (anon_daily_limit, chat_busy, …). */
  readonly code?: string;
  /** Seconds, from the Retry-After header when the server sent one. */
  readonly retryAfter?: number;

  constructor(
    kind: ApiErrorKind,
    message: string,
    opts: { status?: number; code?: string; retryAfter?: number } = {}
  ) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = opts.status;
    this.code = opts.code;
    this.retryAfter = opts.retryAfter;
  }

  get retryable(): boolean {
    return RETRYABLE.has(this.kind);
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

/** Retry-After may be seconds or an HTTP date; either becomes seconds from now. */
export function parseRetryAfter(res: Response): number | undefined {
  const raw = res.headers.get("Retry-After");
  if (!raw) return undefined;
  const n = Number(raw);
  if (Number.isFinite(n) && n >= 0) return Math.round(n);
  const when = Date.parse(raw);
  if (!Number.isNaN(when)) return Math.max(0, Math.round((when - Date.now()) / 1000));
  return undefined;
}

/** Map a non-OK Response to an ApiError. Reads the body once (a clone), so
 *  the caller may still consume the original if it needs to. */
export async function toApiError(res: Response): Promise<ApiError> {
  let detail: unknown;
  try {
    const body = await res.clone().json();
    detail = body && typeof body === "object" && "detail" in body ? (body as { detail: unknown }).detail : body;
  } catch {
    // Not JSON: an nginx or proxy error page. friendlyError gets the status only.
    detail = undefined;
  }
  const retryAfter = parseRetryAfter(res);
  const code =
    typeof detail === "string"
      ? detail
      : detail && typeof detail === "object" && typeof (detail as { code?: unknown }).code === "string"
        ? (detail as { code: string }).code
        : undefined;
  const message = friendlyError(res.status, detail ?? `Backend error ${res.status}`);
  const s = res.status;
  const opts = { status: s, code, retryAfter };

  if (s === 401) return new ApiError("unauthorized", message, opts);
  if (s === 403) return new ApiError("forbidden", message, opts);
  if (s === 404) return new ApiError("not_found", message, opts);
  if (s === 429 || (s === 503 && retryAfter !== undefined)) {
    return new ApiError("rate_limited", message, { ...opts, code: code ?? "rate_limited" });
  }
  if (s >= 500) return new ApiError("server", message, opts);
  return new ApiError("bad_request", message, opts);
}

/** Map a thrown fetch failure (TypeError, AbortError) to an ApiError. */
export function fromFetchFailure(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  const name = err instanceof Error ? err.name : "";
  if (name === "AbortError" || name === "TimeoutError") {
    return new ApiError("aborted", "The request was cancelled.");
  }
  return new ApiError(
    "network",
    "Can't reach Oyster right now. Check your connection and try again."
  );
}

function inAbout(seconds: number | undefined): string {
  const s = Math.max(1, Math.round(seconds ?? 1));
  if (s > 90) {
    const m = Math.round(s / 60);
    return `about ${m} minute${m === 1 ? "" : "s"}`;
  }
  return `about ${s} second${s === 1 ? "" : "s"}`;
}

/**
 * Turn the backend's short error codes into something worth reading.
 *
 * The codes are deliberately terse on the wire (they are also read by logs
 * and tests); showing "chat_one_at_a_time" to a person is not an error
 * message, it is a leak of an internal name.
 */
export function explainChatError(err: ApiError): string {
  switch (err.code) {
    case "chat_one_at_a_time":
      return `Your previous message is still generating — it should finish in ${inAbout(err.retryAfter ?? 5)}. Oyster runs one answer per person at a time so nobody gets stuck behind a queue.`;
    case "chat_busy":
      return `Oyster is at capacity right now. Try again in ${inAbout(err.retryAfter ?? 30)}.`;
    case "anon_daily_limit":
      return "You've used today's free message. Sign in for unlimited chat.";
    case "rate_limited":
      return `You're sending requests a little too fast. Give it ${inAbout(err.retryAfter)} and try again.`;
    case "terms_acceptance_required":
      return "Please accept the user agreement to continue.";
    case "job_not_found":
      return "That generation is no longer available — it finished or the connection was reset.";
    default:
      break;
  }
  if (err.kind === "unauthorized") return "Your session has expired. Sign in again to continue.";
  if (err.kind === "network") return err.message;
  return err.message;
}
