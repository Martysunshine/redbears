/**
 * The chat stream controller.
 *
 * Replaces the old streamChat/consumeFrames/resumeChatJob trio (api.ts), which
 * had no timeout, no abort, and treated an EOF WITHOUT a terminal frame as a
 * clean finish — so a truncated answer (the server restarting, iOS suspending
 * the tab mid-stream, the network dropping) was persisted as if it were
 * complete, and a stream that simply went quiet left the composer dead with no
 * message and no way out but a browser refresh. Those are three of the exact
 * symptoms this reliability work set out to kill.
 *
 * What this adds:
 *   - a real AbortController on the fetch AND the reader, so Stop and the
 *     watchdog can actually end an in-flight generation;
 *   - a watchdog: if no frame arrives for `watchdogMs` the stream is declared
 *     `interrupted:"stalled"` rather than hanging forever. The server sends a
 *     keepalive every ~20 s (chat_queue.watch), and those RESET the watchdog —
 *     so 45 s of true silence is a real stall, not a slow model;
 *   - EOF without a terminal frame is `interrupted:"truncated"`, NEVER `done`,
 *     so a half-answer is kept as a resumable partial, not saved as final;
 *   - the cancelled error frame (B2: `code:"cancelled"`) ends the stream as
 *     `cancelled`, distinct from a real error;
 *   - `onReset`, fired before the first token of a RESUME, because the
 *     re-attach view re-sends the whole answer from the start — the bubble
 *     must be replaced, not appended to.
 *
 * The work is owned by the JOB on the backend, not by this handle: aborting or
 * losing the stream never cancels the generation (that needs cancelChatJob),
 * which is what makes a dropped phone able to come back and resume.
 */
import { ApiError, toApiError } from "@/lib/apiErrors";
import { KNOWN_CODES } from "@/lib/errors";
import { authFetch } from "@/lib/request";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8001";

/** No frame at all for this long → the stream is stalled. Longer than the
 *  server's 20 s heartbeat so a slow model (which still heartbeats) is never
 *  mistaken for a dead connection. */
export const WATCHDOG_MS = 45_000;
/** The very first frame (job) has this long to arrive before we give up on
 *  the request itself — a hung POST that never streams a byte. */
export const FIRST_FRAME_MS = 60_000;

export type InterruptReason = "stalled" | "truncated" | "network" | "aborted";

export type StreamOutcome =
  | { kind: "done" }
  | { kind: "cancelled" }
  | { kind: "error"; error: ApiError }
  | { kind: "interrupted"; reason: InterruptReason; receivedChars: number };

export interface StreamCallbacks {
  /** The job id — persist it so a refresh can re-attach. Fires once, first. */
  onJob?: (jobId: string) => void;
  /** Place in line while waiting for a slot. */
  onQueue?: (position: number, ahead: number, etaSeconds: number) => void;
  /** Generation has begun (first real work, before the first token). */
  onStart?: () => void;
  /** A delta of answer text. */
  onToken?: (text: string) => void;
  /** RESUME ONLY: fires once, before the first token, because the re-attach
   *  stream repeats the whole answer from the beginning. The bubble must clear
   *  its content here so the repeated text replaces rather than doubles. */
  onReset?: () => void;
}

export interface StreamHandle {
  /** Stop reading. Ends `result` as `interrupted:"aborted"`. Does NOT cancel
   *  the backend job — call cancelChatJob for that. */
  abort: () => void;
  /** Resolves when the stream ends, however it ends. Never rejects. */
  result: Promise<StreamOutcome>;
}

/** A prior turn sent to the backend so a follow-up has context. */
export interface ChatHistoryTurn {
  role: "user" | "assistant";
  content: string;
}

export interface StartChatParams {
  prompt: string;
  systemPrompt: string;
  model: string;
  agentMode?: string;
  /** Prior turns of THIS conversation, so "and the second one?" is answered
   *  in context instead of blind. The backend trims it to the model's context
   *  budget; omitted (a first message, or an anonymous chat, which is
   *  deliberately historyless) keeps the old stateless behaviour. */
  history?: ChatHistoryTurn[];
  conversationId?: string | null;
  responseDepth?: "overview" | "technical" | "guided" | "operational";
}

interface Tunables {
  watchdogMs?: number;
  firstFrameMs?: number;
}

const RATE_CODES = new Set(["chat_busy", "chat_one_at_a_time", "anon_daily_limit", "rate_limited"]);

/** Build an ApiError from an NDJSON `error` frame's detail. The detail is
 *  either a short code (anon_daily_limit, chat_busy, …) or a sentence the
 *  backend already wrote for a person; either way explainChatError renders it. */
function errorFromFrame(detail: string): ApiError {
  const code = KNOWN_CODES.has(detail) ? detail : undefined;
  const kind = code && RATE_CODES.has(code) ? "rate_limited" : "server";
  return new ApiError(kind, detail, { code });
}

interface Frame {
  type: string;
  [k: string]: unknown;
}

/**
 * Drive one NDJSON stream to an outcome. Shared by startChat and resumeJob so
 * the two paths can never disagree on what a truncation or a cancel means.
 */
async function consume(
  response: Response,
  cb: StreamCallbacks,
  isResume: boolean,
  controller: AbortController,
  abortReason: { value: InterruptReason | null },
  watchdogMs: number
): Promise<StreamOutcome> {
  const reader = response.body?.getReader();
  if (!reader) {
    return { kind: "error", error: new ApiError("network", "No response from Oyster. Please try again.") };
  }
  const decoder = new TextDecoder();
  let buffer = "";
  let received = 0;
  let didReset = false;
  let terminal: StreamOutcome | null = null;

  // The watchdog: any frame (token, queue, keepalive) resets it; true silence
  // trips it. It aborts the reader, which surfaces below as `abortReason`.
  let watchdog: ReturnType<typeof setTimeout> | null = null;
  const kick = () => {
    if (watchdog) clearTimeout(watchdog);
    watchdog = setTimeout(() => {
      abortReason.value = "stalled";
      controller.abort();
    }, watchdogMs);
  };

  const handle = (line: string) => {
    if (!line.trim()) return;
    let f: Frame;
    try {
      f = JSON.parse(line) as Frame;
    } catch {
      return; // a partial or malformed line — skip, never kill the stream
    }
    switch (f.type) {
      case "job":
        cb.onJob?.(String(f.id));
        break;
      case "queue":
        cb.onQueue?.(Number(f.position), Number(f.ahead), Number(f.eta_seconds));
        break;
      case "start":
        cb.onStart?.();
        break;
      case "token": {
        if (isResume && !didReset) {
          didReset = true;
          cb.onReset?.();
        }
        const t = String(f.t ?? "");
        received += t.length;
        cb.onToken?.(t);
        break;
      }
      case "keepalive":
        break; // its whole job is to reset the watchdog, which kick() already did
      case "done":
        terminal = { kind: "done" };
        break;
      case "error":
        terminal =
          f.code === "cancelled" || f.detail === "cancelled"
            ? { kind: "cancelled" }
            : { kind: "error", error: errorFromFrame(String(f.detail ?? "generation failed")) };
        break;
    }
  };

  try {
    kick();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      kick();
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop() ?? "";
      for (const line of lines) {
        handle(line);
        if (terminal) break;
      }
      if (terminal) break;
    }
    if (!terminal && buffer.trim()) handle(buffer);
    if (terminal) return terminal;
    // Stream ended with no terminal frame: a truncation, never a clean finish.
    return { kind: "interrupted", reason: "truncated", receivedChars: received };
  } catch (err) {
    if (terminal) return terminal;
    const reason = abortReason.value ?? classifyReadError(err);
    return { kind: "interrupted", reason, receivedChars: received };
  } finally {
    if (watchdog) clearTimeout(watchdog);
    try {
      await reader.cancel();
    } catch {
      /* already closed */
    }
  }
}

function classifyReadError(err: unknown): InterruptReason {
  const name = err instanceof Error ? err.name : "";
  if (name === "AbortError") return "aborted";
  return "network";
}

/** Common shell: open the request, map a non-OK response to an error outcome,
 *  then hand the body to consume(). Never rejects. */
function run(
  open: (signal: AbortSignal) => Promise<Response>,
  cb: StreamCallbacks,
  isResume: boolean,
  tun: Tunables
): StreamHandle {
  const controller = new AbortController();
  const abortReason: { value: InterruptReason | null } = { value: null };

  const abort = () => {
    if (abortReason.value === null) abortReason.value = "aborted";
    controller.abort();
  };

  // A ceiling on "opened the request but not one byte back yet".
  const firstFrame = setTimeout(() => {
    if (abortReason.value === null) abortReason.value = "stalled";
    controller.abort();
  }, tun.firstFrameMs ?? FIRST_FRAME_MS);

  const result: Promise<StreamOutcome> = (async () => {
    let response: Response;
    try {
      response = await open(controller.signal);
    } catch (err) {
      clearTimeout(firstFrame);
      if (abortReason.value === "aborted") {
        return { kind: "interrupted", reason: "aborted", receivedChars: 0 } as StreamOutcome;
      }
      const name = err instanceof Error ? err.name : "";
      if (name === "AbortError") {
        return {
          kind: "interrupted",
          reason: abortReason.value ?? "stalled",
          receivedChars: 0,
        } as StreamOutcome;
      }
      return {
        kind: "error",
        error: new ApiError("network", "Can't reach Oyster right now. Check your connection and try again."),
      };
    }
    clearTimeout(firstFrame);
    if (!response.ok) {
      return { kind: "error", error: await toApiError(response) };
    }
    return consume(response, cb, isResume, controller, abortReason, tun.watchdogMs ?? WATCHDOG_MS);
  })();

  return { abort, result };
}

/** Start a new generation. */
export function startChat(params: StartChatParams, cb: StreamCallbacks = {}, tun: Tunables = {}): StreamHandle {
  return run(
    (signal) =>
      authFetch(`${API_URL}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
        body: JSON.stringify({
          prompt: params.prompt,
          system_prompt: params.systemPrompt,
          model: params.model,
          agent_mode: params.agentMode ?? "chat",
          history: params.history ?? [],
          conversation_id: params.conversationId ?? null,
          response_depth: params.responseDepth ?? "overview",
        }),
        signal,
      }),
    cb,
    false,
    tun
  );
}

/** Re-attach to a job still running server-side (after a refresh, or a phone
 *  waking mid-answer). The view repeats the whole answer, hence onReset. */
export function resumeJob(jobId: string, cb: StreamCallbacks = {}, tun: Tunables = {}): StreamHandle {
  return run(
    (signal) =>
      authFetch(`${API_URL}/chat/jobs/${jobId}/stream`, {
        headers: { Accept: "application/x-ndjson" },
        signal,
      }),
    cb,
    true,
    tun
  );
}

/** Ask the backend to stop a job (the Stop button, and the way out of
 *  `chat_one_at_a_time` when the job in the way is one we lost track of).
 *  Best-effort: a failure here never blocks the UI. */
export async function cancelChatJob(jobId: string): Promise<void> {
  try {
    await authFetch(`${API_URL}/chat/jobs/${jobId}/cancel`, { method: "POST" });
  } catch {
    /* the job may already be gone; nothing to do */
  }
}
