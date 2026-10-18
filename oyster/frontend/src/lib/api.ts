import type { Citation, OysterDocument, OysterModel, ScopeConfig, Severity, UserFinding } from "@/types/chat";
import { friendlyError } from "@/lib/errors";
import { authFetch, request } from "@/lib/request";
import type { ChatHistoryTurn } from "@/lib/chatStream";

// authFetch now lives in lib/request.ts (with the timeout, dedup, retry and
// session-expired signalling around it); re-exported so nothing else moves.
export { authFetch };

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8001";

// Bug reports do NOT go to the Oyster backend. That box is local SQLite +
// Ollama with no Postgres, no object storage and no mail sender; the Red Orca
// platform API has all three plus Supabase JWT verification, and both apps
// sign in against the SAME Supabase project — so one endpoint there gives one
// inbox instead of two half-built ones. See Voiceiq/backend/app/routes/bug_reports.py.
//
// Defaults to production because an unset env var on a Vercel build would
// otherwise silently disable the button. For LOCAL dev set
// NEXT_PUBLIC_REDORCA_API_URL=http://localhost:8001 so you don't file real ones.
const REDORCA_API_URL =
  process.env.NEXT_PUBLIC_REDORCA_API_URL || "https://api.redorca.tech";

/** Limits the UI enforces before upload. The server's are authoritative;
 *  these exist so an oversized clip fails instantly and locally instead of
 *  after a long upload. Keep in step with config.BUG_REPORT_*. */
export const BUG_REPORT_LIMITS = {
  maxImages: 3,
  maxImageMB: 10,
  maxVideoMB: 40,
  /** Checked in the browser via <video>.duration — the backend image has no
   *  ffprobe, so the server guarantees SIZE and the client guarantees length. */
  maxVideoSeconds: 15,
} as const;

export interface BugReportResult {
  id: number;
  attachments_stored: number;
  attachments_received: number;
  emailed: boolean;
}

/** File a bug report. Works signed-out (Oyster has an anonymous tier); when a
 *  session exists the server uses ITS email and ignores whatever is sent here. */
export async function submitBugReport(data: {
  description: string;
  email: string;
  page?: string;
  files?: File[];
}): Promise<BugReportResult> {
  const fd = new FormData();
  fd.append("app", "oyster");
  fd.append("description", data.description);
  fd.append("email", data.email);
  if (data.page) fd.append("page", data.page);
  (data.files ?? []).forEach((f) => fd.append("files", f, f.name));

  // authFetch, not fetch: a signed-in reporter must be attributable. It is a
  // no-op for an anonymous caller, which is exactly the intended behaviour.
  const res = await authFetch(`${REDORCA_API_URL}/bug-reports`, {
    method: "POST",
    body: fd,
  });
  if (!res.ok) {
    let detail = "";
    try {
      detail = ((await res.json()) as { detail?: string }).detail ?? "";
    } catch {
      /* a non-JSON error body (proxy timeout, 413) still needs a message */
    }
    throw new Error(detail || `Could not send the report (HTTP ${res.status}).`);
  }
  return (await res.json()) as BugReportResult;
}

// The socmat "SOC Copilot" API is mounted inside the Oyster backend at
// /socmat/api (see backend/main.py). All Blue Team → SOC Copilot calls go
// through this base and inherit the same Supabase bearer auth via authFetch.
export const SOCMAT_API = `${API_URL}/socmat/api`;

// Tier probe for UI gating (backend: routers/chat.py GET /me — public, never
// consumes the anonymous daily allowance). The backend remains the enforcer;
// this only decides which UI to show.
/** What the backend records about this account's acceptance of the agreement. */
export interface AgreementState {
  /** True when this account must accept before it may chat (public users). */
  required: boolean;
  accepted: boolean;
  accepted_version: string | null;
  accepted_at: string | null;
  current_version: string;
}

export interface MeResponse {
  tier: "anon" | "user" | "admin";
  remaining_today?: number;
  email?: string;
  training_consent?: boolean;
  agreement?: AgreementState;
}

// 8 s and retried: this call decides whether the app shows anything at all,
// and it used to have no timeout — a hung /me left a blank pane forever.
export async function getMe(): Promise<MeResponse> {
  return request<MeResponse>(`${API_URL}/me`, {}, { timeoutMs: 8000 });
}

/** Per-category counts of what the backend erased. */
export interface AccountDeletionResult {
  status: "deleted" | "partial";
  deleted: {
    conversations: number;
    artifacts: number;
    memories: number;
    project: boolean;
    agreement: number;
    upload_quota: number;
  };
  failures: string[];
}

// Erase everything Oyster holds for this account. This does NOT remove the
// Supabase login record — that needs privileges this backend deliberately
// doesn't have (see services/account_deletion.py); AuthGate does that second
// step by calling Supabase's own security-definer function.
export async function deleteAccount(): Promise<AccountDeletionResult> {
  const res = await authFetch(`${API_URL}/me`, { method: "DELETE" });
  if (!res.ok) return handleError(res);
  return res.json();
}

// Accept the user agreement, or withdraw it. Acceptance is REQUIRED to use the
// chat as a signed-in user (backend: /chat returns 403 terms_acceptance_required
// without it), so withdrawing also ends access until they accept again.
//
// `token` exists for the sign-up path: immediately after supabase.auth.signUp
// the client's stored session is not readable yet, so authFetch would send the
// request unauthenticated and the backend would (correctly) ignore it —
// silently losing the acceptance the user just gave. Pass the fresh access token.
export async function setTrainingConsent(
  allowed: boolean,
  token?: string
): Promise<{ allowed: boolean; agreement?: AgreementState }> {
  const url = `${API_URL}/me/training-consent`;
  const init: RequestInit = {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ allowed }),
  };
  const res = token
    ? await fetch(url, { ...init, headers: { ...init.headers, Authorization: `Bearer ${token}` } })
    : await authFetch(url, init);
  if (!res.ok) return handleError(res);
  return res.json();
}

// Labels are intentionally generic (no vendor/model names shown in the UI —
// "key" still maps to the real Ollama model in the backend's MODEL_REGISTRY).
// Ordered fastest-first, and the DEFAULT is the small model on purpose.
//
// The server has 7.8 GB of RAM and keeps the 2.5 GB public model resident. An
// 8B is ~5 GB, so defaulting signed-in accounts to one meant the two could not
// both be loaded: Ollama evicted the public model to make room, and a real
// chat failed mid-load under the pressure. The heavier models are still one
// click away — they are now a deliberate choice, and the descriptions say what
// that choice costs so nobody picks "better" without knowing it means slower.
// Ordered fastest-first, and the descriptions are measured rather than adjectival
// — "much slower" told nobody whether that meant two seconds or two minutes.
// Figures are tokens/sec on the inference node for a short answer.
//
// Reasoning is the one option that can be unavailable: Qwen 14B is 9 GB against
// this server's 7.8 GB of RAM, so it exists ONLY on the inference node. When
// that machine is asleep the backend says so in a sentence (see
// services/ollama_service.py::_model_missing) instead of failing cryptically —
// every other model runs in both places and is always available.
export const MODELS: OysterModel[] = [
  { key: "oyster-dolphin-v2", label: "Oyster Dolphin V2", description: "Local 8B · transformed (refusal-ablated) Dolphin 3.0, GGUF · default" },
  { key: "oyster-dolphin-v1", label: "Oyster Dolphin V1", description: "Local 8B · transformed (refusal-ablated) Dolphin 3.0 · previous default (rollback)" },
  { key: "huihui-qwen3.8-27b", label: "Huihui Qwen3.8 27B", description: "Local 27B · upstream huihui-ai abliterated Qwen3.8, UD-IQ4_XS GGUF · not an Oyster-transformed model" },
  { key: "dolphin3", label: "Dolphin 3", description: "Local CPU 8B · unmodified baseline (not abliterated)" },
  { key: "oyster-1x", label: "Oyster-1X", description: "Local Heretic Q3_K_M" },
  { key: "oyster-edge-v1-q4", label: "Oyster Edge V1 Q4", description: "Local CPU Q4_K_M · experimental, lightweight" },
  { key: "oyster-edge-v1-q4-v2", label: "Oyster Edge V1 Q4 v2", description: "Local CPU Q4_K_M · experimental, lightweight" },
  { key: "oyster-edge-v1-q4-v3", label: "Oyster Edge V1 Q4 v3", description: "Local CPU Q4_K_M · experimental, lightweight" },
  { key: "llama3.2-3b", label: "Quick", description: "Fastest · recommended" },
  { key: "dolphin-llama3", label: "Balanced", description: "Stronger · about 2× slower" },
  { key: "dolphin-mistral", label: "Detailed", description: "Long, thorough answers · slower" },
  { key: "hermes", label: "Agent", description: "Agent personality · slower" },
  { key: "qwen-14b", label: "Reasoning", description: "Local 14B · deepest reasoning, ~3× slower" },
];
// 2026-09-30 — was oyster-edge-v1-q4-v3. That Edge lineage (0.8B, qwen3.5)
// failed Oyster's quality gates after conversation-handling bugs were fixed
// and ruled out as the cause: invented tools/commands and wrong technical
// facts (e.g. "16-bit MAC address", fabricated CLI flags), confirmed against
// its own F16 source and against dolphin3:latest — see
// oyster/docs/AI_HANDOFF.md. dolphin3 is unmodified/not abliterated; it is
// the default for factual reliability, not for permissiveness.
//
// 2026-09-30 — default is now oyster-dolphin-v1 (transformed/refusal-ablated
// Dolphin 3.0 8B), which passed Oyster's 101-case live quality gate with the
// same factual accuracy as dolphin3 (0 errors, 0 transcript/think leaks, 0
// empty, only the deliberately-baited fabrication). dolphin3 stays the
// rollback baseline and the anonymous/public model; see oyster/docs/AI_HANDOFF.md.
// 2026-10-08 — default promoted to oyster-dolphin-v2: the same refusal-ablated
// Dolphin 3.0 8B lineage one generation on, exported to GGUF (Q4_K_M) so it
// serves on the fast llama.cpp runner at V1-parity latency (the MLX build of
// the same weights was ~1.85x slower). Held-out gate (96 cases) at parity with
// V1. V1 stays selectable as the rollback; dolphin3 stays the anonymous/public
// baseline. See oyster/docs/AI_HANDOFF.md.
/** The ONLY answer models offered in the hackathon UI, mapped to their existing
 *  working backend configurations. Every other entry in MODELS (V1, Dolphin 3,
 *  Edge, Reasoning, …) stays configured in the backend registry and callable by
 *  key — it is just not offered in the normal UI. */
export const UI_MODELS: OysterModel[] = [
  { key: "oyster-dolphin-v2", label: "Oyster", description: "Local 8B · Oyster Dolphin V2 (transformed Dolphin 3.0, GGUF Q4_K_M) · default · fastest" },
  { key: "huihui-qwen3.8-27b", label: "Huihui", description: "Local 27B · upstream huihui-ai abliterated Qwen3.8 (UD-IQ3_XXS) · slower, stronger grounding" },
];
export const UI_MODEL_KEYS = UI_MODELS.map((m) => m.key);

export const DEFAULT_MODEL = "oyster-dolphin-v2";

async function handleError(res: Response): Promise<never> {
  let detail: unknown = `Backend error ${res.status}`;
  try {
    const body = await res.json();
    detail = body.detail ?? detail;
  } catch {
    // ignore parse errors
  }
  // A 5xx string is never shown raw — see lib/errors.ts for the rule.
  throw new Error(friendlyError(res.status, detail));
}

// Chat streaming/resume/cancel now lives in lib/chatStream.ts (startChat,
// resumeJob, cancelChatJob) — it replaced streamChat/resumeChatJob/
// consumeFrames with a controller that has a real timeout, a real abort, a
// watchdog against silent stalls, and a truncated-vs-done distinction. See
// that file's header for why. explainChatError moved to lib/apiErrors.ts,
// next to the ApiError type it now reads (kind + real Retry-After), instead
// of re-parsing the header from a raw Response. `ChatHistoryTurn` and the
// `history`/`conversationId` fields on `StartChatParams` live there too.

// ---------------------------------------------------------------------------
// Document search — returns raw chunks
// ---------------------------------------------------------------------------

export async function searchDocuments(
  query: string,
  topK = 5
): Promise<{ results: Citation[]; query: string; total: number }> {
  const res = await authFetch(`${API_URL}/documents/search`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, top_k: topK }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: string;
  default_model?: string;
  ollama: boolean;
  ollama_via?: "primary" | "fallback" | null;
  ollama_primary?: boolean;
  probe_age_s?: number | null;
}

// A poll, not a request: no retries (the next tick is the retry) and one
// in-flight call at a time no matter how many effects ask.
export async function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>(`${API_URL}/health`, {}, {
    timeoutMs: 3000,
    retry: false,
    dedupeKey: "health",
  });
}

// ---------------------------------------------------------------------------
// Projects (read-only, for the project selector) — backend Slice 1
// ---------------------------------------------------------------------------

export interface ProjectSummary {
  id: string;
  name: string;
  description?: string;
  is_active?: boolean;
}

// These THROW an ApiError on failure (lib/apiErrors.ts). They used to return
// null for a 401, a 429 and a network drop alike, and the boot rendered every
// one of those as an empty workspace. Callers decide what a failure means.
export async function getActiveProject(): Promise<{ project: ProjectSummary }> {
  return request(`${API_URL}/projects/active`, {}, { timeoutMs: 6000 });
}

export async function listProjects(): Promise<{ projects: ProjectSummary[]; active_id: string }> {
  return request(`${API_URL}/projects`, {}, { timeoutMs: 6000 });
}

/** Switch the globally-active project (operators only). Returns the activated
 *  project, or null on failure. The backend also re-syncs scope to it. */
export async function activateProject(id: string): Promise<ProjectSummary | null> {
  try {
    const res = await authFetch(`${API_URL}/projects/${id}/activate`, { method: "POST" });
    if (!res.ok) return null;
    return (await res.json()).project ?? null;
  } catch {
    return null;
  }
}

/** Create a new project. `activate: true` makes it the active one immediately. */
export async function createProject(
  name: string,
  description?: string,
  activate = true
): Promise<ProjectSummary | null> {
  try {
    const res = await authFetch(`${API_URL}/projects`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description, activate }),
    });
    if (!res.ok) return null;
    return (await res.json()).project ?? null;
  } catch {
    return null;
  }
}

export async function renameProject(id: string, name: string): Promise<ProjectSummary | null> {
  try {
    const res = await authFetch(`${API_URL}/projects/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) return null;
    return (await res.json()).project ?? null;
  } catch {
    return null;
  }
}

/** Delete a project. The backend refuses to delete the protected `default`
 *  project (400) — that reason is returned in `error` so the UI can show it. */
export async function deleteProject(id: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await authFetch(`${API_URL}/projects/${id}`, { method: "DELETE" });
    if (res.ok) return { ok: true };
    let error = `Could not delete project (${res.status}).`;
    try {
      error = (await res.json()).detail ?? error;
    } catch {
      /* non-JSON body */
    }
    return { ok: false, error };
  } catch {
    return { ok: false, error: "Backend unreachable." };
  }
}

// ---------------------------------------------------------------------------
// Findings — a user's own saved chat messages ("profile evidence")
// ---------------------------------------------------------------------------

export interface CreateFindingInput {
  content: string;
  title?: string;
  conversation_id?: string | null;
  conv_mode?: string | null;
  message_id?: string | null;
  citations?: Citation[];
  in_report?: boolean;
  /** Pentest fields — only set when logging a finding by hand. */
  severity?: Severity;
  affected_asset?: string;
  endpoint?: string;
  method?: string;
  notes?: string;
  recommended_fix?: string;
  unresolved_questions?: string;
}

export type FindingPatch = {
  title?: string;
  content?: string;
  in_report?: boolean;
  severity?: Severity;
  affected_asset?: string;
  endpoint?: string;
  method?: string;
  notes?: string;
  recommended_fix?: string;
  unresolved_questions?: string;
};

export async function listFindings(projectId?: string): Promise<UserFinding[]> {
  try {
    const qs = projectId ? `?project_id=${encodeURIComponent(projectId)}` : "";
    const res = await authFetch(`${API_URL}/findings${qs}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return [];
    return (await res.json()).findings ?? [];
  } catch {
    return [];
  }
}

/** Export only the signed-in user's report findings for the active project. */
export async function exportFindingsReport(): Promise<Blob> {
  const res = await authFetch(`${API_URL}/findings/report/export`, {
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`Could not export report (HTTP ${res.status}).`);
  return res.blob();
}

export async function createUserFinding(input: CreateFindingInput): Promise<UserFinding | null> {
  try {
    const res = await authFetch(`${API_URL}/findings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
    });
    if (!res.ok) return null;
    return (await res.json()).finding ?? null;
  } catch {
    return null;
  }
}

/** Rate one assistant answer. `rating: null` clears an existing vote.
 *  A `correction` is optional but is the half that actually improves anything —
 *  it replaces the wrong answer as a training target and lands in memory. */
export async function setMessageFeedback(
  conversationId: string,
  messageId: string,
  rating: "up" | "down" | null,
  correction = ""
): Promise<boolean> {
  try {
    const res = await authFetch(
      `${API_URL}/conversations/${conversationId}/messages/${messageId}/feedback`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rating, correction }),
      }
    );
    return res.ok;
  } catch {
    return false;
  }
}

/** What this caller already rated in a conversation, so reopening a chat shows
 *  the thumbs they previously set rather than a blank slate. */
export async function getMessageFeedback(
  conversationId: string
): Promise<Record<string, { rating: "up" | "down"; correction: string }>> {
  const body = await request<{ feedback?: Record<string, { rating: "up" | "down"; correction: string }> }>(
    `${API_URL}/conversations/${conversationId}/feedback`
  );
  return body.feedback ?? {};
}

export async function updateFinding(
  id: string,
  patch: FindingPatch
): Promise<UserFinding | null> {
  try {
    const res = await authFetch(`${API_URL}/findings/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    if (!res.ok) return null;
    return (await res.json()).finding ?? null;
  } catch {
    return null;
  }
}

export async function deleteFinding(id: string): Promise<boolean> {
  try {
    const res = await authFetch(`${API_URL}/findings/${id}`, { method: "DELETE" });
    return res.ok;
  } catch {
    return false;
  }
}

/** Publish a finding and get its share token back. The public URL is built on
 *  the client (basePath-aware) — the backend stays host-agnostic. */
export async function shareFinding(id: string): Promise<string | null> {
  try {
    const res = await authFetch(`${API_URL}/findings/${id}/share`, { method: "POST" });
    if (!res.ok) return null;
    return (await res.json()).token ?? null;
  } catch {
    return null;
  }
}

export async function revokeFinding(id: string): Promise<boolean> {
  try {
    const res = await authFetch(`${API_URL}/findings/${id}/share`, { method: "DELETE" });
    return res.ok;
  } catch {
    return false;
  }
}

/** A finding someone published, as shown on the community feed. Carries the
 *  author's handle — never an email — and no owner/project/conversation ids. */
export interface PublicFinding {
  id: string;
  title: string;
  content: string;
  citations: Citation[];
  severity: Severity;
  endpoint: string;
  method: string;
  notes: string;
  recommended_fix: string;
  author: string;
  /** True when the viewer published it, so they can make it private again. */
  is_mine: boolean;
  shared_at: string | null;
  created_at: string;
}

/** The public findings feed. Signed-in only — individual share links stay open
 *  to anyone, but the browsable index is not. */
export async function listPublicFindings(limit = 100, offset = 0): Promise<PublicFinding[]> {
  try {
    const res = await authFetch(
      `${API_URL}/findings/public?limit=${limit}&offset=${offset}`,
      { signal: AbortSignal.timeout(8000) }
    );
    if (!res.ok) return [];
    return (await res.json()).findings ?? [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Profile — the nickname shown as the author on published findings
// ---------------------------------------------------------------------------

export interface Profile {
  handle: string;
  display_name: string | null;
  member_no: number;
}

export async function getProfile(): Promise<Profile | null> {
  try {
    const res = await authFetch(`${API_URL}/profile`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    return (await res.json()).profile ?? null;
  } catch {
    return null;
  }
}

/** Set the nickname; pass "" to clear it and go back to the generated "User N".
 *  Returns the updated profile, or an error message the UI can show. */
export async function updateProfile(
  displayName: string
): Promise<{ profile?: Profile; error?: string }> {
  try {
    const res = await authFetch(`${API_URL}/profile`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: displayName }),
    });
    if (res.ok) return { profile: (await res.json()).profile };
    let error = `Could not save that name (${res.status}).`;
    try {
      error = (await res.json()).detail ?? error;
    } catch {
      /* non-JSON body */
    }
    return { error };
  } catch {
    return { error: "Backend unreachable." };
  }
}

export interface SharedFinding {
  title: string;
  content: string;
  citations: Citation[];
  severity?: Severity;
  endpoint?: string;
  method?: string;
  recommended_fix?: string;
  author?: string;
  created_at: string;
}

/** Read a publicly-shared finding by token. Plain fetch (no auth) — this is the
 *  one route reachable without signing in. Returns null for unknown/revoked. */
export async function getSharedFinding(token: string): Promise<SharedFinding | null> {
  try {
    const res = await fetch(`${API_URL}/shared/findings/${encodeURIComponent(token)}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return (await res.json()).finding ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Artifacts — project-scoped uploads (files, folders, notes)
// ---------------------------------------------------------------------------

export interface MediaFrame {
  timestamp_seconds: number;
  thumbnail_path: string;
  description: string;
  visible_text: string[];
  security_observations: string[];
}

export interface ArtifactMetadata {
  // image
  width?: number;
  height?: number;
  format?: string;
  mode?: string;
  exif?: Record<string, string>;
  ocr_text?: string;
  description?: string;
  objects?: string[];
  security_observations?: string[];
  possible_secrets?: string[];
  error_messages?: string[];
  model?: string | null;
  // video
  duration_seconds?: number;
  resolution?: string;
  video_codec?: string;
  fps?: number;
  has_audio?: boolean;
  transcript?: string;
  transcript_segments?: { start: number; end: number; text: string }[];
  frames?: MediaFrame[];
  summary?: string;
  warnings?: string[];
  thumbnail?: boolean;
}

/** Granular backend states; the UI treats anything not ready/failed as in-progress. */
export type ArtifactStatus =
  | "processing" | "uploaded" | "validating" | "extracting"
  | "transcribing" | "analyzing" | "indexing" | "ready" | "failed";

export interface Artifact {
  id: string;
  filename: string;
  original_filename?: string;
  kind: string; // file | note | image | video
  status: ArtifactStatus;
  extract_status?: string;
  index_status?: string;
  analysis_status?: string;
  chunk_count: number;
  error?: string | null;
  mime?: string | null;
  size?: number;
  relative_path?: string | null;
  metadata?: ArtifactMetadata;
  created_at: string;
}

export const isMediaProcessing = (a: Artifact): boolean =>
  a.status !== "ready" && a.status !== "failed";

export function artifactFileUrl(projectId: string, id: string): string {
  return `${API_URL}/projects/${projectId}/artifacts/${id}/file`;
}
export function artifactThumbnailUrl(projectId: string, id: string): string {
  return `${API_URL}/projects/${projectId}/artifacts/${id}/thumbnail`;
}
export function artifactFrameUrl(projectId: string, id: string, name: string): string {
  return `${API_URL}/projects/${projectId}/artifacts/${id}/frame/${name}`;
}

export async function listArtifacts(projectId: string): Promise<Artifact[]> {
  const body = await request<{ artifacts?: Artifact[] }>(`${API_URL}/projects/${projectId}/artifacts`);
  return body.artifacts ?? [];
}

export async function getArtifact(projectId: string, id: string): Promise<Artifact | null> {
  try {
    const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/${id}`);
    if (!res.ok) return null;
    return (await res.json()).artifact ?? null;
  } catch {
    return null;
  }
}

export async function uploadImages(projectId: string, files: File[]): Promise<Artifact[]> {
  const form = new FormData();
  files.forEach((f) => form.append("files", f));
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/images`, { method: "POST", body: form });
  if (!res.ok) await handleError(res);
  return (await res.json()).artifacts ?? [];
}

export async function uploadVideos(projectId: string, files: File[]): Promise<Artifact[]> {
  const form = new FormData();
  files.forEach((f) => form.append("files", f));
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/videos`, { method: "POST", body: form });
  if (!res.ok) await handleError(res);
  return (await res.json()).artifacts ?? [];
}

export async function reprocessArtifact(projectId: string, id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/${id}/reprocess`, { method: "POST" });
  return res.ok;
}

export async function askArtifact(
  projectId: string,
  id: string,
  question: string,
  model = "oyster-dolphin-v2",
  topK = 6
): Promise<{ answer: string; citations: Citation[]; model: string }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/${id}/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, model, top_k: topK }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function uploadArtifacts(projectId: string, files: File[]): Promise<Artifact[]> {
  const form = new FormData();
  files.forEach((f) => form.append("files", f));
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/upload`, { method: "POST", body: form });
  if (!res.ok) await handleError(res);
  return (await res.json()).artifacts ?? [];
}

export async function uploadFolder(
  projectId: string,
  files: File[]
): Promise<{ ingested: number; ready: number; failed: number; skipped: { path: string; reason: string }[]; artifacts: Artifact[] }> {
  const form = new FormData();
  files.forEach((f) => {
    form.append("files", f);
    // relative path within the chosen folder
    form.append("paths", (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name);
  });
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/upload-folder`, { method: "POST", body: form });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function createNote(projectId: string, title: string, content: string): Promise<Artifact> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/note`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title, content }),
  });
  if (!res.ok) await handleError(res);
  return (await res.json()).artifact;
}

export async function deleteArtifact(projectId: string, id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/${id}`, { method: "DELETE" });
  return res.ok;
}

export async function summarizeArtifact(
  projectId: string,
  id: string,
  model = "oyster-dolphin-v2"
): Promise<{ summary: string; filename: string }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/${id}/summarize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function askProject(
  projectId: string,
  question: string,
  model = "oyster-dolphin-v2",
  topK = 5,
  history: ChatHistoryTurn[] = []
): Promise<{ answer: string; citations: Citation[]; model: string }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/artifacts/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, model, top_k: topK, history }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Knowledge Packs — curated, global, source-attributed knowledge
// ---------------------------------------------------------------------------

export interface KnowledgePack {
  id: string;
  version: string;
  title: string;
  domain: string;
  security_domain?: string;
  description: string;
  tags: string[];
  authority?: string | null;
  publisher?: string | null;
  trust_level?: string;
  licence?: string | null;
  attribution?: string | null;
  source_urls?: string[];
  risk_classification?: string;
  freshness_policy?: string | null;
  last_reviewed_at?: string | null;
  content_checksum?: string;
  installed_checksum?: string | null;
  doc_count: number;
  valid: boolean;
  installed: boolean;
  enabled?: boolean;
  installed_version?: string | null;
  outdated?: boolean;
  update_status?: string;
  chunk_count?: number;
}

export interface CitationSource {
  chunk_id: string;
  knowledge_pack?: string;
  pack_version?: string;
  document?: string;
  title?: string;
  publisher?: string;
  canonical_url?: string;
  licence?: string;
  trust_level?: string;
  risk_level?: string;
  domain?: string;
  section?: string;
  source_type?: string;
  passage?: string;
}

export async function listKnowledgePacks(): Promise<{ packs: KnowledgePack[]; total: number; installed: number; enabled?: number }> {
  try {
    const res = await authFetch(`${API_URL}/knowledge/packs`);
    if (!res.ok) return { packs: [], total: 0, installed: 0 };
    return res.json();
  } catch {
    return { packs: [], total: 0, installed: 0 };
  }
}

export interface KnowledgePublicMetrics {
  headline: string;
  marketing_sentence: string | null;
  unique_searchable_chunks: number;
  meets_public_threshold: boolean;
  source_count: number;
  retrieval_evaluation_score: number | null;
  last_verified_at: string | null;
}

// Reads the VERIFIED metric from the active knowledge store. The chunk count is
// never hard-coded in the UI — it always reflects what the backend actually holds.
export async function getKnowledgePublicMetrics(): Promise<KnowledgePublicMetrics | null> {
  try {
    const res = await authFetch(`${API_URL}/knowledge/metrics/public`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function setKnowledgePackEnabled(id: string, enabled: boolean): Promise<boolean> {
  const res = await authFetch(`${API_URL}/knowledge/packs/${id}/enabled`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  return res.ok;
}

export async function resolveCitation(chunkId: string): Promise<CitationSource | null> {
  try {
    const res = await authFetch(`${API_URL}/knowledge/citation/${encodeURIComponent(chunkId)}`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function installKnowledgePack(id: string): Promise<{ ok: boolean; docs?: number; chunks?: number; error?: string }> {
  const res = await authFetch(`${API_URL}/knowledge/packs/${id}/install`, { method: "POST" });
  if (!res.ok) {
    let detail = `Install failed (${res.status})`;
    try { detail = (await res.json()).detail ?? detail; } catch { /* */ }
    return { ok: false, error: detail };
  }
  return res.json();
}

export async function uninstallKnowledgePack(id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/knowledge/packs/${id}`, { method: "DELETE" });
  return res.ok;
}

export async function askKnowledge(
  question: string,
  model = "oyster-dolphin-v2",
  topK = 6
): Promise<{ answer: string; citations: Citation[]; model: string; grounded: boolean }> {
  const res = await authFetch(`${API_URL}/knowledge/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, model, top_k: topK }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Red Bears — streamed Knowledge answer with optional Nemotron evidence
// reranking. Frames: meta (citations + rerank status, sent first), token*,
// done | error. See backend routers/knowledge.py::ask_knowledge_stream.
// ---------------------------------------------------------------------------

export interface RerankInfo {
  requested: boolean;
  /** "ran": Nemotron's order was used. "fell_back": existing retrieval order
   *  was used (see `reason`). "disabled": switched off by server config. */
  status: "ran" | "fell_back" | "disabled";
  reason: string | null;
  model: string;
  endpoint: "local" | "nvidia-hosted" | "remote";
  latency_ms: number | null;
  candidates: number;
  returned: number;
  order_changed: boolean;
}

export type RankedCitation = Citation & { rerank_score?: number; retrieval_rank?: number };

export type KnowledgeStreamFrame =
  | { type: "meta"; citations: RankedCitation[]; rerank: RerankInfo | null; model: string;
      ollama_model: string; grounded: boolean; retrieval_ms: number }
  | { type: "token"; text: string }
  | { type: "done"; answer: string; quality_flags: string[]; ttft_ms: number | null; total_ms: number }
  | { type: "error"; detail: string };

export async function askKnowledgeStream(
  question: string,
  model: string,
  rerank: boolean,
  onFrame: (f: KnowledgeStreamFrame) => void,
  signal?: AbortSignal,
  topK = 5,
): Promise<void> {
  const res = await authFetch(`${API_URL}/knowledge/ask/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, model, rerank, top_k: topK }),
    signal,
  });
  if (!res.ok || !res.body) await handleError(res);
  const reader = res.body!.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onFrame(JSON.parse(line) as KnowledgeStreamFrame);
    }
  }
}

// ---------------------------------------------------------------------------
// Security Intelligence — deterministic router over exact CVE/CWE/CAPEC/
// ATT&CK/D3FEND lookups, vulnerability listings, and detection/mitigation/
// incident-response/cloud/general knowledge questions. Every field below is
// rendered defensively in the UI: the backend's non-fabrication guarantee
// means any of it can be missing or null rather than invented.
// ---------------------------------------------------------------------------

/** One fully-resolved identifier (CVE, CWE, CAPEC, ATT&CK technique, or
 *  D3FEND countermeasure) — same 7-field shape across all four kinds, only
 *  the field CONTENTS differ by identifier type (see backend contract). */
export interface SecurityIntelExactItem {
  identifier: string;
  direct_answer: string;
  severity_and_exploitation: string;
  affected_systems: string;
  defensive_actions: string;
  detection_guidance: string;
  sources: { source_url?: string; title?: string; publisher?: string }[];
  retrieved_at?: string;
  last_modified?: string | null;
  /** GHSA/OSV only: the advisory was withdrawn by its publisher. */
  is_withdrawn?: boolean;
}

/** One row of a `vulnerability_filter` listing. */
export interface SecurityIntelListingRow {
  cve_id: string;
  description?: string;
  cvss_v3_score?: number | null;
  cvss_v3_severity?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  kev_listed?: number;
  kev_due_date?: string | null;
  last_modified_date?: string | null;
}

/** A source backing a detection/mitigation/incident_response/cloud/general
 *  answer. Has a `chunk_id` (unlike exact-lookup sources), so it can be
 *  expanded via resolveCitation() to show the full retrieved passage. */
export interface SecurityIntelSource {
  chunk_id?: string;
  title?: string;
  source_url?: string;
  publisher?: string;
  trust_level?: string;
  retrieved_at?: string;
}

export interface SecurityIntelConfidence {
  level: "grounded" | "partial" | "none";
  data_gap_warning: string | null;
}

export type SecurityIntelRoute =
  | "exact_lookup"
  | "vulnerability_filter"
  | "package_vulnerabilities"
  | "version_check"
  | "prioritization"
  | "detection"
  | "mitigation"
  | "incident_response"
  | "cloud"
  | "compliance"
  | "general";

/** One installed-advisory range verdict for a version_check answer — never a
 *  guess: "indeterminate" means the range or version string couldn't be
 *  confidently compared, not that it was assumed safe. */
export interface VersionCheckMatch {
  advisory_id: string;
  kind: "ghsa" | "osv";
  verdict: "affected" | "not_affected" | "indeterminate";
  introduced?: string | null;
  fixed?: string | null;
  last_affected?: string | null;
  withdrawn: boolean;
}

/** One CVE's transparent, factor-by-factor prioritization score — never a
 *  claimed universal risk score. */
export interface PrioritizationEntry {
  cve_id: string;
  found: boolean;
  score?: number;
  band?: "critical" | "high" | "medium" | "low";
  confidence?: number;
  factors?: Record<string, { weight: number; value: number | null }>;
  missing_factors?: string[];
  explanation?: string[];
  note?: string;
}

export interface SecurityIntelAnswer {
  route: SecurityIntelRoute;
  question: string;
  items?: SecurityIntelExactItem[];
  listing?: SecurityIntelListingRow[];
  direct_answer?: string;
  /** False means direct_answer is a template fallback sentence, not real
   *  synthesized prose — treat the sources list as the actual answer. This is
   *  the COMMON case (no LLM reachable in most environments), not an edge case. */
  llm_available?: boolean;
  detection_guidance?: string[] | null;
  defensive_actions?: string[] | null;
  sources?: SecurityIntelSource[];
  confidence: SecurityIntelConfidence;
  matched_keywords?: string[];
  platforms?: string[];
  // package_vulnerabilities
  ecosystem?: string;
  package?: string;
  // version_check (also reuses ecosystem/package above)
  version?: string;
  status?: "not_found" | "vulnerable" | "not_affected_by_installed_advisories" | "indeterminate";
  fixed_versions?: string[];
  matches?: VersionCheckMatch[];
  // prioritization
  ranked?: PrioritizationEntry[];
  not_found?: string[];
  note?: string;
}

export interface SecurityIntelClassification {
  route: string;
  identifiers: {
    cve: string[]; cwe: string[]; capec: string[]; attack: string[]; d3fend: string[];
    nist_control: string[]; ghsa: string[]; osv: string[];
  };
  matched_keywords: string[];
  platforms: string[];
}

export async function askSecurityIntelligence(
  question: string,
  model: string | null = null,
  topK = 8
): Promise<SecurityIntelAnswer> {
  const res = await authFetch(`${API_URL}/knowledge/intelligence/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, model, top_k: topK }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

/** Instant classify-as-you-type hint — deliberately swallows errors/timeouts
 *  (null) since this only backs a soft inline hint, never the real answer. */
export async function classifySecurityQuestion(question: string): Promise<SecurityIntelClassification | null> {
  try {
    const res = await authFetch(
      `${API_URL}/knowledge/intelligence/classify?question=${encodeURIComponent(question)}`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Conversations — durable sidebar history (project-scoped)
// ---------------------------------------------------------------------------

export interface ApiMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  citations?: Citation[];
  documents_queried?: number | null;
  ord: number;
  created_at?: string;
}

export interface ApiConversation {
  id: string;
  mode: string;
  title: string;
  pinned?: boolean;
  created_at: string;
  updated_at: string;
  message_count: number;
  messages?: ApiMessage[];
}

// Both THROW on failure (see getActiveProject). "[] on any non-OK" is exactly
// how a 429 storm or an expired session rendered as an empty sidebar.
export async function listConversations(mode: string): Promise<ApiConversation[]> {
  const body = await request<{ conversations?: ApiConversation[] }>(
    `${API_URL}/conversations?mode=${encodeURIComponent(mode)}`
  );
  return body.conversations ?? [];
}

export async function getConversation(id: string): Promise<ApiConversation | null> {
  const body = await request<{ conversation?: ApiConversation | null }>(`${API_URL}/conversations/${id}`);
  return body.conversation ?? null;
}

export async function createConversation(mode: string, title = "New Chat"): Promise<ApiConversation> {
  const res = await authFetch(`${API_URL}/conversations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, title }),
  });
  if (!res.ok) await handleError(res);
  return (await res.json()).conversation;
}

export async function renameConversation(id: string, title: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/conversations/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title }),
  });
  return res.ok;
}

export async function setConversationPinned(id: string, pinned: boolean): Promise<boolean> {
  const res = await authFetch(`${API_URL}/conversations/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pinned }),
  });
  return res.ok;
}

export async function deleteConversation(id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/conversations/${id}`, { method: "DELETE" });
  return res.ok;
}

/** Delete a message and everything after it — the server side of editing a
 *  previous user message (the client then resends the edited text). Returns
 *  false on any failure; the caller keeps the optimistic local state either way,
 *  and a reload would reconcile. */
export async function truncateConversationFrom(
  conversationId: string,
  messageId: string
): Promise<boolean> {
  try {
    const res = await authFetch(
      `${API_URL}/conversations/${conversationId}/messages/${messageId}/truncate`,
      { method: "POST" }
    );
    return res.ok;
  } catch {
    return false;
  }
}

/** The server's minimal ack for a persisted message — see add_message() in
 *  services/conversation_service.py, which deliberately does NOT echo back
 *  content/citations (the caller already has those; this response is purely
 *  "here is the real id"). Do not add fields here without adding them there. */
export interface AddedMessageAck {
  id: string;
  ord: number;
  created_at: string;
}

/**
 * Persist one message. Returns the server's ack — most importantly the
 * real id — on success, or `null` on failure — never throws, since this is
 * called fire-and-forget from the middle of a chat send and a persistence
 * hiccup must not blow up the stream that is still running.
 *
 * The id matters: a message is first rendered with a client-generated id (so
 * the bubble can appear before the network round trip), and until the caller
 * swaps it for the real one (conversationStore's `replaceMessageId`), rating
 * or editing that message 404s. Returning the id here is what closes that gap.
 */
export async function addConversationMessage(
  id: string,
  role: "user" | "assistant",
  content: string,
  citations: Citation[] = [],
  documentsQueried: number | null = null
): Promise<AddedMessageAck | null> {
  try {
    const res = await authFetch(`${API_URL}/conversations/${id}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role, content, citations, documents_queried: documentsQueried }),
    });
    if (!res.ok) return null;
    const body = await res.json();
    return (body.message as AddedMessageAck) ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Phase 4 — Red Team: scope
// ---------------------------------------------------------------------------

export async function setScope(scope: ScopeConfig): Promise<{ status: string; scope: ScopeConfig; message: string }> {
  const res = await authFetch(`${API_URL}/scope/set`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(scope),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function getScope(): Promise<{ scope: ScopeConfig; active: boolean }> {
  const res = await authFetch(`${API_URL}/scope`);
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Phase 4 — Red Team: recon
// ---------------------------------------------------------------------------

export async function runRecon(
  target: string,
  description: string,
  model = "deepseek-r1"
): Promise<{ target: string; recon: string; model: string }> {
  const res = await authFetch(`${API_URL}/redteam/recon`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, description, model }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Phase 4 — Red Team: test planner (wraps existing /redteam/plan)
// ---------------------------------------------------------------------------

export async function generateTestPlan(
  target: string,
  objective: string,
  model = "deepseek-r1"
): Promise<{ target: string; in_scope: boolean; plan: string; model: string }> {
  const res = await authFetch(`${API_URL}/redteam/plan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, objective, model }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

// The old Red-Team evidence-logger client (logEvidence / listEvidence /
// deleteEvidence → /redteam/evidence) is gone: it wrote to a single global
// admin JSON file, which is the same concept as a finding but stored twice and
// visible to the wrong people. Everything it did now lives in the Findings API
// above (severity / endpoint / method / notes / recommended_fix), per-user and
// project-scoped. The backend routes still exist for any external caller.

// ---------------------------------------------------------------------------
// Phase 4 — Red Team: fix advisor
// ---------------------------------------------------------------------------

export async function getFixAdvice(
  title: string,
  endpoint: string,
  description: string,
  steps = "",
  stack = "",
  model = "deepseek-r1"
): Promise<{ title: string; endpoint: string; advice: string; model: string }> {
  const res = await authFetch(`${API_URL}/redteam/fix`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title, endpoint, description, steps, stack, model }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Execution Engine (authorization-aware tool execution)
// ---------------------------------------------------------------------------

export interface ToolAvailability {
  available: boolean;
  version?: string | null;
  reason?: string;
  install_hint?: string;
  path?: string;
}

export interface ToolActionDef {
  id: string;
  name: string;
  description: string;
  execution_class: number;
  execution_class_name: string;
  risk_level: string;
  target_types: string[];
  network_required: boolean;
  param_schema: Record<string, { type: string; enum?: string[]; min?: number; max?: number; default?: unknown; required?: boolean; description?: string }>;
  approval: string;
}

export interface ExecutionTool {
  id: string;
  name: string;
  description: string;
  official_docs: string;
  binary: string | null;
  supported_os: string[];
  install_hint: string;
  prohibited_flags: string[];
  availability: ToolAvailability;
  actions: ToolActionDef[];
  enabled: boolean;
}

export interface PolicyDecision {
  id: string;
  decision: "allow" | "requires_approval" | "blocked";
  reasons: string[];
  matched_scope_entries: string[];
  unmatched_targets: string[];
  prohibited_conditions: string[];
  approval_required: boolean;
  allowed_parameters: Record<string, unknown>;
  parameter_constraints: Record<string, unknown>;
  maximum_runtime: number;
  maximum_output_size: number;
}

export interface ExecutionProposal {
  id: string;
  project_id: string;
  objective: string;
  tool_id: string;
  action_id: string;
  targets: string[];
  parameters: Record<string, unknown>;
  generated_command: string;
  sanitized_command: string;
  risk_level: string;
  execution_class: number;
  scope_decision: string;
  approval_requirement: string;
  timeout_seconds: number;
  network_required: boolean;
  cleanup_required: boolean;
  status: string;
  created_at: string;
  expires_at: string;
}

export interface ToolExecution {
  id: string;
  proposal_id: string;
  project_id: string;
  tool_id: string;
  action_id: string;
  target: string;
  sanitized_command: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  exit_code?: number;
  tool_version?: string;
  output_hash?: string;
  timeout_state: string;
  cancellation_state: string;
  cleanup_state: string;
  error_summary?: string;
}

export interface ExecutionOutput {
  id: string;
  execution_id: string;
  stdout: string;
  stderr: string;
  stdout_hash: string;
  truncated: boolean;
  parsed: { observations?: Observation[]; raw_parsed?: Record<string, unknown> };
}

export interface Observation { type: string; title: string; detail: string; severity: string }

export interface EvidenceRecord {
  id: string;
  project_id: string;
  execution_id?: string;
  tool_id: string;
  target: string;
  title: string;
  observation: string;
  content_hash: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  ts: string;
  actor: string;
  event: string;
  proposal_id?: string;
  execution_id?: string;
  detail: Record<string, unknown>;
}

export async function listExecutionTools(): Promise<{ tools: ExecutionTool[]; project_id: string }> {
  const res = await authFetch(`${API_URL}/execution/tools`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function setExecutionToolEnabled(toolId: string, enabled: boolean) {
  const res = await authFetch(`${API_URL}/execution/tools/${toolId}/enabled`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function createProposal(body: {
  tool_id: string; action_id: string; targets: string[];
  parameters?: Record<string, unknown>; objective?: string;
}): Promise<{ ok: boolean; proposal: ExecutionProposal; policy: PolicyDecision }> {
  const res = await authFetch(`${API_URL}/execution/proposals`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function approveProposal(id: string, note = "") {
  const res = await authFetch(`${API_URL}/execution/proposals/${id}/approve`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ note }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function rejectProposal(id: string, note = "") {
  const res = await authFetch(`${API_URL}/execution/proposals/${id}/reject`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ note }),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function executeProposal(id: string): Promise<{
  ok: boolean; execution: ToolExecution; output: ExecutionOutput;
  observations: Observation[]; evidence_ids: string[];
}> {
  const res = await authFetch(`${API_URL}/execution/proposals/${id}/execute`, { method: "POST" });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function getExecution(id: string): Promise<{
  execution: ToolExecution; output: ExecutionOutput | null; evidence: EvidenceRecord[]; cleanup: unknown;
}> {
  const res = await authFetch(`${API_URL}/execution/executions/${id}`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function cancelExecution(id: string) {
  const res = await authFetch(`${API_URL}/execution/executions/${id}/cancel`, { method: "POST" });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listProposals(): Promise<{ proposals: ExecutionProposal[] }> {
  const res = await authFetch(`${API_URL}/execution/proposals`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listExecutions(): Promise<{ executions: ToolExecution[] }> {
  const res = await authFetch(`${API_URL}/execution/executions`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listExecutionEvidence(): Promise<{ evidence: EvidenceRecord[] }> {
  const res = await authFetch(`${API_URL}/execution/evidence`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function createFinding(body: {
  title: string; severity: string; summary: string; evidence_ids: string[]; recommendation?: string;
}) {
  const res = await authFetch(`${API_URL}/execution/findings`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listExecutionAudit(): Promise<{ audit: AuditEvent[] }> {
  const res = await authFetch(`${API_URL}/execution/audit`);
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// Long-term Memory + operator Settings
// ---------------------------------------------------------------------------

export interface MemoryItem {
  id: string;
  project_id: string;
  type: "fact" | "preference" | "decision" | "instruction" | "project_detail";
  subject: string;
  content: string;
  status: "active" | "pending" | "rejected" | "superseded" | "conflicting" | "deleted";
  confidence: number;
  source: string;
  origin_conversation_id: string | null;
  supersedes_id: string | null;
  conflict_group: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConflictGroup {
  conflict_group: string;
  members: MemoryItem[];
}

export interface OysterSettings {
  project_id: string;
  memory_enabled: boolean;
  auto_save: boolean;
  ask_before_saving: boolean;
  allow_training_data: boolean;
}

export async function getSettings(projectId: string): Promise<OysterSettings> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/settings`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function updateSettings(
  projectId: string,
  patch: Partial<Omit<OysterSettings, "project_id">>
): Promise<OysterSettings> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/settings`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function deleteAllPersonalData(projectId: string): Promise<{ ok: boolean; memories_deleted: number }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/settings/personal-data`, { method: "DELETE" });
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listMemories(
  projectId: string,
  status: string = "active"
): Promise<{ memories: MemoryItem[]; total: number }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory?status=${encodeURIComponent(status)}`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listPendingMemories(projectId: string): Promise<{ pending: MemoryItem[]; total: number }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/pending`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function listMemoryConflicts(projectId: string): Promise<{ conflicts: ConflictGroup[]; total: number }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/conflicts`);
  if (!res.ok) await handleError(res);
  return res.json();
}

export async function resolveMemoryConflict(
  projectId: string,
  conflictGroup: string,
  keepId: string
): Promise<boolean> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/conflicts/${conflictGroup}/resolve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ keep_id: keepId }),
  });
  return res.ok;
}

export async function addMemory(
  projectId: string,
  memory: { type: string; subject: string; content: string; confidence?: number }
): Promise<{ ok: boolean; error?: string }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(memory),
  });
  if (!res.ok) {
    try {
      const body = await res.json();
      return { ok: false, error: body.detail ?? "Failed to save memory" };
    } catch {
      return { ok: false, error: "Failed to save memory" };
    }
  }
  return res.json();
}

export async function updateMemory(
  projectId: string,
  id: string,
  patch: { content?: string; subject?: string; type?: string }
): Promise<{ ok: boolean; error?: string }> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
  if (!res.ok) {
    try {
      const body = await res.json();
      return { ok: false, error: body.detail ?? "Failed to update memory" };
    } catch {
      return { ok: false, error: "Failed to update memory" };
    }
  }
  return res.json();
}

export async function approveMemory(projectId: string, id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/${id}/approve`, { method: "POST" });
  return res.ok;
}

export async function rejectMemory(projectId: string, id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/${id}/reject`, { method: "POST" });
  return res.ok;
}

export async function deleteMemory(projectId: string, id: string): Promise<boolean> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/${id}`, { method: "DELETE" });
  return res.ok;
}

export async function exportMemory(projectId: string): Promise<Record<string, unknown>> {
  const res = await authFetch(`${API_URL}/projects/${projectId}/memory/export`);
  if (!res.ok) await handleError(res);
  return res.json();
}

// ---------------------------------------------------------------------------
// SOC Copilot (Blue Team) — the socmat workbench mounted at /socmat/api.
// The full case/evidence/detection client is added in the frontend rebuild;
// this health probe backs the workbench shell's online/offline indicator.
// ---------------------------------------------------------------------------

export interface SocmatHealth {
  status?: string;
  version?: string;
  [k: string]: unknown;
}

export async function socmatHealth(): Promise<SocmatHealth> {
  const res = await authFetch(`${SOCMAT_API}/health`);
  if (!res.ok) await handleError(res);
  return res.json();
}

/** Authenticated fetch against the mounted SOC Copilot API. `path` begins with
 *  "/" and is relative to /socmat/api. Used by lib/socmat.ts. */
export async function socmatFetch(path: string, init?: RequestInit): Promise<Response> {
  return authFetch(`${SOCMAT_API}${path}`, init);
}

/** Shared error unwrap for socmat responses (text or {detail}). */
export async function socmatError(res: Response): Promise<never> {
  let detail = `SOC Copilot error ${res.status}`;
  try {
    const body = await res.clone().json();
    detail = body.detail ?? detail;
  } catch {
    try { detail = (await res.text()) || detail; } catch { /* keep default */ }
  }
  throw new Error(detail);
}
