export type Role = "user" | "assistant";

export type AgentMode = "chat" | "engineer" | "redteam" | "codereview" | "raganalyst" | "osint" | "blueteam";

export interface OysterModel {
  key: string;
  label: string;
  description: string;
}
// "evidence" is gone on purpose: the red-team Evidence logger and Findings were
// the same concept stored twice (a global admin JSON file vs. the per-user,
// project-scoped user_findings table). Findings absorbed it — manual logging
// with severity/endpoint/method/fix included — and lives in the main nav.
export type Mode = "basic" | "rag" | "search" | "summarize" | "scope" | "recon" | "testplan" | "fix" | "codelab" | "execute" | "findings" | "soccopilot" | "cookbook" | "notes" | "shield" | "intel" | "redbears";

export interface Citation {
  document: string;
  chunk: string;
  score: number;
  // media provenance (present only for image/video citations)
  artifact_id?: string;
  artifact_type?: "image" | "video";
  content_type?: string;
  timestamp_start?: number;
  timestamp_end?: number;
  frame_index?: number;
  // knowledge-pack provenance (present only for Knowledge Pack citations)
  knowledge_pack?: string;
  pack_version?: string;
  source_title?: string;
  source_url?: string;
  domain?: string;
  // hybrid-retrieval provenance
  chunk_id?: string;
  source_type?: "built_in" | "project" | "uploaded" | "live" | "tool" | "model";
  publisher?: string;
  licence?: string;
  section?: string;
  risk_level?: string;
  trust_level?: string;
  n?: number;
}

export interface OysterDocument {
  id: string;
  filename: string;
  chunk_count: number;
  uploaded_at: string;
}

export interface Message {
  id: string;
  role: Role;
  content: string;
  timestamp: Date;
  citations?: Citation[];
  documentsQueried?: number;
  isLoading?: boolean;
  /** Place in line while waiting for a generation slot. Absent = not queued. */
  queue?: { position: number; ahead: number; etaSeconds: number };
  bookmarked?: boolean;
  pinned?: boolean;
  /**
   * Whether this answer was any good. Oyster previously had no such signal at
   * all, which meant training treated every past reply — including wrong ones —
   * as an example to imitate. Unlike `pinned`/`bookmarked` (client-only), this
   * is persisted server-side, because its whole purpose is to be read back
   * later when a dataset is built.
   */
  rating?: "up" | "down";
  /** What the answer should have said. Worth far more than the rating alone:
   *  it replaces the wrong answer as the training target and is recalled on the
   *  next message. */
  correction?: string;
  /**
   * The lifecycle of an assistant message that is not simply "done" yet.
   * Absent (undefined) means a normal, finished message — the vast majority.
   *   - "streaming"    tokens are actively arriving (drives the cursor blink
   *                     via ChatWindow's isStreaming, not this field, but kept
   *                     here too so a message can be inspected on its own)
   *   - "interrupted"  the connection went stale/truncated mid-answer; Oyster
   *                     is auto-resuming (or will on the next Resume click).
   *                     Partial content is kept, never discarded.
   *   - "stopped"      the user pressed Stop. Partial content is kept and the
   *                     message is final — no auto-resume.
   *   - "error"        the generation failed outright (not a connectivity
   *                     hiccup); `content` carries the explanation already.
   */
  state?: "streaming" | "interrupted" | "stopped" | "error";
}

export interface Conversation {
  id: string;
  title: string;
  messages: Message[];
  createdAt: Date;
  mode: Mode;
  pinned?: boolean;
  /** Messages are being fetched from the server (a selected, not-yet-hydrated
   *  conversation). Distinguishes "loading an existing chat" from "an empty new
   *  draft" — the welcome/suggestions screen must only show for the latter, and
   *  the composer is disabled while this is true so a send can't be lost to the
   *  in-flight hydrate. */
  loading?: boolean;
  /** Hydration failed (archived / missing / corrupted). Shown as an honest,
   *  retryable error instead of a silently-empty conversation. */
  error?: string | null;
}

/** Attachment shown as a chip above the composer. */
export interface Attachment {
  id: string;
  name: string;
  kind: "pdf" | "txt" | "docx" | "markdown" | "image" | "video" | "note" | "kb" | "artifact" | "finding" | "report";
}

export interface ScopeConfig {
  project: string;
  allowed_targets: string[];
  blocked_targets: string[];
  allowed_tests: string[];
  authorized_by?: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** A finding: either captured from a chat message, or logged by hand with the
 *  pentest fields the old red-team Evidence panel used. One surface, one table. */
export interface UserFinding {
  id: string;
  project_id: string;
  conversation_id?: string | null;
  conv_mode?: string | null;
  message_id?: string | null;
  title: string;
  content: string;
  citations: Citation[];
  shared: boolean;
  /** Present only in the OWNER's payload (ownership-gated); lets the UI rebuild
   *  the public share URL. Never present in the public projection. */
  share_token?: string | null;
  shared_at?: string | null;
  /** Flagged for the report — a report is a curated subset of findings. */
  in_report: boolean;
  /** Pentest fields — empty for a chat-captured finding, filled when logged by hand. */
  severity: Severity;
  /** General target identifier (host/IP/service) — distinct from endpoint/method,
   *  which are HTTP-specific and don't fit a network host, device, or app. */
  affected_asset: string;
  endpoint: string;
  method: string;
  notes: string;
  recommended_fix: string;
  /** What the assessment did NOT establish — renders in the export so the
   *  report says so explicitly instead of implying completeness. */
  unresolved_questions: string;
  created_at: string;
  updated_at: string;
}
