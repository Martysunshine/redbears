"use client";

import { useState, useCallback, useEffect, useMemo, useReducer, useRef } from "react";
import { Sidebar } from "@/components/Sidebar";
import { ChatWindow } from "@/components/ChatWindow";
import { ScopePanel } from "@/components/ScopePanel";
import { ReconPanel } from "@/components/ReconPanel";
import { TestPlannerPanel } from "@/components/TestPlannerPanel";
import { FixAdvisorPanel } from "@/components/FixAdvisorPanel";
import { ExecutionPanel } from "@/components/ExecutionPanel";
import { FindingsPanel } from "@/components/FindingsPanel";
import { SocCopilotPanel } from "@/components/SocCopilotPanel";
import { ShieldPanel } from "@/components/ShieldPanel";
import { CookBookPanel } from "@/components/soccopilot/CookBookPanel";
import { NotesPanel } from "@/components/soccopilot/NotesPanel";
import { CodeLabPanel } from "@/components/CodeLabPanel";
import { SecurityIntelligencePanel } from "@/components/SecurityIntelligencePanel";
import { RedBearsPanel } from "@/components/RedBearsPanel";
import { AccountSettingsModal } from "@/components/AccountSettingsModal";
import { type Conversation, type Mode, type Message, type UserFinding } from "@/types/chat";
import { type MessageAction } from "@/components/MessageToolbar";
import {
  getHealth,
  getActiveProject,
  listConversations,
  getConversation,
  createConversation,
  renameConversation,
  setConversationPinned,
  deleteConversation,
  addConversationMessage,
  truncateConversationFrom,
  listProjects,
  activateProject,
  createProject,
  renameProject,
  deleteProject,
  type ProjectSummary,
  type PublicFinding,
  createUserFinding,
  setMessageFeedback,
  getMessageFeedback,
  listArtifacts,
  uploadArtifacts,
  uploadFolder,
  uploadImages,
  uploadVideos,
  createNote as createNoteApi,
  deleteArtifact,
  summarizeArtifact,
  askProject,
  isMediaProcessing,
  DEFAULT_MODEL,
  type ApiConversation,
  type ApiMessage,
  type Artifact,
} from "@/lib/api";
import {
  startChat,
  resumeJob,
  cancelChatJob,
  type StreamHandle,
  type StreamCallbacks,
  type StartChatParams,
  type StreamOutcome,
  type ChatHistoryTurn,
} from "@/lib/chatStream";
import { explainChatError } from "@/lib/apiErrors";
import {
  conversationStoreReducer,
  emptyStore,
  listFor,
  getConv,
  type StoreConversation,
} from "@/lib/conversationStore";
import { ArtifactPreview } from "@/components/ArtifactPreview";
import { KnowledgePacksModal } from "@/components/KnowledgePacksModal";
import { AuthGate, useAuth } from "@/components/AuthGate";
import { BootScreen } from "@/components/BootScreen";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { UpsellModal } from "@/components/UpsellModal";
import { HandbookPanel } from "@/components/HandbookPanel";
import { modeToHandbookContext } from "@/data/handbook";
import { clearLocalHistory, loadLocalHistory, saveLocalHistory } from "@/lib/localHistory";

function generateId() {
  return Math.random().toString(36).slice(2, 11);
}

// Which conversation the URL points at (deep link / refresh / back-forward).
// `?c=<id>` is the whole contract: the mode is resolved from the conversation
// itself, so a single param round-trips both. basePath-agnostic (reads the live
// query), and null in SSR or when absent.
function convIdFromUrl(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return new URLSearchParams(window.location.search).get("c");
  } catch {
    return null;
  }
}

// Reflect the visible conversation in the URL so a refresh reopens it and a
// shared link lands on it. Only PERSISTED conversations are linkable — an
// unsaved draft clears the param (it has no server row to reopen). replaceState,
// not push: selecting chats must not spam the history stack.
function syncConvUrl(activeId: string) {
  if (typeof window === "undefined") return;
  try {
    const url = new URL(window.location.href);
    if (activeId && !activeId.startsWith("local-")) url.searchParams.set("c", activeId);
    else url.searchParams.delete("c");
    window.history.replaceState(window.history.state, "", url.toString());
  } catch {
    /* history API unavailable — the app still works, just no deep-link */
  }
}

// A generation that is still running server-side. Survives a refresh so the
// answer can be re-attached rather than lost — the work is owned by the job on
// the backend, not by this browser tab.
const ACTIVE_JOB_KEY = "oyster-active-job";

/**
 * Clear the stored job — but ONLY if it is the one that just finished.
 *
 * localStorage is shared by every tab on the origin. An unconditional remove
 * meant the first tab to finish deleted whatever job a *different* tab was
 * still waiting on, so that tab could no longer resume after a refresh.
 * Observed directly in testing: a tab sat queued while the key read null.
 */
function clearActiveJob(jobId?: string | null) {
  try {
    if (jobId) {
      const raw = localStorage.getItem(ACTIVE_JOB_KEY);
      if (raw && JSON.parse(raw)?.jobId !== jobId) return; // someone else's job
    }
    localStorage.removeItem(ACTIVE_JOB_KEY);
  } catch {
    /* private mode, or unparseable — nothing worth resuming anyway */
  }
}

// Anonymous allowance bookkeeping (client-side UX only — the backend's per-IP
// quota is the real enforcement; this just avoids a doomed request and shows
// the lock instantly).
function anonUsedKey() {
  return `oyster-anon-used:${new Date().toISOString().slice(0, 10)}`;
}
function anonUsedToday(): number {
  try {
    return Number(localStorage.getItem(anonUsedKey()) ?? "0");
  } catch {
    return 0;
  }
}
function markAnonUsed() {
  try {
    localStorage.setItem(anonUsedKey(), String(anonUsedToday() + 1));
  } catch {
    /* private mode — backend still enforces */
  }
}

// A brand-new chat is a client-side DRAFT: it lives only in React state and is
// not persisted anywhere until its first message. For anonymous visitors that
// means localStorage (and only once it has content — see saveLocalHistory); for
// signed-in accounts it is promoted to a real server conversation on the first
// send (see sendBasic/sendRag). The `local-` id prefix is what every guard in
// this file keys on to mean "unsaved" — an empty draft therefore never reaches
// the backend, which is what stops the stray empty "New Chat" rows.
function draftConversation(mode: Mode = "basic"): Conversation {
  return {
    id: `local-${generateId()}`,
    title: "New chat",
    messages: [],
    createdAt: new Date(),
    mode,
    pinned: false,
  };
}

/** Concise history title derived from the first user message. */
function makeTitle(text: string): string {
  const clean = text.trim().replace(/\s+/g, " ");
  if (clean.length <= 48) return clean;
  const cut = clean.slice(0, 48);
  const lastSpace = cut.lastIndexOf(" ");
  return (lastSpace > 24 ? cut.slice(0, lastSpace) : cut).trim() + "…";
}

function toMsg(m: ApiMessage): Message {
  return {
    id: m.id,
    role: m.role,
    content: m.content,
    timestamp: m.created_at ? new Date(m.created_at) : new Date(),
    citations: m.citations,
    documentsQueried: m.documents_queried ?? undefined,
  };
}

function toConv(c: ApiConversation): Conversation {
  return {
    id: c.id,
    title: c.title,
    messages: (c.messages ?? []).map(toMsg),
    createdAt: c.created_at ? new Date(c.created_at) : new Date(),
    mode: c.mode as Mode,
    pinned: c.pinned ?? false,
  };
}

function OysterApp() {
  const { tier, session, refreshAgreement } = useAuth();
  // Two DIFFERENT questions, deliberately separate:
  //   isSignedIn  — has an account. Gets the full workspace: every mode, the
  //                 model picker, scope, red-team planning, memory, settings,
  //                 and server-side history. The backend resolves each account
  //                 into its OWN project (services/project_context.py), so this
  //                 is one workspace per account, not a shared one.
  //   isOperator  — additionally allow-listed. The only extras left are the
  //                 things that are genuinely instance-wide: switching between
  //                 multiple projects, and live tool execution.
  // Anonymous visitors keep the simple public chat and localStorage history.
  const isOperator = tier === "admin";
  const isSignedIn = tier === "admin" || tier === "user";
  const [locked, setLocked] = useState(false);
  const [upsellOpen, setUpsellOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("basic");
  // Start CLOSED on phones: the sidebar is 16rem of a ~390px screen and its
  // mobile overlay sits on top of the composer, so opening by default meant a
  // visitor landed on a dimmed, untypable chat. Desktop keeps it open.
  //
  // `null` until hydration: the server has no window, so CSS decides the first
  // paint (Sidebar renders `w-0 md:w-64` for null) and both markup and the
  // client agree. The old boolean default painted the desktop layout on a
  // phone and then snapped it shut.
  const [sidebarOpen, setSidebarOpen] = useState<boolean | null>(null);
  useEffect(() => {
    setSidebarOpen(window.matchMedia("(min-width: 768px)").matches);
  }, []);
  const [systemPrompt, setSystemPrompt] = useState("");
  const [selectedModel, setSelectedModel] = useState(DEFAULT_MODEL);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [activeProjectName, setActiveProjectName] = useState("Default Engagement");
  const [activeProjectId, setActiveProjectId] = useState("default");
  // Search now lives in the sidebar; its open state is lifted here so the
  // sidebar button toggles the panel that ChatWindow renders.
  const [searchOpen, setSearchOpen] = useState(false);
  // Operator project switcher — the list backing the sidebar Project popover.
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  // Bumped when a finding is created from the message toolbar, so the Findings
  // panel reloads. A tiny transient toast confirms the save without a modal.
  const [findingsRefresh, setFindingsRefresh] = useState(0);
  const [toast, setToast] = useState<string | null>(null);

  // The conversation store — see lib/conversationStore.ts for why this is a
  // reducer and not two plain useState arrays: a list refresh (project
  // switch, or the old per-tab-switch reboot F1 fixed) must be able to
  // update title/pinned WITHOUT wiping a conversation's already-loaded
  // messages back to empty. That silent wipe was "the chat loads empty
  // until I refresh" — a raw array literally cannot express the distinction
  // a reducer state shape can.
  const [store, dispatch] = useReducer(conversationStoreReducer, undefined, emptyStore);
  const [basicActiveId, setBasicActiveId] = useState("");
  const [ragActiveId, setRagActiveId] = useState("");

  const [isStreaming, setIsStreaming] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [previewArtifact, setPreviewArtifact] = useState<Artifact | null>(null);
  const [knowledgeOpen, setKnowledgeOpen] = useState(false);
  const [handbookOpen, setHandbookOpen] = useState(false);

  const isRag = mode === "rag";
  const chatModeKey: "basic" | "rag" = isRag ? "rag" : "basic";
  const conversations = useMemo(() => listFor(store, chatModeKey), [store, chatModeKey]);
  const activeId = isRag ? ragActiveId : basicActiveId;
  const setActiveId = isRag ? setRagActiveId : setBasicActiveId;
  const activeConversation = conversations.find((c) => c.id === activeId);

  const refreshArtifacts = useCallback(async (pid?: string) => {
    try {
      const list = await listArtifacts(pid ?? activeProjectId);
      setArtifacts(list);
    } catch {
      /* a failed refresh keeps the last known list; the next poll retries */
    }
  }, [activeProjectId]);

  // Poll while any media artifact is still processing (survives page refresh:
  // status lives in SQLite, so a reload re-hydrates + resumes polling).
  // Keyed on the BOOLEAN, not the array: every poll produced a new array, which
  // re-armed this effect on every tick, and a hidden tab kept polling.
  const anyProcessing = artifacts.some(isMediaProcessing);
  useEffect(() => {
    if (!anyProcessing) return;
    const tick = () => {
      if (document.hidden) return;
      void refreshArtifacts();
    };
    const t = setInterval(tick, 2500);
    return () => clearInterval(t);
  }, [anyProcessing, refreshArtifacts]);

  // Keep an open preview panel in sync with polled updates.
  useEffect(() => {
    if (!previewArtifact) return;
    const fresh = artifacts.find((a) => a.id === previewArtifact.id);
    if (fresh && fresh !== previewArtifact) setPreviewArtifact(fresh);
  }, [artifacts, previewArtifact]);

  // Health poll — once a minute, never while the tab is hidden, and again the
  // moment it becomes visible or the network comes back. /health is served
  // from the backend's own probe state now, so this is cheap, but a hidden
  // phone tab still has no business polling.
  useEffect(() => {
    const check = () => {
      if (document.hidden) return;
      getHealth().then(() => setBackendOk(true)).catch(() => setBackendOk(false));
    };
    check();
    const interval = setInterval(check, 60_000);
    const onVisible = () => {
      if (!document.hidden) check();
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("online", check);
    return () => {
      clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("online", check);
    };
  }, []);

  const handleReconnect = useCallback(() => {
    setBackendOk(null);
    getHealth().then(() => setBackendOk(true)).catch(() => setBackendOk(false));
  }, []);

  // Reflect tier changes: lock state only ever applies to anonymous visitors,
  // who are also the only tier pinned to basic chat — every signed-in account
  // can enter the red-team and RAG modes now.
  useEffect(() => {
    if (tier !== "anon") {
      setLocked(false);
      setUpsellOpen(false);
    } else {
      setLocked(anonUsedToday() >= 1);
      setMode("basic");
    }
  }, [tier]);

  // Load one project's workspace: its artifacts and its conversations for both
  // modes. Shared by the initial boot and by switching the active project, so
  // both land in an identical state. No eager POST — when a mode has no saved
  // chats we open a client-side draft that only becomes a row on the first
  // message. That keeps this idempotent under React StrictMode's double-mount
  // (re-running just re-sets the same single-draft array — no network, no
  // duplicate shells) and is the source-side half of the empty-chat fix.
  const loadWorkspace = useCallback(async (pid: string, preferId?: string | null) => {
    listArtifacts(pid).then(setArtifacts).catch(() => {});
    // Every row here belongs to a workspace we are (re)entering — the store
    // is reset once, up front, rather than per-mode, so the "basic" and "rag"
    // merges below never see each other's stale rows.
    dispatch({ type: "resetForProject" });
    for (const m of ["basic", "rag"] as const) {
      const rows = (await listConversations(m)).map(toConv);
      dispatch({ type: "mergeList", mode: m, rows });
      if (rows.length) {
        if (m === "basic") setBasicActiveId(rows[0].id);
        else setRagActiveId(rows[0].id);
      } else {
        const draft = draftConversation(m);
        dispatch({ type: "upsertDraft", conv: draft });
        if (m === "basic") setBasicActiveId(draft.id);
        else setRagActiveId(draft.id);
      }
    }
  }, []);

  // Boot: load project, artifacts, and persisted conversations for both modes.
  //
  // Keyed on the ACCOUNT, and run once per account. auth-js re-emits SIGNED_IN
  // on every tab switch; this effect used to re-run the whole sequence (nine
  // requests) each time, replacing loaded chats with empty shells and tripping
  // the rate limiter on phones. AuthGate now filters those re-emissions and
  // bootedForRef makes this side idempotent too. Failures are a state, not a
  // silent empty workspace: the pane shows a Retry instead.
  const [bootState, setBootState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [bootError, setBootError] = useState<string | null>(null);
  const bootedForRef = useRef<string | null>(null);

  const bootWorkspace = useCallback(async () => {
    setBootState("loading");
    setBootError(null);
    try {
      // getActiveProject() returns the operators' active project for an
      // operator and the account's own workspace for everyone else, so one
      // path serves both.
      const res = await getActiveProject();
      const pid = res?.project?.id ?? "default";
      if (res?.project?.name) setActiveProjectName(res.project.name);
      setActiveProjectId(pid);
      // Every signed-in account has its own private projects now — prime the
      // switcher list for all of them, not just operators. The backend scopes
      // the list to the caller, so nobody sees another account's projects.
      try {
        const pl = await listProjects();
        if (pl?.projects) setProjects(pl.projects);
      } catch {
        /* the switcher list is a nicety; the workspace itself still loads */
      }
      await loadWorkspace(pid);
      setBootState("ready");
    } catch (err) {
      setBootState("error");
      setBootError(err instanceof Error ? err.message : "Please try again.");
    }
  }, [loadWorkspace]);

  useEffect(() => {
    if (tier === null) return; // wait for the tier to resolve
    if (!isSignedIn) {
      // Anonymous: history lives in this browser. Restore it so a refresh (or
      // coming back tomorrow) doesn't wipe what they asked Oyster.
      const stored = loadLocalHistory();
      const convs = stored.length ? stored : [draftConversation()];
      dispatch({ type: "loadAnon", convs });
      setBasicActiveId(convs[0].id);
      bootedForRef.current = "anon";
      setBootState("ready");
      return;
    }
    const who = session?.user?.id ?? "signed-in";
    if (bootedForRef.current === who) return;
    bootedForRef.current = who;
    void bootWorkspace();
  }, [tier, isSignedIn, isOperator, session, bootWorkspace]);

  // Anonymous history is persisted on every change (cheap: a handful of
  // conversations, and the write is debounced by React's batching). Strip the
  // two store-only fields (hydration/hydrationError) before writing — they
  // are always "loaded" for an anonymous conv anyway (see loadAnon) and have
  // no meaning once read back from localStorage.
  useEffect(() => {
    if (tier === "anon") {
      saveLocalHistory(listFor(store, "basic").map(({ hydration: _h, hydrationError: _e, ...c }) => c));
    }
  }, [tier, store]);

  // -------------------------------------------------------------------------
  // The chat stream — one at a time, matching CHAT_MAX_PER_USER on the
  // backend. A generation is owned by a JOB on the server
  // (services/chat_queue.py), not by this browser tab: losing the connection
  // — a phone backgrounded, a network blip, even closing the tab — never
  // loses the answer, because the server keeps generating and the job can
  // always be re-attached to via GET /chat/jobs/{id}/stream. What this block
  // gets right is NOTICING the interruption, saying so, and reconnecting —
  // instead of the composer sitting dead (the #1 reported symptom) or a
  // truncated partial being saved as if it were the final answer (the #2).
  //
  // ctx is intentionally a plain mutable object in a ref, not React state:
  // it is written many times per second (once per token) and read from
  // timers and event listeners outside the render cycle. React state would
  // mean a token → a dispatch → a re-render → a new closure, for every single
  // token; the ref carries the bookkeeping, and `dispatch` (stable, from
  // useReducer) is the only thing that actually needs to reach React.
  //
  // saveActiveJob/persistAssistantAnswer/finishStream/scheduleResume/
  // handleStreamOutcome/openStream/forceResumeActive below are deliberately
  // PLAIN function declarations, not useCallback — they mutually reference
  // each other (scheduleResume calls openStream, which schedules
  // handleStreamOutcome, which calls scheduleResume), and memoizing that
  // cycle correctly needs ref-indirection that isn't worth it here: every
  // one of them is cheap to recreate, none is an expensive computation, and
  // recreating a function does not itself cause a re-render. The build will
  // report a few "wrap in useCallback" exhaustive-deps warnings for them —
  // expected, and the WRONG fix: memoizing without breaking the cycle would
  // reintroduce the exact frozen-closure staleness (stale tier/isSignedIn/
  // selectedModel inside a listener registered once at mount) that a plain,
  // always-fresh function avoids by construction. Every effect/callback that
  // uses one of these lists it in its own deps array, so IT stays correctly
  // reactive even though the function underneath is unmemoized.
  // -------------------------------------------------------------------------
  const RESUME_BACKOFF_S = [1, 2, 4, 8, 16, 16, 16, 16] as const;

  interface StreamCtx {
    convId: string;
    asstId: string;
    jobId: string | null;
    epoch: number;   // bumped by Stop; a pending resume checks this before acting
    attempt: number; // resume attempts so far — drives backoff and the give-up cap
    acc: string;     // accumulated answer text, authoritative until persisted
    // Kept so a bare nginx rate-limit (rejected before any job existed — see
    // the "error" outcome branch below) can retry with the SAME prompt.
    // Absent for a boot-time/cross-refresh resume ctx (there is no original
    // send to replay — a resume always has a jobId already); never read once
    // ctx.jobId is set, since from that point a resume is the only correct
    // way to continue.
    startParams?: StartChatParams;
    handle: StreamHandle | null;
  }

  const streamCtxRef = useRef<StreamCtx | null>(null);
  const resumeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearResumeTimer = () => {
    if (resumeTimerRef.current) {
      clearTimeout(resumeTimerRef.current);
      resumeTimerRef.current = null;
    }
  };

  function saveActiveJob(jobId: string, convId: string) {
    try {
      localStorage.setItem(ACTIVE_JOB_KEY, JSON.stringify({ jobId, convId }));
    } catch {
      /* private mode — resume simply won't be available */
    }
  }

  /** Persist the finished answer and swap its optimistic id for the server's
   *  real one, so rating/editing it never 404s. Anonymous chats are never
   *  persisted server-side — their history is this browser's localStorage. */
  function persistAssistantAnswer(convId: string, asstId: string, text: string) {
    if (!isSignedIn || convId.startsWith("local-") || !text) return;
    void addConversationMessage(convId, "assistant", text).then((ack) => {
      if (ack) dispatch({ type: "replaceMessageId", convId, oldId: asstId, newId: ack.id });
    });
  }

  /** End the stream bookkeeping and, unless there's real partial content to
   *  keep (in which case it stays untouched — a status tag communicates the
   *  outcome), fall back to putting `errorText` in the bubble so it is never
   *  left blank. */
  function finishStream(ctx: StreamCtx, state: Message["state"], errorText?: string) {
    clearResumeTimer();
    if (streamCtxRef.current === ctx) {
      streamCtxRef.current = null;
      setIsStreaming(false);
    }
    clearActiveJob(ctx.jobId);
    dispatch({
      type: "patchMessage",
      id: ctx.convId,
      messageId: ctx.asstId,
      patch: {
        isLoading: false,
        queue: undefined,
        state,
        ...(errorText !== undefined && !ctx.acc ? { content: errorText } : {}),
      },
    });
  }

  function scheduleResume(ctx: StreamCtx) {
    if (ctx.attempt >= RESUME_BACKOFF_S.length) {
      finishStream(ctx, "error", "Couldn't reconnect to Oyster. Please try again.");
      return;
    }
    const delay = RESUME_BACKOFF_S[ctx.attempt] * 1000;
    const epoch = ctx.epoch;
    resumeTimerRef.current = setTimeout(() => {
      resumeTimerRef.current = null;
      if (streamCtxRef.current !== ctx || ctx.epoch !== epoch) return; // superseded
      ctx.attempt += 1;
      openStream(ctx, { kind: "resume" });
    }, delay);
  }

  function handleStreamOutcome(outcome: StreamOutcome, ctx: StreamCtx) {
    if (streamCtxRef.current !== ctx) return; // stopped or superseded — ignore
    switch (outcome.kind) {
      case "done":
        finishStream(ctx, undefined);
        if (ctx.acc) persistAssistantAnswer(ctx.convId, ctx.asstId, ctx.acc);
        if (tier === "anon" && anonUsedToday() >= 1) setLocked(true);
        return;
      case "cancelled":
        // The reaper or another client cancelled it (not this tab's Stop —
        // that path finalizes synchronously and clears streamCtxRef itself,
        // so this handler never even reaches here for a local Stop).
        finishStream(ctx, "stopped");
        if (ctx.acc) persistAssistantAnswer(ctx.convId, ctx.asstId, ctx.acc);
        return;
      case "error": {
        const err = outcome.error;
        if (err.code === "terms_acceptance_required") void refreshAgreement();
        if (err.code === "anon_daily_limit") {
          markAnonUsed();
          setLocked(true);
          setUpsellOpen(true);
        }
        // A bare nginx rate_limited — rejected before any job ever existed,
        // so this is the reverse proxy's burst limiter, not a queue refusal
        // — is transient by nature: one retry after the real Retry-After
        // usually just goes through. Nothing else auto-retries:
        // anon_daily_limit is a hard daily cap (nothing to wait out) and
        // chat_one_at_a_time needs the OTHER generation to finish (the
        // person can already see how long from the sentence itself).
        if (err.kind === "rate_limited" && err.code === "rate_limited" && !ctx.jobId && ctx.attempt === 0 && ctx.startParams) {
          const startParams = ctx.startParams;
          ctx.attempt += 1;
          const delayMs = Math.min(30, Math.max(1, err.retryAfter ?? 1)) * 1000;
          dispatch({ type: "patchMessage", id: ctx.convId, messageId: ctx.asstId, patch: { isLoading: true, state: "interrupted" } });
          resumeTimerRef.current = setTimeout(() => {
            resumeTimerRef.current = null;
            if (streamCtxRef.current !== ctx) return;
            openStream(ctx, { kind: "start", params: startParams });
          }, delayMs);
          return; // streamCtxRef stays ctx — isStreaming stays true through the wait
        }
        finishStream(ctx, "error", explainChatError(err));
        return;
      }
      case "interrupted":
        if (outcome.reason === "aborted") return; // handleStop already finalized this
        if (!ctx.jobId) {
          finishStream(ctx, "error", "Can't reach Oyster right now. Check your connection and try again.");
          return;
        }
        dispatch({
          type: "patchMessage", id: ctx.convId, messageId: ctx.asstId,
          patch: { state: "interrupted", isLoading: false, queue: undefined },
        });
        scheduleResume(ctx);
        return;
    }
  }

  function openStream(ctx: StreamCtx, spec: { kind: "start"; params: StartChatParams } | { kind: "resume" }) {
    clearResumeTimer();
    const cb: StreamCallbacks = {
      onJob: (jobId) => { ctx.jobId = jobId; saveActiveJob(jobId, ctx.convId); },
      onQueue: (position, ahead, etaSeconds) =>
        dispatch({ type: "patchMessage", id: ctx.convId, messageId: ctx.asstId, patch: { queue: { position, ahead, etaSeconds } } }),
      onStart: () => {
        dispatch({ type: "patchMessage", id: ctx.convId, messageId: ctx.asstId, patch: { queue: undefined, isLoading: false, state: "streaming" } });
        // The backend actually commits an anonymous visitor's daily message
        // the moment a slot is granted and generation begins (chat_quota.
        // consume in routers/chat.py's run()) — mirrored here, and ONLY for
        // a fresh send (never a resume, which re-attaches to a job whose
        // quota was already spent when it was first admitted, or the give-up
        // cap would double-count it after a reconnect).
        if (spec.kind === "start" && tier === "anon") markAnonUsed();
      },
      onToken: (t) => {
        ctx.acc += t;
        dispatch({ type: "patchMessage", id: ctx.convId, messageId: ctx.asstId, patch: { content: ctx.acc, isLoading: false, state: "streaming" } });
      },
      onReset: () => {
        ctx.acc = "";
        dispatch({ type: "patchMessage", id: ctx.convId, messageId: ctx.asstId, patch: { content: "" } });
      },
    };
    const handle = spec.kind === "resume" ? resumeJob(ctx.jobId as string, cb) : startChat(spec.params, cb);
    ctx.handle = handle;
    streamCtxRef.current = ctx;
    setIsStreaming(true);
    void handle.result.then((outcome) => handleStreamOutcome(outcome, ctx));
  }

  /** Force an immediate resume attempt, bypassing the remaining backoff wait —
   *  used when the tab comes back to the foreground or the network returns,
   *  since a backgrounded tab's setTimeout is throttled or frozen and may not
   *  fire on its own for a long time (mobile Safari in particular). A no-op
   *  unless a resume is actually pending. */
  function forceResumeActive() {
    const ctx = streamCtxRef.current;
    if (!ctx || !ctx.jobId || resumeTimerRef.current === null) return;
    clearResumeTimer();
    ctx.attempt += 1;
    openStream(ctx, { kind: "resume" });
  }

  useEffect(() => {
    const onVisible = () => { if (!document.hidden) forceResumeActive(); };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("online", forceResumeActive);
    window.addEventListener("pageshow", forceResumeActive);
    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("online", forceResumeActive);
      window.removeEventListener("pageshow", forceResumeActive);
    };
    // forceResumeActive is a plain function (not memoized — see the stream
    // machinery's own note on why), so it is genuinely fresh every render and
    // belongs in the deps: without it, the listeners registered at mount
    // would permanently close over that first render's tier/isSignedIn/etc,
    // which is exactly the staleness this whole rewrite exists to remove.
  }, [forceResumeActive]);

  /** Stop the active generation. Finalizes locally at once (so the UI reacts
   *  in well under a second, never waiting on the network) and best-effort
   *  asks the backend to cancel the job so the slot is freed for the account
   *  rather than waiting out the RUNNING reaper's grace period. */
  const handleStop = useCallback(() => {
    const ctx = streamCtxRef.current;
    if (!ctx) return;
    ctx.epoch += 1; // invalidates any pending resume timer
    clearResumeTimer();
    const jobId = ctx.jobId;
    ctx.handle?.abort();
    streamCtxRef.current = null;
    setIsStreaming(false);
    clearActiveJob(jobId);
    dispatch({
      type: "patchMessage", id: ctx.convId, messageId: ctx.asstId,
      patch: { isLoading: false, queue: undefined, state: "stopped" },
    });
    if (ctx.acc) persistAssistantAnswer(ctx.convId, ctx.asstId, ctx.acc);
    if (jobId) void cancelChatJob(jobId);
  }, [persistAssistantAnswer]);

  // Re-attach to a generation that was still running when the page reloaded.
  // Re-runs as the store fills in (a signed-in user's history loads
  // asynchronously, and the tier resolves first).
  const resumedRef = useRef(false);
  useEffect(() => {
    if (resumedRef.current || tier === null) return;
    let saved: { jobId: string; convId: string } | null = null;
    try {
      const raw = localStorage.getItem(ACTIVE_JOB_KEY);
      saved = raw ? JSON.parse(raw) : null;
    } catch {
      saved = null;
    }
    if (!saved?.jobId) {
      resumedRef.current = true; // nothing to resume; stop re-checking
      return;
    }
    if (!listFor(store, "basic").some((c) => c.id === saved!.convId)) return;
    resumedRef.current = true;

    const asstId = generateId();
    dispatch({
      type: "appendMessages", id: saved.convId,
      messages: [{ id: asstId, role: "assistant", content: "", timestamp: new Date(), isLoading: true, state: "streaming" }],
    });
    const ctx: StreamCtx = { convId: saved.convId, asstId, jobId: saved.jobId, epoch: 0, attempt: 0, acc: "", handle: null };
    openStream(ctx, { kind: "resume" });
  }, [tier, store, openStream]);

  // Signing up right after trying Oyster shouldn't throw away what you just
  // asked it: on the first signed-in load, push any anonymous conversations
  // into the account, then clear the local copy. Runs once per session.
  const migratedRef = useRef(false);
  useEffect(() => {
    if (!isSignedIn || migratedRef.current) return;
    const local = loadLocalHistory().filter((c) => c.messages.length > 0);
    if (local.length === 0) return;
    migratedRef.current = true;
    (async () => {
      const migrated: Conversation[] = [];
      for (const conv of local) {
        try {
          const created = toConv(await createConversation("basic", conv.title));
          for (const m of conv.messages) {
            if (m.content) await addConversationMessage(created.id, m.role, m.content);
          }
          migrated.push({ ...created, title: conv.title, messages: conv.messages });
        } catch {
          break; // backend unhappy — keep the local copy rather than lose it
        }
      }
      if (migrated.length) {
        clearLocalHistory();
        // Every migrated row already has its messages, so it is "loaded" —
        // upsertDraft happens to be exactly that shape (any Conversation,
        // marked loaded, prepended to order) even though these aren't
        // drafts. Reversed so the final prepend order matches `migrated`'s
        // own (newest-first) order. Dispatched via the reducer, so this
        // never has to read a possibly-stale `store` snapshot to know what
        // else loadWorkspace has concurrently put there — it only ever adds.
        for (let i = migrated.length - 1; i >= 0; i--) {
          dispatch({ type: "upsertDraft", conv: migrated[i] });
        }
        setBasicActiveId(migrated[0].id);
      }
    })();
  }, [isSignedIn]);

  // Hydrate messages of the active conversation on select / mode switch.
  // Keyed on hydration state, not a separate "have we ever fetched this" set:
  // "none" (never tried) and "error" (tried, failed) both retry; "loading"
  // and "loaded" both leave it alone. A failed hydrate keeps the chat exactly
  // as it was — never wiped — with an inline Retry (ChatWindow) driving
  // `retryHydrate` below.
  const hydrateConversation = useCallback((id: string) => {
    if (!id || id.startsWith("local-")) return;
    const rec = getConv(store, id);
    if (!rec || (rec.hydration !== "none" && rec.hydration !== "error")) return;
    dispatch({ type: "setHydration", id, hydration: "loading" });
    Promise.all([getConversation(id), getMessageFeedback(id)])
      .then(([conv, feedback]) => {
        if (!conv) throw new Error("not_found");
        dispatch({
          type: "setMessages", id,
          messages: (conv.messages ?? []).map((m) => {
            const msg = toMsg(m);
            const verdict = feedback[msg.id];
            return verdict ? { ...msg, rating: verdict.rating, correction: verdict.correction } : msg;
          }),
        });
      })
      .catch((err) => {
        dispatch({
          type: "setHydration", id, hydration: "error",
          error: err instanceof Error ? err.message : "Couldn't load this conversation.",
        });
      });
  }, [store]);

  useEffect(() => {
    if (activeId) hydrateConversation(activeId);
  }, [activeId, hydrateConversation]);

  const retryHydrate = useCallback(() => {
    if (activeId) hydrateConversation(activeId);
  }, [activeId, hydrateConversation]);

  // Keep the URL in step with the conversation on screen, so a refresh reopens
  // it and its link is shareable. Drafts clear the param (nothing to reopen).
  useEffect(() => {
    syncConvUrl(activeId);
  }, [activeId]);

  // Browser back/forward: re-select whatever conversation the URL now names.
  useEffect(() => {
    const onPop = () => {
      const id = convIdFromUrl();
      if (!id) return;
      const rec = getConv(store, id);
      if (!rec) return;
      setMode(rec.mode);
      if (rec.mode === "rag") setRagActiveId(id);
      else setBasicActiveId(id);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [store]);

  const handleNewConv = useCallback(() => {
    // A new chat is just a client-side draft (both tiers) — no server row until
    // the first message. If the current mode already has an unsaved draft open,
    // reuse it rather than stacking a second "New chat", the way Claude/ChatGPT
    // behave. Only `local-` drafts qualify: a freshly-listed server chat also
    // has messages.length === 0 until it is hydrated, and must not be treated
    // as a reusable blank.
    const blank = conversations.find((c) => c.id.startsWith("local-") && c.messages.length === 0);
    if (blank) {
      setActiveId(blank.id);
      return;
    }
    const created = draftConversation(isRag ? "rag" : "basic");
    dispatch({ type: "upsertDraft", conv: created });
    setActiveId(created.id);
  }, [conversations, isRag, setActiveId]);

  // History actions (persisted for operators; local-only for public tiers)
  const handleRenameConv = useCallback((id: string, title: string) => {
    dispatch({ type: "patchConv", id, patch: { title } });
    if (!id.startsWith("local-")) void renameConversation(id, title);
  }, []);

  const handlePinConv = useCallback((id: string, pinned: boolean) => {
    dispatch({ type: "patchConv", id, patch: { pinned } });
    if (!id.startsWith("local-")) void setConversationPinned(id, pinned);
  }, []);

  const handleDeleteConv = useCallback(async (id: string) => {
    const wasActive = id === activeId;
    if (!id.startsWith("local-")) await deleteConversation(id);
    dispatch({ type: "removeConv", id });
    const remaining = conversations.filter((c) => c.id !== id);
    if (wasActive) {
      // Deleting the open chat opens the next one if any remain, otherwise a
      // fresh client-side draft — never a persisted empty row (which is what
      // made the old "New Chat" shells feel undeletable: deleting one POSTed
      // another).
      if (remaining.length) {
        setActiveId(remaining[0].id);
      } else {
        const created = draftConversation(isRag ? "rag" : "basic");
        dispatch({ type: "upsertDraft", conv: created });
        setActiveId(created.id);
      }
    }
  }, [activeId, conversations, isRag, setActiveId]);

  // Send — basic (streaming). Returns whether the send actually proceeded —
  // ChatInput only clears the composer text on `true`, so a guarded-out or
  // failed send never loses what the person typed.
  const sendBasic = useCallback(
    async (prompt: string, responseDepth: "overview" | "technical" | "guided" | "operational" = "overview"): Promise<boolean> => {
      const conv = conversations.find((c) => c.id === basicActiveId);
      // hydration === "loading" → the messages are still being fetched;
      // sending now would race the hydrate and could lose the message.
      if (!prompt.trim() || isStreaming || isLoading || !conv || conv.hydration === "loading") return false;

      // Anonymous allowance: client-side pre-check for instant UX. The
      // backend's per-IP quota is authoritative (the real enforcement is in
      // the outcome handler's anon_daily_limit branch).
      if (tier === "anon" && anonUsedToday() >= 1) {
        setLocked(true);
        setUpsellOpen(true);
        return false;
      }

      const text = prompt.trim();
      let convId = conv.id;
      const isFirst = conv.messages.length === 0;
      const newTitle = isFirst ? makeTitle(text) : null;
      // Prior turns, captured BEFORE the optimistic user/placeholder messages
      // are appended, so the backend answers this follow-up in context. Trimmed
      // to a budget server-side (num_ctx is small). Signed-in only — anonymous
      // chat is deliberately historyless (the backend ignores it for anon).
      const history: ChatHistoryTurn[] = conv.messages
        .filter((m) => m.content && !m.isLoading)
        .map((m) => ({ role: m.role, content: m.content }));

      // Promote a signed-in DRAFT to a real conversation on its first
      // message. Do it before anything downstream reads convId, and swap the
      // draft id → real id in the store so the row now owns the messages. If
      // the backend is unreachable we keep the draft and still stream — the
      // message simply stays client-side this turn rather than being lost.
      if (isSignedIn && convId.startsWith("local-")) {
        try {
          const created = await createConversation("basic");
          const realId = created.id;
          dispatch({ type: "replaceConvId", oldId: convId, newId: realId });
          setBasicActiveId(realId);
          convId = realId;
        } catch {
          /* backend offline — keep the draft id */
        }
      }

      const userMsg: Message = { id: generateId(), role: "user", content: text, timestamp: new Date() };
      const asstId = generateId();
      // isLoading → the spinner bubble ("Oyster is working") until the first
      // token arrives, then live token streaming takes over.
      const asstMsg: Message = {
        id: asstId, role: "assistant", content: "", timestamp: new Date(), isLoading: true, state: "streaming",
      };

      dispatch({ type: "appendMessages", id: convId, messages: [userMsg, asstMsg] });
      if (newTitle) dispatch({ type: "patchConv", id: convId, patch: { title: newTitle } });

      // Persist user message + auto-title for anyone with an account (the
      // conversations API owns the row). Anonymous chats are written to
      // localStorage by the effect above instead. Fire-and-forget with an id
      // swap on success — a failure here costs nothing but the message
      // rating id, since the content itself already rendered optimistically.
      if (isSignedIn && !convId.startsWith("local-")) {
        void addConversationMessage(convId, "user", text).then((ack) => {
          if (ack) dispatch({ type: "replaceMessageId", convId, oldId: userMsg.id, newId: ack.id });
        });
        if (newTitle) void renameConversation(convId, newTitle);
      }

      const startParams: StartChatParams = {
        prompt: text, systemPrompt, model: selectedModel, agentMode: "chat",
        history, conversationId: convId, responseDepth,
      };
      const ctx: StreamCtx = { convId, asstId, jobId: null, epoch: 0, attempt: 0, acc: "", startParams, handle: null };
      openStream(ctx, { kind: "start", params: startParams });
      return true;
    },
    [conversations, basicActiveId, isStreaming, isLoading, tier, isSignedIn, systemPrompt, selectedModel, openStream]
  );

  // Send — RAG (non-streaming). Also returns whether it proceeded, matching
  // sendBasic's contract so ChatInput has one signature for either mode.
  const sendRag = useCallback(
    async (prompt: string): Promise<boolean> => {
      const conv = conversations.find((c) => c.id === ragActiveId);
      if (!prompt.trim() || isStreaming || isLoading || !conv || conv.hydration === "loading") return false;
      const text = prompt.trim();
      let convId = conv.id;
      const isFirst = conv.messages.length === 0;
      const newTitle = isFirst ? makeTitle(text) : null;
      // Prior turns for follow-up context, captured before the optimistic
      // messages are appended (same as sendBasic). Retrieval still keys on the
      // question; this only helps the model understand "that"/"the second one".
      const history: ChatHistoryTurn[] = conv.messages
        .filter((m) => m.content && !m.isLoading)
        .map((m) => ({ role: m.role, content: m.content }));

      // Promote a signed-in RAG draft to a real conversation on its first
      // message (same as sendBasic) so the row exists before we persist to it.
      if (isSignedIn && convId.startsWith("local-")) {
        try {
          const created = await createConversation("rag");
          const realId = created.id;
          dispatch({ type: "replaceConvId", oldId: convId, newId: realId });
          setRagActiveId(realId);
          convId = realId;
        } catch {
          /* backend offline — keep the draft id */
        }
      }

      const userMsg: Message = { id: generateId(), role: "user", content: text, timestamp: new Date() };
      const asstId = generateId();
      const loadingMsg: Message = { id: asstId, role: "assistant", content: "", timestamp: new Date(), isLoading: true };

      dispatch({ type: "appendMessages", id: convId, messages: [userMsg, loadingMsg] });
      if (newTitle) dispatch({ type: "patchConv", id: convId, patch: { title: newTitle } });
      setIsLoading(true);

      // Skip persistence if promotion failed (still a draft) — never POST to a
      // local- id, which the backend has no row for.
      if (!convId.startsWith("local-")) {
        void addConversationMessage(convId, "user", text).then((ack) => {
          if (ack) dispatch({ type: "replaceMessageId", convId, oldId: userMsg.id, newId: ack.id });
        });
        if (newTitle) void renameConversation(convId, newTitle);
      }

      try {
        const data = await askProject(activeProjectId, prompt, selectedModel, 5, history);
        dispatch({
          type: "patchMessage", id: convId, messageId: asstId,
          patch: { content: data.answer, citations: data.citations, documentsQueried: data.citations.length, isLoading: false },
        });
        if (!convId.startsWith("local-")) {
          void addConversationMessage(convId, "assistant", data.answer, data.citations, data.citations.length).then((ack) => {
            if (ack) dispatch({ type: "replaceMessageId", convId, oldId: asstId, newId: ack.id });
          });
        }
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : "RAG error";
        dispatch({
          type: "patchMessage", id: convId, messageId: asstId,
          patch: { content: `Error: ${errMsg}`, isLoading: false, state: "error" },
        });
      } finally {
        setIsLoading(false);
      }
      return true;
    },
    [conversations, ragActiveId, isStreaming, isLoading, selectedModel, activeProjectId, isSignedIn]
  );

  const handleSend = isRag ? sendRag : sendBasic;

  // Edit a previous USER message and resubmit. The clean model: drop the edited
  // message and everything after it (backend first so the resend persists onto a
  // truncated conversation, then locally), then resend the edited text as a
  // fresh turn — a regenerated continuation, never a misleadingly spliced
  // history. The resend fires from an effect keyed on `store` rather than
  // inline, because dispatch is asynchronous relative to this callback:
  // calling sendBasic/sendRag directly here would read the PRE-truncation
  // messages and double up the edited turn.
  const pendingEditRef = useRef<{ mode: "basic" | "rag"; convId: string; text: string } | null>(null);

  const handleEditMessage = useCallback(async (msg: Message, newContent: string) => {
    const text = newContent.trim();
    if (!text) return;
    const ragMode = mode === "rag";
    const convId = ragMode ? ragActiveId : basicActiveId;
    const conv = conversations.find((c) => c.id === convId);
    if (!conv || isStreaming || isLoading) return;
    const idx = conv.messages.findIndex((m) => m.id === msg.id);
    if (idx < 0 || conv.messages[idx].role !== "user") return;
    if (text === conv.messages[idx].content.trim()) return; // unchanged — no-op

    if (!convId.startsWith("local-")) {
      // Server truncation first so the resend's persisted messages don't land
      // after the now-stale downstream turns.
      await truncateConversationFrom(convId, msg.id);
    }
    const kept = conv.messages.slice(0, idx);
    dispatch({ type: "replaceMessages", id: convId, messages: kept });
    pendingEditRef.current = { mode: ragMode ? "rag" : "basic", convId, text };
  }, [mode, ragActiveId, basicActiveId, conversations, isStreaming, isLoading]);

  useEffect(() => {
    const p = pendingEditRef.current;
    if (!p) return;
    // One-shot: cleared now regardless of outcome, so a guard miss (the user
    // switched mode/conversation before the truncation's re-render landed)
    // can never leave a stale resend armed to fire later if they happen to
    // return to the same mode/conversation without having edited anything.
    pendingEditRef.current = null;
    if (mode !== p.mode) return;
    const liveId = p.mode === "rag" ? ragActiveId : basicActiveId;
    if (liveId !== p.convId) return;
    if (p.mode === "basic") void sendBasic(p.text);
    else void sendRag(p.text);
  }, [store, mode, basicActiveId, ragActiveId, sendBasic, sendRag]);

  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showToast = useCallback((text: string) => {
    setToast(text);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 2200);
  }, []);

  const handleMessageAction = useCallback(
    (action: MessageAction, msg: Message) => {
      if (action === "pin" || action === "bookmark") {
        const field = action === "pin" ? "pinned" : "bookmarked";
        if (activeId) {
          dispatch({
            type: "patchMessage", id: activeId, messageId: msg.id,
            patch: { [field]: !msg[field] } as Partial<Message>,
          });
        }
        return;
      }
      if (action === "rateUp" || action === "rateDown") {
        if (!isSignedIn) return void showToast("Sign in to rate answers.");
        if (!activeId) return void showToast("Rate answers in a saved chat.");

        const wanted = action === "rateUp" ? "up" : "down";
        // Clicking the thumb that is already lit clears the vote, matching how
        // Pin/Bookmark behave in this same toolbar.
        const clearing = msg.rating === wanted;

        let correction = "";
        if (!clearing && wanted === "down") {
          // The rating alone only lets a bad answer be dropped from training.
          // The correction is what turns it into a good example instead — so we
          // ask, but never require it: an empty answer still records the vote.
          correction =
            window.prompt(
              "What should the answer have been? (optional — leave blank to just mark it wrong)",
              msg.correction || ""
            ) ?? "";
        }

        const nextRating = clearing ? undefined : (wanted as "up" | "down");
        dispatch({
          type: "patchMessage", id: activeId, messageId: msg.id,
          patch: { rating: nextRating, correction: clearing ? "" : correction },
        });

        void setMessageFeedback(activeId, msg.id, clearing ? null : (wanted as "up" | "down"), correction)
          .then((ok) => {
            if (!ok) {
              // Put the old value back rather than leaving the UI asserting
              // something the server never stored. `msg` here is still the
              // PRE-toggle message, captured by this closure.
              dispatch({
                type: "patchMessage", id: activeId, messageId: msg.id,
                patch: { rating: msg.rating, correction: msg.correction },
              });
              return void showToast("Couldn’t save that feedback.");
            }
            if (clearing) return void showToast("Feedback cleared");
            showToast(
              correction
                ? "Thanks — Oyster will use your correction from the next message"
                : wanted === "up"
                ? "Marked as a good answer"
                : "Marked as wrong — it won’t be used for training"
            );
          });
        return;
      }
      if (action === "createFinding" || action === "addToReport") {
        if (!isSignedIn) return void showToast("Sign in to save findings.");
        const forReport = action === "addToReport";
        void createUserFinding({
          content: msg.content,
          conversation_id: activeId || null,
          conv_mode: mode,
          message_id: msg.id,
          citations: msg.citations,
          in_report: forReport,
        }).then((f) => {
          if (f) {
            setFindingsRefresh((n) => n + 1);
            showToast(forReport ? "Added to report" : "Saved to Findings");
          } else {
            showToast("Couldn’t save that finding.");
          }
        });
        return;
      }
      if (action === "summarize") return void handleSend("Summarize your previous answer concisely.");
      if (action === "explain") return void handleSend("Explain your previous answer in simpler terms with an example.");
      if (action === "regenerate") {
        const msgs = activeConversation?.messages ?? [];
        const idx = msgs.findIndex((m) => m.id === msg.id);
        for (let i = idx - 1; i >= 0; i--) {
          if (msgs[i].role === "user") return void handleSend(msgs[i].content);
        }
      }
    },
    [activeId, handleSend, activeConversation, isSignedIn, mode, showToast]
  );

  const handleUploadFiles = useCallback(async (files: File[]) => {
    setIsUploading(true);
    try {
      await uploadArtifacts(activeProjectId, files);
      await refreshArtifacts();
    } catch (e) {
      console.error("Upload failed:", e);
    } finally {
      setIsUploading(false);
    }
  }, [activeProjectId, refreshArtifacts]);

  const handleUploadFolder = useCallback(async (files: File[]) => {
    setIsUploading(true);
    try {
      await uploadFolder(activeProjectId, files);
      await refreshArtifacts();
    } catch (e) {
      console.error("Folder upload failed:", e);
    } finally {
      setIsUploading(false);
    }
  }, [activeProjectId, refreshArtifacts]);

  const handleUploadImages = useCallback(async (files: File[]) => {
    setIsUploading(true);
    try {
      await uploadImages(activeProjectId, files);
      await refreshArtifacts();
    } catch (e) {
      console.error("Image upload failed:", e);
    } finally {
      setIsUploading(false);
    }
  }, [activeProjectId, refreshArtifacts]);

  const handleUploadVideos = useCallback(async (files: File[]) => {
    setIsUploading(true);
    try {
      await uploadVideos(activeProjectId, files);
      await refreshArtifacts();
    } catch (e) {
      console.error("Video upload failed:", e);
    } finally {
      setIsUploading(false);
    }
  }, [activeProjectId, refreshArtifacts]);

  const handleCreateNote = useCallback(async (title: string, content: string) => {
    setIsUploading(true);
    try {
      await createNoteApi(activeProjectId, title, content);
      await refreshArtifacts();
    } catch (e) {
      console.error("Note failed:", e);
    } finally {
      setIsUploading(false);
    }
  }, [activeProjectId, refreshArtifacts]);

  const handleRemoveArtifact = useCallback(async (id: string) => {
    setArtifacts((prev) => prev.filter((a) => a.id !== id)); // optimistic
    await deleteArtifact(activeProjectId, id);
    refreshArtifacts();
  }, [activeProjectId, refreshArtifacts]);

  const handleSummarizeArtifact = useCallback(async (id: string) => {
    const convId = activeId;
    if (!convId) return;
    const art = artifacts.find((a) => a.id === id);
    const userMsg: Message = { id: generateId(), role: "user", content: `Summarize ${art?.filename ?? "this file"}`, timestamp: new Date() };
    const asstId = generateId();
    const loading: Message = { id: asstId, role: "assistant", content: "", timestamp: new Date(), isLoading: true };
    dispatch({ type: "appendMessages", id: convId, messages: [userMsg, loading] });
    try {
      const res = await summarizeArtifact(activeProjectId, id, selectedModel);
      dispatch({ type: "patchMessage", id: convId, messageId: asstId, patch: { content: res.summary, isLoading: false } });
      void addConversationMessage(convId, "user", userMsg.content);
      void addConversationMessage(convId, "assistant", res.summary).then((ack) => {
        if (ack) dispatch({ type: "replaceMessageId", convId, oldId: asstId, newId: ack.id });
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Summarize failed";
      dispatch({ type: "patchMessage", id: convId, messageId: asstId, patch: { content: `Error: ${msg}`, isLoading: false, state: "error" } });
    }
  }, [activeId, artifacts, activeProjectId, selectedModel]);

  // ---- Project switcher (operators only) ------------------------------------
  // Switching or creating a project flips the global active pointer on the
  // backend (which also re-syncs scope) and then reloads that project's whole
  // workspace so chats/artifacts follow. loadWorkspace resets the store itself
  // (see its own comment) — the new project's conversations are entirely
  // different rows, so nothing from the old one should survive the switch.
  // listConversations (inside loadWorkspace) now THROWS on failure (F1) —
  // every call site below wraps it, so a flaky network mid-switch surfaces as
  // a toast, never an uncaught rejection.

  const handleSwitchProject = useCallback(async (id: string) => {
    if (id === activeProjectId) return;
    const project = await activateProject(id);
    if (!project) return void showToast("Couldn't switch project — please try again.");
    setActiveProjectId(project.id);
    setActiveProjectName(project.name);
    setProjects((prev) => prev.map((p) => ({ ...p, is_active: p.id === project.id })));
    try {
      await loadWorkspace(project.id);
    } catch {
      showToast("Couldn't load that project's chats — try switching again.");
    }
  }, [activeProjectId, loadWorkspace, showToast]);

  const handleCreateProject = useCallback(async (name: string) => {
    const project = await createProject(name); // activate=true by default
    if (!project) return void showToast("Couldn't create that project.");
    setActiveProjectId(project.id);
    setActiveProjectName(project.name);
    setProjects((prev) => [
      ...prev.map((p) => ({ ...p, is_active: false })),
      { ...project, is_active: true },
    ]);
    try {
      await loadWorkspace(project.id);
    } catch {
      showToast("Project created, but couldn't load its chats yet — try reopening it.");
    }
  }, [loadWorkspace, showToast]);

  const handleRenameProject = useCallback(async (id: string, name: string) => {
    const project = await renameProject(id, name);
    if (!project) return;
    setProjects((prev) => prev.map((p) => (p.id === id ? { ...p, name: project.name } : p)));
    if (id === activeProjectId) setActiveProjectName(project.name);
  }, [activeProjectId]);

  // Returns null on success, or a message to show (the backend refuses to
  // delete the protected `default` project).
  const handleDeleteProject = useCallback(async (id: string): Promise<string | null> => {
    const res = await deleteProject(id);
    if (!res.ok) return res.error ?? "Could not delete project.";
    setProjects((prev) => prev.filter((p) => p.id !== id));
    if (id === activeProjectId) {
      // Deleting the active project reassigns the pointer server-side — re-read
      // it and reload that workspace.
      let active: Awaited<ReturnType<typeof getActiveProject>> | null = null;
      try {
        active = await getActiveProject();
      } catch {
        active = null;
      }
      const pid = active?.project?.id ?? "default";
      setActiveProjectId(pid);
      if (active?.project?.name) setActiveProjectName(active.project.name);
      setProjects((prev) => prev.map((p) => ({ ...p, is_active: p.id === pid })));
      try {
        await loadWorkspace(pid);
      } catch {
        showToast("Project deleted, but couldn't reload your workspace — try refreshing.");
      }
    }
    return null;
  }, [activeProjectId, loadWorkspace, showToast]);

  // Jump from a finding card into its source chat: switch project if the
  // finding lives in a different one, then select the right mode + conversation.
  const openFindingChat = useCallback(async (f: UserFinding) => {
    const targetMode: Mode = f.conv_mode === "rag" ? "rag" : "basic";
    if (f.project_id && f.project_id !== activeProjectId) {
      await handleSwitchProject(f.project_id);
    }
    setMode(targetMode);
    if (f.conversation_id) {
      if (targetMode === "rag") setRagActiveId(f.conversation_id);
      else setBasicActiveId(f.conversation_id);
    }
  }, [activeProjectId, handleSwitchProject]);

  // --- reuse a published finding -------------------------------------------
  // Someone else's finding becomes the opening message of a NEW chat in the
  // reuser's own workspace. It cannot continue the ORIGINAL thread: the feed
  // deliberately carries no conversation_id or project_id (that is the privacy
  // guarantee), and the original lives in another account's project.
  const pendingSeedRef = useRef<{ convId: string; text: string } | null>(null);

  // How much of a finding's body we paste into the opening message.
  //
  // The model runs with a 4096-token context (OYSTER_OLLAMA_NUM_CTX) — roughly
  // 15k characters shared between the system prompt, this message AND the
  // answer. Findings are just chat messages, so nothing bounds their length,
  // and an oversized one does not fail loudly: llama.cpp drops the OLDEST part
  // of the prompt, which is the system prompt, so the agent quietly loses its
  // instructions. 6k characters covers every finding on the box today (longest
  // 4,873, average 3,430) while still leaving room for the system prompt and a
  // full answer. Anything longer is trimmed with a visible marker rather than
  // silently cut.
  const FINDING_BODY_LIMIT = 6000;

  const clip = (text: string): string =>
    text.length <= FINDING_BODY_LIMIT
      ? text
      : `${text.slice(0, FINDING_BODY_LIMIT).trimEnd()}\n\n…[finding trimmed here to fit the context window — open it in Findings to read the rest]`;

  // The finding is the context; the QUESTION is whatever the person picked or
  // typed in the feed. Their words go last, so it is their question the model
  // answers rather than a sentence we chose for them.
  const seedFromFinding = (f: PublicFinding, question: string): string => {
    const lines = [`I want to work from a published finding: **${f.title}**`, ""];
    const facts = [
      f.severity ? `Severity: ${f.severity}` : "",
      f.endpoint ? `Affected: ${f.method || ""} ${f.endpoint}`.trim() : "",
      f.author ? `Shared by: ${f.author}` : "",
    ].filter(Boolean);
    if (facts.length) lines.push(facts.join(" · "), "");
    lines.push(clip(f.content.trim()), "");
    if (f.recommended_fix?.trim()) {
      lines.push(`Recommended fix: ${clip(f.recommended_fix.trim())}`, "");
    }
    lines.push(question.trim());
    return lines.join("\n");
  };

  const handleReuseFinding = useCallback((f: PublicFinding, question: string) => {
    if (!isSignedIn) return void showToast("Sign in to start a chat from a finding.");
    const draft = draftConversation("basic");
    dispatch({ type: "upsertDraft", conv: draft });
    setBasicActiveId(draft.id);
    setMode("basic");
    // sendBasic reads the ACTIVE conversation out of state, so calling it now
    // would find nothing and silently bail. Hand the seed to an effect that
    // fires once React has flushed the new conversation into place.
    pendingSeedRef.current = { convId: draft.id, text: seedFromFinding(f, question) };
    showToast("Started a new chat from that finding");
  }, [isSignedIn, showToast]);

  useEffect(() => {
    const pending = pendingSeedRef.current;
    if (!pending || mode !== "basic" || basicActiveId !== pending.convId) return;
    if (!getConv(store, pending.convId)) return;
    pendingSeedRef.current = null;
    void sendBasic(pending.text);
  }, [mode, basicActiveId, store, sendBasic]);

  const isChatMode = mode === "basic" || mode === "rag";
  const toggleSidebar = () =>
    setSidebarOpen((v) => !(v ?? window.matchMedia("(min-width: 768px)").matches));

  // Signed-in accounts see a spinner until their workspace has loaded, and a
  // sentence with a Retry if it could not — never the blank pane that used
  // to mean "tier still resolving" and "boot failed" alike.
  const booting = tier === null || (isSignedIn && (bootState === "idle" || bootState === "loading"));
  const bootFailed = isSignedIn && bootState === "error";

  return (
    <div className="flex h-app overflow-hidden bg-oyster-bg">
      <Sidebar
        tier={tier}
        mode={mode}
        onModeChange={setMode}
        conversations={conversations}
        activeConvId={activeId}
        onSelectConv={setActiveId}
        onNewConv={handleNewConv}
        onRenameConv={handleRenameConv}
        onDeleteConv={handleDeleteConv}
        onPinConv={handlePinConv}
        backendOk={backendOk}
        isOpen={sidebarOpen}
        onToggle={toggleSidebar}
        selectedModel={selectedModel}
        onModelChange={setSelectedModel}
        activeProjectName={activeProjectName}
        onOpenSettings={() => setSettingsOpen(true)}
        onOpenHandbook={() => setHandbookOpen(true)}
        searchOpen={searchOpen}
        onToggleSearch={() => setSearchOpen((v) => !v)}
        projects={projects}
        activeProjectId={activeProjectId}
        onSwitchProject={handleSwitchProject}
        onCreateProject={handleCreateProject}
        onRenameProject={handleRenameProject}
        onDeleteProject={handleDeleteProject}
      />

      {booting ? (
        <BootScreen />
      ) : bootFailed ? (
        <BootScreen error={bootError} onRetry={() => void bootWorkspace()} />
      ) : isChatMode && activeConversation ? (
        <ErrorBoundary resetKey={activeConversation.id}>
          <ChatWindow
            conversation={activeConversation}
            hydration={activeConversation.hydration}
            hydrationError={activeConversation.hydrationError}
            onRetryHydrate={retryHydrate}
            mode={mode}
            isStreaming={isStreaming}
            isLoading={isLoading}
            onStop={mode === "basic" ? handleStop : undefined}
            onForceResume={mode === "basic" ? forceResumeActive : undefined}
            artifacts={artifacts}
            projectId={activeProjectId}
            onUploadFiles={handleUploadFiles}
            onUploadFolder={handleUploadFolder}
            onUploadImages={handleUploadImages}
            onUploadVideos={handleUploadVideos}
            onCreateNote={handleCreateNote}
            onOpenKnowledge={() => setKnowledgeOpen(true)}
            onRemoveArtifact={handleRemoveArtifact}
            onSummarizeArtifact={handleSummarizeArtifact}
            onOpenArtifact={setPreviewArtifact}
            isUploading={isUploading}
            onSend={handleSend}
            onToggleSidebar={toggleSidebar}
            sidebarOpen={sidebarOpen}
            selectedModel={selectedModel}
            activeProjectName={activeProjectName}
            systemPrompt={systemPrompt}
            onSystemPromptChange={setSystemPrompt}
            onMessageAction={handleMessageAction}
            onEditMessage={handleEditMessage}
            welcomeKey={`${activeConversation.id}:${activeProjectName}`}
            isLocked={locked}
            onLockedClick={() => setUpsellOpen(true)}
            searchOpen={searchOpen}
            onCloseSearch={() => setSearchOpen(false)}
          />
        </ErrorBoundary>
      ) : mode === "scope" ? (
        <ScopePanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} />
      ) : mode === "recon" ? (
        <ReconPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} selectedModel={selectedModel} />
      ) : mode === "testplan" ? (
        <TestPlannerPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} selectedModel={selectedModel} />
      ) : mode === "fix" ? (
        <FixAdvisorPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} selectedModel={selectedModel} />
      ) : mode === "execute" ? (
        <ExecutionPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} activeProjectName={activeProjectName} />
      ) : mode === "soccopilot" ? (
        <SocCopilotPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} activeProjectName={activeProjectName} />
      ) : mode === "cookbook" ? (
        <CookBookPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} />
      ) : mode === "notes" ? (
        <NotesPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} />
      ) : mode === "codelab" ? (
        <CodeLabPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} />
      ) : mode === "shield" ? (
        <ShieldPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} />
      ) : mode === "intel" ? (
        <SecurityIntelligencePanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} selectedModel={selectedModel} />
      ) : mode === "redbears" ? (
        <RedBearsPanel onToggleSidebar={toggleSidebar} sidebarOpen={sidebarOpen ?? true} selectedModel={selectedModel} />
      ) : mode === "findings" ? (
        <FindingsPanel
          onToggleSidebar={toggleSidebar}
          sidebarOpen={sidebarOpen ?? true}
          projectId={activeProjectId}
          onOpenChat={openFindingChat}
          onReuseFinding={handleReuseFinding}
          refreshKey={findingsRefresh}
        />
      ) : (
        <div className="flex-1" />
      )}

      {toast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[80] px-4 py-2 rounded-lg bg-oyster-sidebar border border-oyster-border shadow-2xl text-sm text-oyster-text">
          {toast}
        </div>
      )}

      {settingsOpen && (
        <AccountSettingsModal
          onClose={() => setSettingsOpen(false)}
          selectedModel={selectedModel}
          onModelChange={setSelectedModel}
          backendOk={backendOk}
          onReconnect={handleReconnect}
          projectId={activeProjectId}
        />
      )}

      {previewArtifact && (
        <ArtifactPreview
          projectId={activeProjectId}
          artifact={previewArtifact}
          onClose={() => setPreviewArtifact(null)}
        />
      )}

      {knowledgeOpen && (
        <KnowledgePacksModal onClose={() => setKnowledgeOpen(false)} />
      )}

      {upsellOpen && <UpsellModal onClose={() => setUpsellOpen(false)} />}

      <HandbookPanel
        open={handbookOpen}
        context={modeToHandbookContext(mode)}
        onClose={() => setHandbookOpen(false)}
      />
    </div>
  );
}

export default function Home() {
  return (
    <AuthGate>
      <OysterApp />
    </AuthGate>
  );
}
