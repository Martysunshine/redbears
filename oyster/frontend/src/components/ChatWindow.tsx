"use client";

import { useEffect, useRef, useState } from "react";
import { PanelLeftOpen, BookOpen, MessageSquare, Settings2, FolderKanban, Cpu, Sparkles, AlertCircle, Loader2 } from "lucide-react";
import { type Conversation, type Mode } from "@/types/chat";
import { type Hydration } from "@/lib/conversationStore";
import { MODELS, type Artifact } from "@/lib/api";
import { ChatMessage } from "./ChatMessage";
import { ChatInput } from "./ChatInput";
import { ChatSearch } from "./ChatSearch";
import { OysterMascot } from "./OysterMascot";
import { type MessageAction } from "./MessageToolbar";
import { useAuth } from "./AuthGate";
import { RedOrcaMark } from "./brand";
import { DASHBOARD_URL } from "@/lib/site";

interface ChatWindowProps {
  conversation: Conversation;
  /** Per-conversation fetch state (lib/conversationStore.ts). "none"/"loading"
   *  show a spinner in place of the messages; "error" shows a Retry; "loaded"
   *  is the only state where an empty `messages` array means "this really is
   *  a new, empty chat" rather than "hasn't been fetched yet". */
  hydration: Hydration;
  hydrationError?: string;
  onRetryHydrate: () => void;
  mode: Mode;
  isStreaming: boolean;
  isLoading: boolean;
  /** Stop the active generation. Only meaningful for basic (streaming) chat —
   *  undefined in RAG mode, where there is nothing to cancel. */
  onStop?: () => void;
  /** Force an immediate resume of an interrupted stream, bypassing its
   *  remaining backoff wait. Surfaced as "Retry now" on an interrupted bubble. */
  onForceResume?: () => void;
  artifacts: Artifact[];
  projectId: string;
  onUploadFiles: (files: File[]) => void;
  onUploadFolder: (files: File[]) => void;
  onUploadImages: (files: File[]) => void;
  onUploadVideos: (files: File[]) => void;
  onCreateNote: (title: string, content: string) => void;
  onOpenKnowledge: () => void;
  onRemoveArtifact: (id: string) => void;
  onSummarizeArtifact: (id: string) => void;
  onOpenArtifact: (a: Artifact) => void;
  isUploading: boolean;
  /** Returns whether the send actually proceeded (guarded out or failed
   *  attempts resolve false) — ChatInput uses this to decide whether to
   *  clear the composer text. */
  onSend: (prompt: string, responseDepth?: "overview" | "technical" | "guided" | "operational") => Promise<boolean>;
  onToggleSidebar: () => void;
  sidebarOpen: boolean | null;
  selectedModel: string;
  activeProjectName: string;
  systemPrompt: string;
  onSystemPromptChange: (v: string) => void;
  onMessageAction: (action: MessageAction, msg: import("@/types/chat").Message) => void;
  /** Edit a previous user message and resubmit (regenerates the reply below). */
  onEditMessage?: (msg: import("@/types/chat").Message, newContent: string) => void;
  /** Changes on new chat / project switch / load → replays the welcome animation. */
  welcomeKey: string;
  /** Anonymous allowance spent — locks the composer. */
  isLocked?: boolean;
  onLockedClick?: () => void;
  /** Search now lives in the sidebar; its open state is lifted to the page so
   *  the sidebar button can toggle the panel this window still renders. */
  searchOpen: boolean;
  onCloseSearch: () => void;
}

const MODE_META: Record<"basic" | "rag", { label: string; icon: React.ElementType; placeholder: string }> = {
  basic: { label: "Chat", icon: MessageSquare, placeholder: "Ask Oyster anything…" },
  rag: { label: "RAG Analyst", icon: BookOpen, placeholder: "Ask about your uploaded files…" },
};

export function ChatWindow({
  conversation,
  hydration,
  hydrationError,
  onRetryHydrate,
  mode,
  isStreaming,
  isLoading,
  onStop,
  onForceResume,
  artifacts,
  projectId,
  onUploadFiles,
  onUploadFolder,
  onUploadImages,
  onUploadVideos,
  onCreateNote,
  onOpenKnowledge,
  onRemoveArtifact,
  onSummarizeArtifact,
  onOpenArtifact,
  isUploading,
  onSend,
  onToggleSidebar,
  sidebarOpen,
  selectedModel,
  activeProjectName,
  systemPrompt,
  onSystemPromptChange,
  onMessageAction,
  onEditMessage,
  welcomeKey,
  isLocked = false,
  onLockedClick,
  searchOpen,
  onCloseSearch,
}: ChatWindowProps) {
  const [responseDepth, setResponseDepth] = useState<"overview" | "technical" | "guided" | "operational">("overview");
  const bottomRef = useRef<HTMLDivElement>(null);
  const { tier, session, openAuth } = useAuth();
  const isOperator = tier === "admin";
  const chatMode = mode as "basic" | "rag";
  const meta = MODE_META[chatMode];
  const Icon = meta.icon;
  const modelLabel = MODELS.find((m) => m.key === selectedModel)?.label ?? selectedModel;

  const [promptOpen, setPromptOpen] = useState(false);
  const isSignedIn = tier === "user" || tier === "admin";

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [conversation.messages]);

  const isEmpty = conversation.messages.length === 0;
  const readyCount = artifacts.filter((a) => a.status === "ready").length;
  const noDocsForRag = mode === "rag" && readyCount === 0;

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      {/* Header */}
      <header className="flex items-center gap-3 px-4 h-14 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {sidebarOpen !== true && (
          <button
            onClick={onToggleSidebar}
            className={`cursor-pointer text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface ${
              sidebarOpen === null ? "md:hidden" : ""
            }`}
          >
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Icon size={16} className="text-oyster-accent shrink-0" />
        <span className="text-[15px] font-medium text-oyster-text truncate">{meta.label}</span>

        <div className="ml-auto flex items-center gap-2 min-w-0">
          {/* context badges — any signed-in account (the project shown is
              their own workspace; only operators can switch between several) */}
          {isSignedIn && (
            <>
              {isOperator && (
                <span className="hidden sm:flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface/60 px-2.5 py-1 rounded-md border border-oyster-border">
                  <FolderKanban size={12} className="text-oyster-muted" />
                  <span className="max-w-[140px] truncate">{activeProjectName || "Default Engagement"}</span>
                </span>
              )}
              <span className="flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface/60 px-2.5 py-1 rounded-md border border-oyster-border">
                <Cpu size={12} className="text-green-500" />
                {modelLabel}
              </span>
            </>
          )}

          {isSignedIn && (
            <button
              onClick={() => { setPromptOpen((v) => !v); }}
              className={`cursor-pointer p-1.5 rounded-md transition-colors ${
                promptOpen ? "text-oyster-accent bg-oyster-accent/10" : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface"
              }`}
              title="System prompt"
            >
              <Settings2 size={16} />
            </button>
          )}

          {/* auth area — public tiers */}
          {tier === "anon" && (
            <>
              <span className="hidden sm:flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface/60 px-2.5 py-1 rounded-md border border-oyster-border">
                <Sparkles size={12} className="text-oyster-accent" />
                1 free message/day
              </span>
              {/* Phones only have room for one call to action — sign-in is
                  still reachable from inside the sign-up modal's tabs. */}
              <button
                onClick={() => openAuth("signin")}
                className="hidden sm:block cursor-pointer px-2.5 py-1.5 rounded-md text-xs font-medium text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface transition-colors"
              >
                Sign in
              </button>
              <button
                onClick={() => openAuth("signup")}
                className="cursor-pointer shrink-0 px-3 py-1.5 rounded-md text-xs font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white transition-colors"
              >
                <span className="sm:hidden">Sign up</span>
                <span className="hidden sm:inline">Create account</span>
              </button>
            </>
          )}
          {isSignedIn && (
            <>
              <span className="hidden lg:block max-w-[160px] truncate text-xs text-oyster-muted">
                {session?.user?.email}
              </span>
              {/* Account hub on the main site. A plain <a>, never next/link:
                  <Link> would prefix basePath and send /oyster/account. */}
              <a
                href={DASHBOARD_URL}
                title="Red Orca dashboard"
                className="flex shrink-0 cursor-pointer items-center gap-1.5 rounded-md border border-oyster-border px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-oyster-muted transition-colors hover:border-oyster-accent/40 hover:bg-oyster-surface hover:text-oyster-text"
              >
                <RedOrcaMark width={17} />
                <span className="hidden sm:inline">Dashboard</span>
              </a>
              {/* The settings wheel used to sit here. It now lives in the
                  sidebar footer, merged with the old Oyster-config gear so
                  there is exactly one Settings door. */}
            </>
          )}
        </div>
      </header>

      {/* System prompt panel (hidden by default) */}
      {promptOpen && (
        <div className="border-b border-oyster-border bg-oyster-bg/95">
          <div className="max-w-3xl mx-auto px-4 py-3">
            <label className="text-[10px] font-semibold text-oyster-muted uppercase tracking-widest mb-1.5 block">
              System Prompt
            </label>
            <textarea
              value={systemPrompt}
              onChange={(e) => onSystemPromptChange(e.target.value)}
              placeholder="You are Oyster, a local security operator assistant…"
              rows={3}
              className="w-full bg-oyster-surface border border-oyster-border rounded-xl px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50 transition-colors"
            />
          </div>
        </div>
      )}

      {/* Unified search */}
      {searchOpen && <ChatSearch messages={conversation.messages} onClose={onCloseSearch} />}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto">
        {hydration === "loading" || hydration === "none" ? (
          <HydratingState />
        ) : hydration === "error" ? (
          <HydrationErrorState error={hydrationError} onRetry={onRetryHydrate} />
        ) : noDocsForRag && isEmpty ? (
          <NoDocsState />
        ) : isEmpty ? (
          <EmptyState key={welcomeKey} mode={chatMode} onSend={onSend} />
        ) : (
          <div className="max-w-3xl mx-auto px-4 py-6">
            {conversation.messages.map((msg, idx) => (
              <ChatMessage
                key={msg.id}
                message={msg}
                isStreaming={isStreaming && idx === conversation.messages.length - 1 && msg.role === "assistant"}
                onAction={onMessageAction}
                onForceResume={onForceResume}
                onEditMessage={onEditMessage}
                busy={isStreaming || isLoading}
              />
            ))}
            <div ref={bottomRef} />
          </div>
        )}
      </div>

      {/* Input */}
      <div className="max-w-3xl mx-auto px-4 pb-2 flex items-center gap-2 text-xs text-oyster-muted">
        <span className="uppercase tracking-widest">Depth</span>
        {([['overview','Quick'],['technical','Technical'],['guided','Guided'],['operational','Lab']] as const).map(([value, label]) => (
          <button key={value} type="button" onClick={() => setResponseDepth(value)} className={`rounded-md px-2 py-1 border transition-colors ${responseDepth === value ? "border-oyster-accent text-oyster-accent bg-oyster-surface" : "border-oyster-border hover:text-oyster-text"}`}>
            {label}
          </button>
        ))}
      </div>
      <ChatInput
        onSend={(prompt) => onSend(prompt, responseDepth)}
        isStreaming={isStreaming || isLoading}
        onStop={onStop}
        placeholder={meta.placeholder}
        isLocked={isLocked}
        onLockedClick={onLockedClick}
        projectId={projectId}
        onUploadFiles={onUploadFiles}
        onUploadFolder={onUploadFolder}
        onUploadImages={onUploadImages}
        onUploadVideos={onUploadVideos}
        onCreateNote={onCreateNote}
        onOpenKnowledge={onOpenKnowledge}
        isUploading={isUploading}
        artifacts={artifacts}
        onRemoveArtifact={onRemoveArtifact}
        onSummarizeArtifact={onSummarizeArtifact}
        onOpenArtifact={onOpenArtifact}
      />
    </div>
  );
}

function HydratingState() {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-3 text-oyster-muted">
      <Loader2 size={20} className="animate-spin" />
      <p className="text-sm">Loading conversation…</p>
    </div>
  );
}

function HydrationErrorState({ error, onRetry }: { error?: string; onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-3 px-4 text-center">
      <AlertCircle size={22} className="text-red-400" />
      <p className="text-sm text-oyster-text">Couldn&apos;t load this chat{error ? ` — ${error}` : ""}.</p>
      <button
        onClick={onRetry}
        className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white transition-colors"
      >
        Retry
      </button>
    </div>
  );
}

function EmptyState({ mode, onSend }: { mode: "basic" | "rag"; onSend: (prompt: string) => Promise<boolean> }) {
  const suggestions =
    mode === "basic"
      ? [
          "Map the attack surface of localhost:8001",
          "Review this FastAPI endpoint for vulns",
          "Write a rate-limiter for Oyster's /chat",
          "What auth issues should I test first?",
        ]
      : [
          "What are the key findings in the uploaded report?",
          "Summarize the architecture doc",
          "What does the RoE say about testing scope?",
          "List all critical vulnerabilities found",
        ];

  return (
    <div className="flex flex-col items-center justify-center h-full gap-10 px-4 text-center select-none">
      <OysterMascot size={210} animated variant="welcome" />
      <div className="space-y-3 -mt-2">
        <h1 className="text-[30px] font-semibold text-oyster-text tracking-tight">
          {mode === "basic" ? "How can I help?" : "Ask Your Files"}
        </h1>
        <p className="text-oyster-muted text-[15px] max-w-md mx-auto leading-relaxed">
          {mode === "basic"
            ? "Security-focused AI by Red Orca — vulnerabilities, hardening, defense. Start typing below."
            : "Answers grounded in your uploaded files, with citations."}
        </p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-w-lg w-full">
        {suggestions.map((s) => (
          <button
            key={s}
            onClick={() => void onSend(s)}
            className="cursor-pointer text-left text-[13px] text-oyster-muted bg-oyster-surface/60 border border-oyster-border rounded-xl px-4 py-3.5 transition-all duration-150 hover:border-oyster-accent/40 hover:text-oyster-text hover:bg-oyster-surface hover:-translate-y-0.5 hover:shadow-lg hover:shadow-black/20"
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}

function NoDocsState() {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-4 px-4 text-center">
      <div className="w-14 h-14 rounded-2xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
        <BookOpen size={24} className="text-oyster-muted" />
      </div>
      <div className="space-y-2">
        <h2 className="text-lg font-semibold text-oyster-text">No documents yet</h2>
        <p className="text-oyster-muted text-sm max-w-xs">
          Attach PDFs or TXT files with the + button below to build your knowledge base, then ask questions here.
        </p>
      </div>
    </div>
  );
}
