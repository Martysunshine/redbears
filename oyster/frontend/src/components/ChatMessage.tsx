"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import { Loader2, Pencil, Check } from "lucide-react";
import { type Message } from "@/types/chat";
import { CitationList } from "./CitationCard";
import { OysterMascot } from "./OysterMascot";
import { MessageToolbar, type MessageAction } from "./MessageToolbar";

interface ChatMessageProps {
  message: Message;
  isStreaming?: boolean;
  onAction?: (action: MessageAction, message: Message) => void;
  /** Force an immediate resume of an interrupted stream (bypasses its
   *  backoff wait). Only meaningful on the message currently interrupted;
   *  harmless to pass to every message since only that one renders the link. */
  onForceResume?: () => void;
  /** Edit a previous USER message and resubmit. Absent ⇒ editing disabled
   *  (e.g. while another answer is generating). */
  onEditMessage?: (message: Message, newContent: string) => void;
  /** Something is generating right now — hide the edit affordance so an edit
   *  can't race an in-flight answer. */
  busy?: boolean;
}

/** Rounded, human wait. Precision here would be false — the ETA is an estimate. */
function formatEta(seconds: number): string {
  if (seconds < 60) return `${Math.max(5, Math.round(seconds / 5) * 5)} seconds`;
  const mins = Math.round(seconds / 60);
  return `${mins} minute${mins === 1 ? "" : "s"}`;
}

export function ChatMessage({ message, isStreaming, onAction, onForceResume, onEditMessage, busy }: ChatMessageProps) {
  const isUser = message.role === "user";
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const canEdit = isUser && !!onEditMessage && !busy;

  const startEdit = () => { setDraft(message.content); setEditing(true); };
  const cancelEdit = () => { setEditing(false); setDraft(""); };
  const saveEdit = () => {
    const next = draft.trim();
    if (!next || next === message.content.trim()) { cancelEdit(); return; }
    setEditing(false);
    onEditMessage?.(message, next);
  };

  if (message.isLoading) {
    // While queued, say so plainly. A spinner that sits for 40 seconds reads
    // as "broken"; "2 ahead of you, about 40 seconds" reads as "working, and
    // here's why it's taking a moment" — the same wait, honestly labelled.
    const q = message.queue;
    return (
      <div className="flex gap-3 py-3 justify-start">
        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5">
          <OysterMascot size={32} variant="sidebar" />
        </div>
        <div className="bg-oyster-surface border border-oyster-border rounded-2xl rounded-bl-sm px-4 py-3">
          {q && q.position > 0 ? (
            <div className="flex items-center gap-2">
              <Loader2 size={14} className="shrink-0 text-oyster-accent animate-spin" />
              <span className="text-[13px] text-oyster-muted">
                {q.ahead === 0
                  ? "You're next"
                  : `Waiting — ${q.ahead} ${q.ahead === 1 ? "person" : "people"} ahead of you`}
                {q.etaSeconds > 0 && (
                  <span className="text-oyster-muted/70"> · about {formatEta(q.etaSeconds)}</span>
                )}
              </span>
            </div>
          ) : (
            <Loader2 size={14} className="text-oyster-muted animate-spin" />
          )}
        </div>
      </div>
    );
  }

  return (
    <div className={`group flex gap-3 py-4 ${isUser ? "justify-end" : "justify-start"}`}>
      {!isUser && (
        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5">
          <OysterMascot size={32} variant="sidebar" />
        </div>
      )}

      <div className={isUser ? "max-w-[80%] min-w-0" : "max-w-[85%] min-w-0"}>
      {isUser && editing ? (
        <div className="w-full">
          <textarea
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); saveEdit(); }
              if (e.key === "Escape") { e.preventDefault(); cancelEdit(); }
            }}
            aria-label="Edit your message"
            rows={Math.min(8, Math.max(2, draft.split("\n").length))}
            className="w-full bg-oyster-surface border border-oyster-accent/50 rounded-2xl px-4 py-3 text-[15px] text-oyster-text leading-relaxed resize-none outline-none focus:border-oyster-accent"
          />
          <div className="flex items-center justify-end gap-2 mt-2">
            <span className="mr-auto text-[11px] text-oyster-muted">Editing resends and replaces the replies below.</span>
            <button
              onClick={cancelEdit}
              className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface border border-oyster-border transition-colors outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60"
            >
              Cancel
            </button>
            <button
              onClick={saveEdit}
              disabled={!draft.trim()}
              className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60"
            >
              <Check size={13} /> Save &amp; resend
            </button>
          </div>
        </div>
      ) : (
      <div
        className={`
          rounded-2xl px-4 py-3 text-[15px] leading-relaxed
          ${
            isUser
              ? "bg-oyster-accent text-white rounded-br-sm"
              : "bg-oyster-surface border border-oyster-border text-oyster-text rounded-bl-sm"
          }
        `}
      >
        {isUser ? (
          <p className="whitespace-pre-wrap">{message.content}</p>
        ) : (
          <div>
            <div className={`prose prose-sm ${isStreaming && !message.content ? "cursor-blink" : ""}`}>
              {message.content ? (
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    code({ className, children, ...props }) {
                      const match = /language-(\w+)/.exec(className || "");
                      const isBlock = match != null;
                      return isBlock ? (
                        <SyntaxHighlighter
                          style={vscDarkPlus as Record<string, React.CSSProperties>}
                          language={match[1]}
                          PreTag="div"
                          customStyle={{
                            margin: "0.5rem 0",
                            borderRadius: "8px",
                            border: "1px solid #2a2a2a",
                            fontSize: "0.8rem",
                          }}
                        >
                          {String(children).replace(/\n$/, "")}
                        </SyntaxHighlighter>
                      ) : (
                        <code className={className} {...props}>
                          {children}
                        </code>
                      );
                    },
                  }}
                >
                  {message.content}
                </ReactMarkdown>
              ) : (
                <span className="text-oyster-muted">
                  <span className="cursor-blink" />
                </span>
              )}
              {isStreaming && message.content && <span className="cursor-blink" />}
            </div>

            {message.citations && message.citations.length > 0 && (
              <CitationList
                citations={message.citations}
                documentsQueried={message.documentsQueried}
              />
            )}
          </div>
        )}
      </div>
      )}

        {!isUser && message.state && message.state !== "streaming" && (
          <StatusTag state={message.state} hasContent={!!message.content} onForceResume={onForceResume} />
        )}

        {!isUser && !isStreaming && message.content && onAction && (
          <MessageToolbar message={message} onAction={onAction} />
        )}

        {isUser && canEdit && !editing && (
          <div className="flex justify-end mt-1.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
            <button
              onClick={startEdit}
              title="Edit & resend"
              aria-label="Edit this message"
              className="cursor-pointer inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[11px] text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface transition-colors outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60"
            >
              <Pencil size={12} /> Edit
            </button>
          </div>
        )}
      </div>

      {isUser && (
        <div className="w-8 h-8 rounded-lg bg-oyster-surface border border-oyster-border flex items-center justify-center shrink-0 mt-0.5">
          <span className="text-xs font-bold text-oyster-muted">U</span>
        </div>
      )}
    </div>
  );
}

/**
 * The small status line under an assistant bubble that is not simply
 * "finished" — added 2026-09-14 so a lost connection reads as "reconnecting",
 * not as a dead composer the reader has to refresh the page to escape.
 *
 * `error` with no partial content is deliberately silent here: the bubble's
 * `content` already carries the explanatory sentence in that case (see
 * page.tsx's finishStream), and a second, redundant tag under an otherwise
 * empty-of-real-answer bubble would just be noise.
 */
function StatusTag({
  state,
  hasContent,
  onForceResume,
}: {
  state: NonNullable<Message["state"]>;
  hasContent: boolean;
  onForceResume?: () => void;
}) {
  if (state === "interrupted") {
    return (
      <div className="mt-1.5 flex items-center gap-1.5 text-[11px] text-amber-500">
        <Loader2 size={11} className="shrink-0 animate-spin" />
        <span>Connection interrupted — reconnecting…</span>
        {onForceResume && (
          <button
            onClick={onForceResume}
            className="cursor-pointer text-oyster-muted underline decoration-dotted hover:text-oyster-text hover:no-underline"
          >
            Retry now
          </button>
        )}
      </div>
    );
  }
  if (state === "stopped") {
    return <div className="mt-1.5 text-[11px] text-oyster-muted">Stopped</div>;
  }
  if (state === "error" && hasContent) {
    return <div className="mt-1.5 text-[11px] text-red-400">Couldn&apos;t finish — try again</div>;
  }
  return null;
}
