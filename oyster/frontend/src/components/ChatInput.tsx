"use client";

import { useState, useRef, KeyboardEvent, useEffect } from "react";
import {
  Send,
  Square,
  Plus,
  FileText,
  FolderUp,
  StickyNote,
  Loader2,
  Lock,
  X,
  AlertCircle,
  FileType2,
  Image as ImageIcon,
  Video,
  Sparkles,
  BookOpen,
} from "lucide-react";
import { type Artifact, artifactThumbnailUrl, isMediaProcessing } from "@/lib/api";
import { AuthenticatedImage } from "@/components/AuthenticatedMedia";
import { useAuth } from "./AuthGate";

const FILE_ACCEPT =
  ".pdf,.docx,.txt,.md,.markdown,.rst,.log,.json,.jsonl,.csv,.tsv,.yaml,.yml,.toml,.ini,.cfg,.conf,.xml,.html,.htm,.css,.sql,.sh,.bash,.py,.js,.ts,.tsx,.jsx,.mjs,.java,.kt,.go,.rb,.php,.c,.h,.cpp,.hpp,.cc,.cs,.rs,.swift,.scala,.lua,.r,.dart,.vue,.svelte";
const IMAGE_ACCEPT = "image/png,image/jpeg,image/webp,image/gif,image/svg+xml,image/bmp,image/tiff";
const VIDEO_ACCEPT = "video/mp4,video/quicktime,video/webm,video/x-matroska,video/x-m4v,video/avi";

interface ChatInputProps {
  /** Returns whether the send actually proceeded — the composer text is
   *  cleared only on `true`, so a guarded-out or failed send never loses
   *  what was typed. */
  onSend: (prompt: string) => Promise<boolean>;
  /** Stop the active generation. When present and `isStreaming` is true, the
   *  send button becomes a working Stop button instead of a decorative icon —
   *  it used to be a no-op while streaming, which read as broken. */
  onStop?: () => void;
  isStreaming: boolean;
  placeholder?: string;
  projectId: string;
  onUploadFiles: (files: File[]) => void;
  onUploadFolder: (files: File[]) => void;
  onUploadImages: (files: File[]) => void;
  onUploadVideos: (files: File[]) => void;
  onCreateNote: (title: string, content: string) => void;
  onOpenKnowledge: () => void;
  artifacts: Artifact[];
  onRemoveArtifact: (id: string) => void;
  onSummarizeArtifact: (id: string) => void;
  onOpenArtifact: (a: Artifact) => void;
  isUploading: boolean;
  /** Anonymous daily allowance spent — composer disabled, lock button shown. */
  isLocked?: boolean;
  /** Clicking the composer while locked (opens the upsell). */
  onLockedClick?: () => void;
  /** Attachments/knowledge are operator features — hidden for public tiers. */
  allowAttach?: boolean;
}

function kindIcon(a: Artifact) {
  if (a.kind === "note") return StickyNote;
  if (a.kind === "image") return ImageIcon;
  if (a.kind === "video") return Video;
  return FileType2;
}

/** Short in-progress label from the granular backend status. */
function statusLabel(a: Artifact): string {
  switch (a.status) {
    case "transcribing": return "transcribing";
    case "analyzing": return "analyzing";
    case "indexing": return "indexing";
    case "validating": return "validating";
    case "extracting": return "extracting";
    case "uploaded": return "queued";
    default: return "processing";
  }
}

export function ChatInput({
  onSend,
  onStop,
  isStreaming,
  placeholder = "Ask Oyster anything…",
  projectId,
  onUploadFiles,
  onUploadFolder,
  onUploadImages,
  onUploadVideos,
  onCreateNote,
  onOpenKnowledge,
  artifacts,
  onRemoveArtifact,
  onSummarizeArtifact,
  onOpenArtifact,
  isUploading,
  isLocked = false,
  onLockedClick,
  allowAttach = true,
}: ChatInputProps) {
  const { trainingConsent, tier } = useAuth();
  const [value, setValue] = useState("");
  // Guards the gap between clicking Send and the parent flipping isStreaming
  // true (there's an await in between — promoting a draft conversation to a
  // real one) so a fast double-click cannot fire the request twice.
  const [sending, setSending] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [noteOpen, setNoteOpen] = useState(false);
  const [noteTitle, setNoteTitle] = useState("");
  const [noteBody, setNoteBody] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const filesRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const imagesRef = useRef<HTMLInputElement>(null);
  const videosRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const close = () => setMenuOpen(false);
    if (menuOpen) window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [menuOpen]);

  // set webkitdirectory on the folder input (not a standard React attribute)
  useEffect(() => {
    if (folderRef.current) {
      folderRef.current.setAttribute("webkitdirectory", "");
      folderRef.current.setAttribute("directory", "");
    }
  }, []);

  const handleSend = async () => {
    if (isLocked) {
      onLockedClick?.();
      return;
    }
    if (!value.trim() || isStreaming || sending) return;
    const text = value;
    setSending(true);
    try {
      const ok = await onSend(text);
      if (ok) {
        setValue("");
        if (textareaRef.current) textareaRef.current.style.height = "auto";
      }
      // ok === false: the send was guarded out or failed outright — leave the
      // text in place so nothing typed is lost.
    } catch {
      // onSend is contracted to resolve false rather than throw; caught here
      // anyway so a surprise exception can never escape as an unhandled
      // rejection or silently swallow what was typed.
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setValue(e.target.value);
    const el = e.target;
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 200) + "px";
  };

  const canSend = !isLocked && value.trim().length > 0 && !isStreaming && !sending;

  const menuItem =
    "w-full flex items-center gap-2.5 px-3 py-2 text-left text-[13px] text-oyster-text rounded-lg cursor-pointer transition-colors hover:bg-oyster-bg/70";

  return (
    <div className="shrink-0 bg-oyster-bg px-4 pt-2 safe-bottom">
      <div className="max-w-3xl mx-auto">
        {/* Attachment chips */}
        {artifacts.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-2.5">
            {artifacts.map((a) => {
              const Icon = kindIcon(a);
              const isMedia = a.kind === "image" || a.kind === "video";
              const processing = isMediaProcessing(a);
              const hasThumb = isMedia && a.status === "ready" && a.metadata?.thumbnail !== false;
              const clickable = isMedia && a.status !== "failed";
              return (
                <span
                  key={a.id}
                  onClick={() => clickable && onOpenArtifact(a)}
                  className={`group inline-flex items-center gap-1.5 max-w-[240px] bg-oyster-surface border border-oyster-border rounded-lg pl-1.5 pr-1 py-1 text-xs text-oyster-text transition-colors hover:border-oyster-accent/40 ${clickable ? "cursor-pointer" : ""}`}
                  title={a.status === "failed" ? a.error || "Failed" : clickable ? `Open ${a.filename}` : a.relative_path || a.filename}
                >
                  {hasThumb ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <AuthenticatedImage
                      src={artifactThumbnailUrl(projectId, a.id)}
                      alt=""
                      className="w-6 h-6 rounded object-cover border border-oyster-border shrink-0"
                    />
                  ) : processing ? (
                    <Loader2 size={12} className="text-oyster-accent shrink-0 animate-spin" />
                  ) : a.status === "failed" ? (
                    <AlertCircle size={12} className="text-red-400 shrink-0" />
                  ) : (
                    <Icon size={12} className="text-oyster-accent shrink-0" />
                  )}
                  <span className="flex flex-col min-w-0">
                    <span className={`truncate ${a.status === "failed" ? "text-oyster-muted line-through" : ""}`}>
                      {a.filename}
                    </span>
                    {processing && (
                      <span className="text-[9px] text-oyster-accent/80 leading-none capitalize">{statusLabel(a)}…</span>
                    )}
                    {a.kind === "video" && a.status === "ready" && a.metadata?.duration_seconds != null && (
                      <span className="text-[9px] text-oyster-muted leading-none">
                        {Math.floor(a.metadata.duration_seconds / 60)}:{`${Math.floor(a.metadata.duration_seconds % 60)}`.padStart(2, "0")}
                      </span>
                    )}
                  </span>
                  {a.status === "ready" && (
                    <button
                      onClick={(e) => { e.stopPropagation(); onSummarizeArtifact(a.id); }}
                      className="cursor-pointer text-oyster-muted hover:text-oyster-accent shrink-0 p-0.5 rounded transition-colors"
                      title="Summarize this file"
                    >
                      <Sparkles size={12} />
                    </button>
                  )}
                  <button
                    onClick={(e) => { e.stopPropagation(); onRemoveArtifact(a.id); }}
                    className="cursor-pointer text-oyster-muted hover:text-red-400 shrink-0 p-0.5 rounded transition-colors"
                    title="Remove"
                  >
                    <X size={12} />
                  </button>
                </span>
              );
            })}
          </div>
        )}

        {/* hidden inputs */}
        <input
          ref={filesRef}
          type="file"
          multiple
          accept={FILE_ACCEPT}
          className="hidden"
          onChange={(e) => {
            const files = Array.from(e.target.files ?? []);
            if (files.length) onUploadFiles(files);
            e.target.value = "";
          }}
        />
        <input
          ref={folderRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => {
            const files = Array.from(e.target.files ?? []);
            if (files.length) onUploadFolder(files);
            e.target.value = "";
          }}
        />
        <input
          ref={imagesRef}
          type="file"
          multiple
          accept={IMAGE_ACCEPT}
          className="hidden"
          onChange={(e) => {
            const files = Array.from(e.target.files ?? []);
            if (files.length) onUploadImages(files);
            e.target.value = "";
          }}
        />
        <input
          ref={videosRef}
          type="file"
          multiple
          accept={VIDEO_ACCEPT}
          className="hidden"
          onChange={(e) => {
            const files = Array.from(e.target.files ?? []);
            if (files.length) onUploadVideos(files);
            e.target.value = "";
          }}
        />

        {/* Composer */}
        <div
          onClick={isLocked ? onLockedClick : undefined}
          className={`relative flex items-end gap-2 bg-oyster-surface border rounded-2xl pl-2 pr-2 py-2 transition-colors ${
            isLocked
              ? "border-oyster-accent/40 cursor-pointer"
              : "border-oyster-border focus-within:border-oyster-accent/50"
          }`}
        >
          {allowAttach && (
          <div className="relative shrink-0">
            <button
              onClick={(e) => { e.stopPropagation(); setMenuOpen((v) => !v); }}
              disabled={isUploading}
              aria-label="Add attachment"
              className="cursor-pointer w-9 h-9 rounded-lg flex items-center justify-center text-oyster-muted hover:text-oyster-accent hover:bg-oyster-bg/60 transition-all duration-150 hover:-translate-y-0.5 disabled:opacity-50"
            >
              {isUploading ? <Loader2 size={18} className="animate-spin" /> : <Plus size={20} />}
            </button>

            {menuOpen && (
              <div
                onClick={(e) => e.stopPropagation()}
                className="absolute bottom-12 left-0 z-50 w-52 bg-oyster-surface border border-oyster-border rounded-xl shadow-2xl p-1.5 animate-[fadeUp_0.12s_ease-out]"
              >
                <button className={menuItem} onClick={() => { setMenuOpen(false); filesRef.current?.click(); }}>
                  <FileText size={15} className="shrink-0 text-oyster-accent" />
                  <span className="flex-1">Upload Files</span>
                </button>
                <button className={menuItem} onClick={() => { setMenuOpen(false); folderRef.current?.click(); }}>
                  <FolderUp size={15} className="shrink-0 text-oyster-accent" />
                  <span className="flex-1">Upload Folder</span>
                </button>
                <button className={menuItem} onClick={() => { setMenuOpen(false); imagesRef.current?.click(); }}>
                  <ImageIcon size={15} className="shrink-0 text-oyster-accent" />
                  <span className="flex-1">Upload Image</span>
                </button>
                <button className={menuItem} onClick={() => { setMenuOpen(false); videosRef.current?.click(); }}>
                  <Video size={15} className="shrink-0 text-oyster-accent" />
                  <span className="flex-1">Upload Video</span>
                </button>
                <div className="my-1 border-t border-oyster-border" />
                <button className={menuItem} onClick={() => { setMenuOpen(false); onOpenKnowledge(); }}>
                  <BookOpen size={15} className="shrink-0 text-oyster-accent" />
                  <span className="flex-1">Import Knowledge Pack</span>
                </button>
                <button className={menuItem} onClick={() => { setMenuOpen(false); setNoteOpen(true); }}>
                  <StickyNote size={15} className="shrink-0 text-oyster-accent" />
                  <span className="flex-1">Create Note</span>
                </button>
              </div>
            )}
          </div>
          )}

          <textarea
            ref={textareaRef}
            value={value}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            placeholder={isLocked ? "Daily free message used — create a free account for unlimited chat" : placeholder}
            rows={1}
            disabled={isLocked}
            // 16px on phones: below that, iOS Safari zooms the page on focus and
            // never zooms back out. Desktop keeps the tighter 15px.
            className="flex-1 bg-transparent resize-none outline-none text-base md:text-[15px] text-oyster-text placeholder:text-oyster-muted leading-relaxed max-h-48 overflow-y-auto py-1.5 disabled:cursor-pointer"
          />

          <button
            onClick={() => {
              if (isStreaming && onStop) onStop();
              else void handleSend();
            }}
            disabled={!isLocked && !(isStreaming && onStop) && !canSend}
            aria-label={isLocked ? "Unlock unlimited chat" : isStreaming && onStop ? "Stop generating" : "Send"}
            title={
              isLocked
                ? "Create a free account for unlimited chat"
                : isStreaming && onStop
                  ? "Stop generating"
                  : undefined
            }
            className={`shrink-0 w-9 h-9 rounded-lg flex items-center justify-center transition-all duration-150 ${
              isLocked
                ? "bg-oyster-accent/20 text-oyster-accent hover:bg-oyster-accent/30 cursor-pointer"
                : isStreaming && onStop
                  ? "bg-oyster-surface border border-oyster-border hover:border-red-400/50 text-oyster-text hover:text-red-400 cursor-pointer"
                  : canSend
                    ? "bg-oyster-accent hover:bg-oyster-accent-hover text-white hover:-translate-y-0.5"
                    : "bg-oyster-border/60 text-oyster-muted cursor-not-allowed"
            }`}
          >
            {isLocked ? <Lock size={15} /> : isStreaming ? <Square size={14} className="fill-current" /> : <Send size={16} />}
          </button>
        </div>

        {/* This line is a promise to the user, so it must be derived from the
            actual stored state — never hardcoded. Saying "not used for
            training" to someone who accepted would be a lie, and saying the
            opposite to an anonymous visitor (whose chats really are never
            stored) would be alarming and false. */}
        <p className="text-center text-[11px] text-oyster-muted/70 mt-2.5">
          Oyster chat ·{" "}
          {trainingConsent
            ? "your chats help improve Oyster — manage in Settings"
            : tier === "admin" || tier === "user"
              ? "workspace conversation history enabled"
              : "not signed in — chats stay in your browser, never used for training"}
        </p>
      </div>

      {/* Create Note modal */}
      {noteOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onKeyDown={(e) => e.key === "Escape" && setNoteOpen(false)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setNoteOpen(false)} />
          <div className="relative w-full max-w-md bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl p-5">
            <h2 className="text-sm font-semibold text-oyster-text mb-3 flex items-center gap-2">
              <StickyNote size={15} className="text-oyster-accent" /> Create Note
            </h2>
            <input
              autoFocus
              value={noteTitle}
              onChange={(e) => setNoteTitle(e.target.value)}
              placeholder="Title (optional)"
              className="w-full bg-oyster-surface border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 mb-2"
            />
            <textarea
              value={noteBody}
              onChange={(e) => setNoteBody(e.target.value)}
              placeholder="Write a note — it becomes searchable in this project…"
              rows={5}
              className="w-full bg-oyster-surface border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50"
            />
            <div className="flex items-center justify-end gap-2 mt-4">
              <button
                onClick={() => setNoteOpen(false)}
                className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface border border-oyster-border transition-colors"
              >
                Cancel
              </button>
              <button
                disabled={!noteBody.trim()}
                onClick={() => { onCreateNote(noteTitle, noteBody); setNoteOpen(false); setNoteTitle(""); setNoteBody(""); }}
                className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Save Note
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
