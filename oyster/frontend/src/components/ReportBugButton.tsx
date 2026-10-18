"use client";

// "Report Bug" — the one control that must be reachable from anywhere.
//
// It sits in the sidebar footer beside the model selector because that strip is
// the only thing on screen in every mode, and a bug report you have to go
// looking for is a bug report nobody files. Red on purpose: it is the single
// alarm-coloured affordance in an otherwise calm chrome, so it reads as
// "something is wrong" without a label hunt.
//
// Unlike the model selector next to it, this is NOT gated on being signed in.
// Oyster has an anonymous tier, and someone who hits a bug before they ever
// sign up is exactly the reporter you otherwise never hear from — they just
// type their address instead of having it filled in.

import { useEffect, useRef, useState } from "react";
import { Bug, Hammer, Loader2, Paperclip, X } from "lucide-react";
import { BUG_REPORT_LIMITS, submitBugReport } from "@/lib/api";

const isVideo = (f: File) => f.type.startsWith("video/");

/**
 * Read a clip's length in the browser. The Red Orca backend image has no
 * ffprobe, so LENGTH is guaranteed here and SIZE is guaranteed server-side.
 *
 * Resolves null when the duration is unreadable: MediaRecorder's WebM output
 * routinely reports `Infinity` because it writes no duration into the header,
 * and refusing a legitimate screen recording over that would be worse than
 * letting the size cap catch it.
 */
function readDuration(file: File): Promise<number | null> {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const v = document.createElement("video");
    const done = (val: number | null) => {
      URL.revokeObjectURL(url);
      resolve(val);
    };
    v.preload = "metadata";
    v.onloadedmetadata = () =>
      done(Number.isFinite(v.duration) && v.duration > 0 ? v.duration : null);
    v.onerror = () => done(null);
    v.src = url;
  });
}

export function ReportBugButton({ userEmail }: { userEmail: string | null }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="Report a bug"
        aria-label="Report a bug"
        className="group shrink-0 cursor-pointer rounded-md border border-red-500/30
                   bg-red-500/10 p-1.5 text-red-400 transition-colors
                   hover:border-red-500/60 hover:bg-red-500/20 hover:text-red-300"
      >
        <span className="relative flex h-4 w-4 items-center justify-center">
          <Bug size={15} />
          {/* The hammer rides the bug's shoulder — "found it, now fix it". */}
          <Hammer
            size={9}
            className="absolute -bottom-1 -right-1.5 rotate-12 transition-transform
                       group-hover:-rotate-12"
          />
        </span>
      </button>

      {open && (
        <ReportBugModal onClose={() => setOpen(false)} userEmail={userEmail} />
      )}
    </>
  );
}

function ReportBugModal({
  onClose,
  userEmail,
}: {
  onClose: () => void;
  userEmail: string | null;
}) {
  const [email, setEmail] = useState(userEmail ?? "");
  const [description, setDescription] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sentId, setSentId] = useState<number | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (userEmail) setEmail(userEmail);
  }, [userEmail]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const locked = Boolean(userEmail);
  const hasVideo = files.some(isVideo);
  // Oyster is a single-page app: the mode is the only meaningful "where", and
  // it is already in the URL hash/search the shell maintains.
  const page = typeof window !== "undefined" ? window.location.pathname + window.location.search : "";

  async function addFiles(picked: FileList | null) {
    if (!picked || picked.length === 0) return;
    setError("");
    const incoming = Array.from(picked);

    const video = incoming.find(isVideo);
    if (video) {
      if (incoming.length > 1 || files.length > 0) {
        setError("Attach screenshots or one video — not both.");
        return;
      }
      if (video.size > BUG_REPORT_LIMITS.maxVideoMB * 1024 * 1024) {
        setError(`That clip is over ${BUG_REPORT_LIMITS.maxVideoMB} MB.`);
        return;
      }
      const seconds = await readDuration(video);
      if (seconds !== null && seconds > BUG_REPORT_LIMITS.maxVideoSeconds + 0.5) {
        setError(
          `Videos can be up to ${BUG_REPORT_LIMITS.maxVideoSeconds} seconds — ` +
            `that one is ${Math.round(seconds)}s.`
        );
        return;
      }
      setFiles([video]);
      return;
    }

    if (hasVideo) {
      setError("Attach screenshots or one video — not both.");
      return;
    }
    const images = incoming.filter((f) => f.type.startsWith("image/"));
    if (images.length !== incoming.length) {
      setError("Attach images (PNG/JPG) or one short video.");
      return;
    }
    const tooBig = images.find((f) => f.size > BUG_REPORT_LIMITS.maxImageMB * 1024 * 1024);
    if (tooBig) {
      setError(`${tooBig.name} is over ${BUG_REPORT_LIMITS.maxImageMB} MB.`);
      return;
    }
    if (files.length + images.length > BUG_REPORT_LIMITS.maxImages) {
      setError(`Up to ${BUG_REPORT_LIMITS.maxImages} screenshots.`);
    }
    setFiles([...files, ...images].slice(0, BUG_REPORT_LIMITS.maxImages));
  }

  async function submit() {
    if (!description.trim()) {
      setError("Please describe what happened.");
      return;
    }
    if (!email.trim()) {
      setError("Please enter your email address.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await submitBugReport({
        description: description.trim(),
        email: email.trim(),
        page,
        files,
      });
      setSentId(res.id);
    } catch (err) {
      setError((err as Error)?.message || "Could not send the report. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-[85] flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="bug-title"
    >
      <div className="absolute inset-0 bg-black/65 backdrop-blur-sm" onClick={onClose} />

      <div className="relative flex max-h-[88vh] w-full max-w-lg flex-col rounded-2xl border border-oyster-border bg-oyster-sidebar shadow-2xl">
        <div className="flex shrink-0 items-center gap-2.5 border-b border-oyster-border p-5 pb-4">
          <span className="relative flex h-5 w-5 items-center justify-center text-red-400">
            <Bug size={18} />
            <Hammer size={10} className="absolute -bottom-1 -right-1.5 rotate-12" />
          </span>
          <h2 id="bug-title" className="text-base font-semibold text-oyster-text">
            {sentId !== null ? "Thanks — that helps" : "Report a bug"}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="ml-auto cursor-pointer rounded p-1 text-oyster-muted transition-colors hover:text-oyster-text"
          >
            <X size={16} />
          </button>
        </div>

        {sentId !== null ? (
          <div className="p-6 text-center">
            <p className="text-sm text-oyster-text">
              Report <span className="tabular-nums">#{sentId}</span> is in. We read every one.
            </p>
            <button
              onClick={onClose}
              className="mt-5 cursor-pointer rounded-lg bg-oyster-surface px-4 py-2 text-sm
                         font-medium text-oyster-text transition-colors hover:bg-oyster-surface/70"
            >
              Close
            </button>
          </div>
        ) : (
          <>
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-5">
              <section>
                <label
                  htmlFor="bug-email"
                  className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-oyster-muted"
                >
                  Your email
                </label>
                <input
                  id="bug-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  readOnly={locked}
                  placeholder="you@company.com"
                  className={`w-full rounded-lg border border-oyster-border bg-oyster-bg px-3 py-2
                              text-sm text-oyster-text outline-none placeholder:text-oyster-muted/60
                              focus:border-red-500/50 ${locked ? "cursor-not-allowed text-oyster-muted" : ""}`}
                />
                <p className="mt-1 text-[11px] text-oyster-muted">
                  {locked ? "From your account — so we can reply." : "So we can reply."}
                </p>
              </section>

              <section>
                <label
                  htmlFor="bug-what"
                  className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-oyster-muted"
                >
                  What happened?
                </label>
                <textarea
                  id="bug-what"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={5}
                  autoFocus
                  placeholder="What were you doing, what did you expect, and what happened instead?"
                  className="w-full resize-y rounded-lg border border-oyster-border bg-oyster-bg px-3 py-2
                             text-sm text-oyster-text outline-none placeholder:text-oyster-muted/60
                             focus:border-red-500/50"
                />
              </section>

              <section>
                <span className="mb-1.5 block text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
                  Attachments (optional)
                </span>
                <input
                  ref={inputRef}
                  type="file"
                  multiple
                  accept="image/png,image/jpeg,image/webp,image/gif,video/webm,video/mp4,video/quicktime"
                  onChange={(e) => {
                    void addFiles(e.target.files);
                    e.target.value = ""; // so re-picking the same file still fires
                  }}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg
                             border border-dashed border-oyster-border px-3 py-3 text-sm
                             text-oyster-muted transition-colors hover:border-red-500/40 hover:text-oyster-text"
                >
                  <Paperclip size={14} />
                  Add screenshots or a clip
                </button>
                <p className="mt-1.5 text-[11px] text-oyster-muted">
                  Up to {BUG_REPORT_LIMITS.maxImages} screenshots, or one video of{" "}
                  {BUG_REPORT_LIMITS.maxVideoSeconds}s or less.
                </p>

                {files.length > 0 && (
                  <ul className="mt-3 space-y-1.5">
                    {files.map((f, i) => (
                      <li
                        key={`${f.name}-${i}`}
                        className="flex items-center gap-2 rounded-lg bg-oyster-surface px-3 py-2 text-xs"
                      >
                        <span className="flex-1 truncate text-oyster-text">{f.name}</span>
                        <span className="tabular-nums text-oyster-muted">
                          {(f.size / (1024 * 1024)).toFixed(1)} MB
                        </span>
                        <button
                          type="button"
                          onClick={() => setFiles(files.filter((_, j) => j !== i))}
                          aria-label={`Remove ${f.name}`}
                          className="cursor-pointer rounded p-0.5 text-oyster-muted transition-colors hover:text-red-400"
                        >
                          <X size={13} />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {error && (
                <p className="rounded-lg border border-red-500/25 bg-red-500/10 px-3 py-2 text-xs text-red-300">
                  {error}
                </p>
              )}
            </div>

            <div className="flex shrink-0 justify-end gap-3 border-t border-oyster-border p-5 pt-4">
              <button
                onClick={onClose}
                disabled={busy}
                className="cursor-pointer rounded-lg px-4 py-2 text-sm font-medium text-oyster-muted
                           transition-colors hover:text-oyster-text disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={submit}
                disabled={busy}
                className="flex cursor-pointer items-center gap-2 rounded-lg bg-red-600 px-4 py-2
                           text-sm font-semibold text-white transition-colors hover:bg-red-500
                           disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy && <Loader2 size={14} className="animate-spin" />}
                {busy ? "Sending…" : "Send report"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
