"use client";

import { useEffect, useRef, useState } from "react";
import { X, FileWarning, ShieldAlert, ScanText, Film, Image as ImageIcon, Clock } from "lucide-react";
import {
  type Artifact,
  artifactFileUrl,
  artifactFrameUrl,
  getArtifact,
} from "@/lib/api";
import { AuthenticatedImage, AuthenticatedVideo } from "@/components/AuthenticatedMedia";

function fmt(sec: number): string {
  const s = Math.floor(sec % 60);
  const m = Math.floor((sec / 60) % 60);
  const h = Math.floor(sec / 3600);
  const mm = `${m}`.padStart(2, "0");
  const ss = `${s}`.padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

export function ArtifactPreview({
  projectId,
  artifact,
  onClose,
}: {
  projectId: string;
  artifact: Artifact;
  onClose: () => void;
}) {
  const [full, setFull] = useState<Artifact>(artifact);
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    // pull fresh metadata (transcript / frames may have just finished)
    getArtifact(projectId, artifact.id).then((a) => a && setFull(a));
  }, [projectId, artifact.id]);

  const meta = full.metadata ?? {};
  const isVideo = full.kind === "video";
  const isImage = full.kind === "image";

  const seek = (t: number) => {
    if (videoRef.current) {
      videoRef.current.currentTime = t;
      videoRef.current.play().catch(() => {});
    }
  };

  const secrets = meta.possible_secrets ?? [];
  const secObs = meta.security_observations ?? [];

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-4xl max-h-[88vh] overflow-hidden flex flex-col bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl">
        {/* header */}
        <div className="flex items-center gap-2.5 px-5 h-13 py-3 border-b border-oyster-border shrink-0">
          {isVideo ? <Film size={16} className="text-oyster-accent" /> : <ImageIcon size={16} className="text-oyster-accent" />}
          <span className="text-sm font-medium text-oyster-text truncate">{full.original_filename || full.filename}</span>
          {full.status !== "ready" && full.status !== "failed" && (
            <span className="text-[11px] text-oyster-accent capitalize">· {full.status}…</span>
          )}
          <button onClick={onClose} className="ml-auto cursor-pointer text-oyster-muted hover:text-oyster-text p-1 rounded-md hover:bg-oyster-surface">
            <X size={16} />
          </button>
        </div>

        <div className="overflow-y-auto p-5 grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* LEFT: media */}
          <div className="space-y-3">
            {isImage && (
              // eslint-disable-next-line @next/next/no-img-element
              <AuthenticatedImage
                src={artifactFileUrl(projectId, full.id)}
                alt={full.filename}
                className="w-full rounded-xl border border-oyster-border bg-black/30 object-contain max-h-[52vh]"
              />
            )}
            {isVideo && (
              <AuthenticatedVideo
                ref={videoRef}
                src={artifactFileUrl(projectId, full.id)}
                controls
                className="w-full rounded-xl border border-oyster-border bg-black max-h-[52vh]"
              />
            )}

            {/* metadata card */}
            <div className="text-[12px] text-oyster-muted bg-oyster-surface/60 border border-oyster-border rounded-xl p-3 space-y-1">
              {isImage && (
                <>
                  {meta.width && <div>Dimensions: {meta.width}×{meta.height}px</div>}
                  {meta.format && <div>Format: {meta.format} · {meta.mode}</div>}
                  {meta.model && <div>Vision model: {meta.model}</div>}
                  {meta.exif && Object.keys(meta.exif).length > 0 && (
                    <div className="pt-1">
                      EXIF: {Object.entries(meta.exif).map(([k, v]) => `${k}=${v}`).join(", ")}
                    </div>
                  )}
                </>
              )}
              {isVideo && (
                <>
                  {meta.duration_seconds != null && <div>Duration: {fmt(meta.duration_seconds)}</div>}
                  {meta.resolution && <div>Resolution: {meta.resolution} · {meta.fps}fps</div>}
                  {meta.video_codec && <div>Codec: {meta.video_codec} · audio: {meta.has_audio ? "yes" : "no"}</div>}
                  {meta.model !== undefined && meta.frames && meta.frames.length > 0 && (
                    <div>Frames analyzed: {meta.frames.length}</div>
                  )}
                </>
              )}
            </div>

            {/* keyframes */}
            {isVideo && meta.frames && meta.frames.length > 0 && (
              <div>
                <div className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-1.5">Keyframes</div>
                <div className="flex gap-2 overflow-x-auto pb-1">
                  {meta.frames.map((f) => (
                    <button
                      key={f.timestamp_seconds}
                      onClick={() => seek(f.timestamp_seconds)}
                      className="shrink-0 group relative cursor-pointer"
                      title={f.description}
                    >
                      {/* eslint-disable-next-line @next/next/no-img-element */}
              <AuthenticatedImage
                        src={artifactFrameUrl(projectId, full.id, f.thumbnail_path)}
                        alt={`frame ${f.timestamp_seconds}`}
                        className="h-16 w-auto rounded-md border border-oyster-border group-hover:border-oyster-accent/60"
                      />
                      <span className="absolute bottom-0.5 right-0.5 text-[9px] bg-black/70 text-white px-1 rounded">
                        {fmt(f.timestamp_seconds)}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* RIGHT: analysis */}
          <div className="space-y-4 text-[13px] text-oyster-text">
            {full.status === "failed" && (
              <div className="flex items-start gap-2 text-red-300 bg-red-500/10 border border-red-500/30 rounded-xl p-3">
                <FileWarning size={15} className="shrink-0 mt-0.5" />
                <span>{full.error}</span>
              </div>
            )}

            {(meta.description || meta.summary) && (
              <section>
                <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-1">
                  {isVideo ? "Summary" : "Description"}
                </h3>
                <p className="text-oyster-text/90 leading-relaxed whitespace-pre-wrap">
                  {isVideo ? meta.summary || meta.description : meta.description}
                </p>
              </section>
            )}

            {secObs.length > 0 && (
              <section>
                <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <ShieldAlert size={12} className="text-amber-400" /> Security observations
                </h3>
                <ul className="list-disc pl-4 space-y-1 text-oyster-text/90">
                  {secObs.map((o, i) => <li key={i}>{o}</li>)}
                </ul>
              </section>
            )}

            {secrets.length > 0 && (
              <section>
                <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <ShieldAlert size={12} className="text-red-400" /> Possible secrets (redacted)
                </h3>
                <ul className="space-y-1 font-mono text-[11px] text-red-300/90">
                  {secrets.map((o, i) => <li key={i}>{o}</li>)}
                </ul>
              </section>
            )}

            {isImage && meta.ocr_text && (
              <section>
                <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <ScanText size={12} /> OCR text
                </h3>
                <pre className="whitespace-pre-wrap text-[11px] text-oyster-muted bg-oyster-surface/60 border border-oyster-border rounded-lg p-2 max-h-40 overflow-y-auto">{meta.ocr_text}</pre>
              </section>
            )}

            {isVideo && meta.transcript_segments && meta.transcript_segments.length > 0 && (
              <section>
                <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-1 flex items-center gap-1.5">
                  <Clock size={12} /> Transcript
                </h3>
                <div className="space-y-0.5 max-h-52 overflow-y-auto pr-1">
                  {meta.transcript_segments.map((s, i) => (
                    <button
                      key={i}
                      onClick={() => seek(s.start)}
                      className="w-full text-left flex gap-2 rounded px-1.5 py-1 hover:bg-oyster-surface transition-colors cursor-pointer"
                    >
                      <span className="text-oyster-accent font-mono text-[11px] shrink-0 tabular-nums">{fmt(s.start)}</span>
                      <span className="text-oyster-text/90 text-[12px]">{s.text}</span>
                    </button>
                  ))}
                </div>
              </section>
            )}

            {isVideo && meta.warnings && meta.warnings.length > 0 && (
              <p className="text-[11px] text-oyster-muted/80 italic">{meta.warnings.join(" · ")}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
