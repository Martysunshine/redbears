"use client";

import { useState } from "react";
import { FileText, ChevronDown, ChevronUp, BookOpen, Film, Image as ImageIcon, ExternalLink } from "lucide-react";
import { type Citation } from "@/types/chat";

function citationIcon(c: Citation) {
  if (c.knowledge_pack || c.source_type === "built_in") return BookOpen;
  if (c.artifact_type === "video") return Film;
  if (c.artifact_type === "image") return ImageIcon;
  return FileText;
}

/** Where did this passage come from? Visibly labeled per the answer-provenance
 * requirement (built-in knowledge / project / uploaded / live / tool / model). */
function sourceTypeMeta(c: Citation): { label: string; cls: string } {
  const t = c.source_type
    || (c.knowledge_pack ? "built_in" : c.artifact_type ? "uploaded" : "project");
  switch (t) {
    case "built_in": return { label: "Built-in knowledge", cls: "text-oyster-accent bg-oyster-accent/10" };
    case "uploaded": return { label: "Uploaded evidence", cls: "text-emerald-300 bg-emerald-500/10" };
    case "project": return { label: "Project source", cls: "text-sky-300 bg-sky-500/10" };
    case "live": return { label: "Live research", cls: "text-amber-300 bg-amber-500/10" };
    case "tool": return { label: "Tool output", cls: "text-purple-300 bg-purple-500/10" };
    case "model": return { label: "Model inference", cls: "text-oyster-muted bg-oyster-surface" };
    default: return { label: t, cls: "text-oyster-muted bg-oyster-surface" };
  }
}

const RISK_CLS: Record<string, string> = {
  high: "text-red-300 bg-red-500/10",
  critical: "text-red-300 bg-red-500/10",
  medium: "text-amber-300 bg-amber-500/10",
};

function fmtTs(sec: number): string {
  const s = Math.floor(sec % 60);
  const m = Math.floor(sec / 60);
  return `${m}:${`${s}`.padStart(2, "0")}`;
}

interface CitationCardProps {
  citation: Citation;
  index: number;
}

export function CitationCard({ citation, index }: CitationCardProps) {
  const [expanded, setExpanded] = useState(false);
  const pct = Math.round(citation.score * 100);
  const Icon = citationIcon(citation);
  const st = sourceTypeMeta(citation);
  const label = citation.knowledge_pack
    ? citation.source_title || citation.document
    : citation.document;
  const tsLabel = citation.artifact_type === "video" && citation.timestamp_start != null
    ? ` [${fmtTs(citation.timestamp_start)}]`
    : "";

  return (
    <div className="border border-oyster-border rounded-lg overflow-hidden bg-oyster-bg/40">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-oyster-surface/40 transition-colors text-left"
      >
        <span className="text-[10px] font-bold text-oyster-muted bg-oyster-surface px-1.5 py-0.5 rounded">
          [{index}]
        </span>
        <Icon size={12} className={`shrink-0 ${citation.knowledge_pack ? "text-oyster-accent" : "text-oyster-muted"}`} />
        <span className="flex-1 text-xs text-oyster-text truncate font-medium">
          {label}{tsLabel}
          <span className={`ml-1.5 text-[9px] uppercase tracking-wide px-1 py-0.5 rounded ${st.cls}`}>
            {st.label}
          </span>
          {citation.risk_level && RISK_CLS[citation.risk_level] && (
            <span className={`ml-1 text-[9px] uppercase tracking-wide px-1 py-0.5 rounded ${RISK_CLS[citation.risk_level]}`}>
              {citation.risk_level} risk
            </span>
          )}
        </span>
        <div className="flex items-center gap-1.5 shrink-0">
          {/* score bar */}
          <div className="w-16 h-1 bg-oyster-border rounded-full overflow-hidden">
            <div
              className="h-full bg-oyster-accent rounded-full"
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="text-[10px] text-oyster-muted w-7 text-right">{pct}%</span>
          {expanded ? (
            <ChevronUp size={12} className="text-oyster-muted" />
          ) : (
            <ChevronDown size={12} className="text-oyster-muted" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-1 border-t border-oyster-border/60">
          {/* Source inspector: exact retrieved passage + provenance */}
          <p className="text-xs text-oyster-muted leading-relaxed whitespace-pre-wrap">
            {citation.chunk}
          </p>
          {(citation.knowledge_pack || citation.publisher || citation.licence) && (
            <dl className="mt-2.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[10px]">
              {citation.knowledge_pack && (
                <><dt className="text-oyster-muted">Pack</dt>
                  <dd className="text-oyster-text">{citation.knowledge_pack}{citation.pack_version ? ` v${citation.pack_version}` : ""}</dd></>
              )}
              {citation.publisher && (
                <><dt className="text-oyster-muted">Publisher</dt><dd className="text-oyster-text">{citation.publisher}</dd></>
              )}
              {citation.section && (
                <><dt className="text-oyster-muted">Section</dt><dd className="text-oyster-text">{citation.section}</dd></>
              )}
              {citation.trust_level && (
                <><dt className="text-oyster-muted">Trust</dt><dd className="text-oyster-text">{citation.trust_level}</dd></>
              )}
              {citation.licence && (
                <><dt className="text-oyster-muted">Licence</dt><dd className="text-oyster-text/80">{citation.licence}</dd></>
              )}
            </dl>
          )}
          {citation.source_url && (
            <a
              href={citation.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-[11px] text-oyster-accent hover:underline"
            >
              <ExternalLink size={11} />
              {citation.source_title || citation.source_url}
            </a>
          )}
        </div>
      )}
    </div>
  );
}

interface CitationListProps {
  citations: Citation[];
  documentsQueried?: number;
}

export function CitationList({ citations, documentsQueried }: CitationListProps) {
  const [open, setOpen] = useState(false);
  if (!citations || citations.length === 0) return null;

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-[11px] text-oyster-muted hover:text-oyster-text transition-colors mb-1.5"
      >
        {open ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
        <span>
          {citations.length} source{citations.length !== 1 ? "s" : ""}
          {documentsQueried ? ` · ${documentsQueried} doc${documentsQueried !== 1 ? "s" : ""}` : ""}
        </span>
      </button>
      {open && (
        <div className="space-y-1.5">
          {citations.map((c, i) => (
            <CitationCard key={i} citation={c} index={i + 1} />
          ))}
        </div>
      )}
    </div>
  );
}
