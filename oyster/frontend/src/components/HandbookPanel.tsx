"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { BookOpen, X, Search, ChevronDown, Info, AlertTriangle, ShieldAlert, Copy, Check } from "lucide-react";
import {
  HANDBOOK,
  GLOSSARY,
  type HandbookArticle,
  type HandbookBlock,
  type HandbookContext,
  type HandbookSection,
} from "@/data/handbook";

interface HandbookPanelProps {
  open: boolean;
  /** The active workspace context — decides which section opens first. */
  context: HandbookContext;
  onClose: () => void;
}

const GLOSSARY_SECTION_ID = "troubleshooting";

function articleText(a: HandbookArticle): string {
  const parts: string[] = [a.title];
  for (const b of a.body) {
    if (b.type === "p" || b.type === "h" || b.type === "callout") parts.push(b.text);
    else if (b.type === "ul" || b.type === "steps" || b.type === "prompts") parts.push(...b.items);
  }
  return parts.join(" ").toLowerCase();
}

/** Which section should open first for a given context. */
function sectionForContext(ctx: HandbookContext): string {
  if (ctx === "redteam") return "red-team";
  if (ctx === "blueteam") return "blue-team";
  if (ctx === "rag" || ctx === "intel") return "rag-knowledge";
  return "getting-started";
}

export function HandbookPanel({ open, context, onClose }: HandbookPanelProps) {
  const [query, setQuery] = useState("");
  const [activeSectionId, setActiveSectionId] = useState<string>(sectionForContext(context));
  const [openArticles, setOpenArticles] = useState<Record<string, boolean>>({});
  const panelRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);

  // On open: jump to the context's section, expand its context-matching
  // articles, clear any stale search, remember what to refocus on close, and
  // move focus into the panel.
  useEffect(() => {
    if (!open) return;
    restoreFocusRef.current = (document.activeElement as HTMLElement) ?? null;
    const sectionId = sectionForContext(context);
    setActiveSectionId(sectionId);
    setQuery("");
    const section = HANDBOOK.find((s) => s.id === sectionId);
    const expanded: Record<string, boolean> = {};
    section?.articles.forEach((a) => {
      if (a.context.includes(context)) expanded[a.id] = true;
    });
    // Nothing context-specific? Open the first article so the panel isn't blank.
    if (Object.keys(expanded).length === 0 && section?.articles[0]) expanded[section.articles[0].id] = true;
    setOpenArticles(expanded);
    const t = setTimeout(() => searchRef.current?.focus(), 40);
    return () => clearTimeout(t);
  }, [open, context]);

  // Escape to close + a lightweight focus trap (Tab cycles within the panel).
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panelRef.current) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  // Restore focus to the trigger when the panel closes.
  useEffect(() => {
    if (open) return;
    restoreFocusRef.current?.focus?.();
  }, [open]);

  const q = query.trim().toLowerCase();

  const searchResults = useMemo(() => {
    if (!q) return null;
    const articles: { section: HandbookSection; article: HandbookArticle }[] = [];
    for (const section of HANDBOOK) {
      for (const article of section.articles) {
        if (articleText(article).includes(q)) articles.push({ section, article });
      }
    }
    const glossary = GLOSSARY.filter(
      (g) => g.term.toLowerCase().includes(q) || g.def.toLowerCase().includes(q)
    );
    return { articles, glossary };
  }, [q]);

  if (!open) return null;

  const activeSection = HANDBOOK.find((s) => s.id === activeSectionId) ?? HANDBOOK[0];
  const toggleArticle = (id: string) => setOpenArticles((prev) => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="fixed inset-0 z-[75] flex justify-end" role="dialog" aria-modal="true" aria-labelledby="handbook-title">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[1px]" onClick={onClose} />
      <div
        ref={panelRef}
        className="relative h-full w-full sm:w-[460px] max-w-full bg-oyster-sidebar border-l border-oyster-border shadow-2xl flex flex-col animate-[slideInRight_0.18s_ease-out]"
      >
        {/* Header */}
        <div className="shrink-0 px-4 pt-4 pb-3 border-b border-oyster-border">
          <div className="flex items-center gap-2.5">
            <span className="w-8 h-8 rounded-lg bg-oyster-accent/15 text-oyster-accent flex items-center justify-center shrink-0">
              <BookOpen size={16} />
            </span>
            <div className="flex-1 min-w-0">
              <h2 id="handbook-title" className="text-[15px] font-semibold text-oyster-text leading-tight">
                Company Handbook
              </h2>
              <p className="text-[11px] text-oyster-muted leading-tight">How to get the most out of Oyster</p>
            </div>
            <button
              onClick={onClose}
              aria-label="Close handbook"
              title="Close (Esc)"
              className="cursor-pointer p-1.5 rounded-md text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface transition-colors outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60"
            >
              <X size={17} />
            </button>
          </div>

          {/* Search */}
          <div className="mt-3 relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-oyster-muted pointer-events-none" />
            <input
              ref={searchRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search the handbook…"
              aria-label="Search the handbook"
              className="w-full bg-oyster-surface border border-oyster-border rounded-lg pl-8 pr-8 py-2 text-[13px] text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors"
            />
            {query && (
              <button
                onClick={() => { setQuery(""); searchRef.current?.focus(); }}
                aria-label="Clear search"
                className="cursor-pointer absolute right-2 top-1/2 -translate-y-1/2 p-0.5 rounded text-oyster-muted hover:text-oyster-text"
              >
                <X size={13} />
              </button>
            )}
          </div>

          {/* Section tabs (hidden while searching) */}
          {!q && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {HANDBOOK.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setActiveSectionId(s.id)}
                  className={`cursor-pointer px-2.5 py-1 rounded-full text-[11px] font-medium border transition-colors ${
                    s.id === activeSectionId
                      ? "bg-oyster-accent/15 text-oyster-accent border-oyster-accent/40"
                      : "text-oyster-muted border-oyster-border hover:text-oyster-text hover:bg-oyster-surface/60"
                  }`}
                >
                  {s.title}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-4 py-4">
          {q && searchResults ? (
            <SearchView results={searchResults} onOpenArticle={(sid, aid) => { setQuery(""); setActiveSectionId(sid); setOpenArticles({ [aid]: true }); }} />
          ) : (
            <>
              <div className="space-y-2">
                {activeSection.articles.map((a) => (
                  <ArticleAccordion
                    key={a.id}
                    article={a}
                    open={!!openArticles[a.id]}
                    onToggle={() => toggleArticle(a.id)}
                  />
                ))}
              </div>
              {activeSection.id === GLOSSARY_SECTION_ID && <Glossary />}
            </>
          )}
        </div>

        <div className="shrink-0 px-4 py-2.5 border-t border-oyster-border text-[10px] text-oyster-muted/80 text-center">
          Oyster only assists with systems you own or are authorized to assess.
        </div>
      </div>
    </div>
  );
}

function ArticleAccordion({ article, open, onToggle }: { article: HandbookArticle; open: boolean; onToggle: () => void }) {
  return (
    <div className="border border-oyster-border rounded-xl overflow-hidden bg-oyster-surface/40">
      <button
        onClick={onToggle}
        aria-expanded={open}
        className="cursor-pointer w-full flex items-center gap-2 px-3.5 py-2.5 text-left hover:bg-oyster-surface/60 transition-colors outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/50"
      >
        <span className="flex-1 text-[13px] font-medium text-oyster-text">{article.title}</span>
        <ChevronDown size={15} className={`shrink-0 text-oyster-muted transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="px-3.5 pb-3.5 pt-0.5 space-y-2.5">
          {article.body.map((b, i) => (
            <Block key={i} block={b} />
          ))}
        </div>
      )}
    </div>
  );
}

function Block({ block }: { block: HandbookBlock }) {
  switch (block.type) {
    case "p":
      return <p className="text-[13px] text-oyster-muted leading-relaxed">{block.text}</p>;
    case "h":
      return <p className="text-[11px] font-semibold text-oyster-text uppercase tracking-wide pt-1">{block.text}</p>;
    case "ul":
      return (
        <ul className="space-y-1.5">
          {block.items.map((it, i) => (
            <li key={i} className="text-[13px] text-oyster-muted leading-relaxed flex gap-2">
              <span className="text-oyster-accent shrink-0 mt-1.5 w-1 h-1 rounded-full bg-oyster-accent" />
              <span>{it}</span>
            </li>
          ))}
        </ul>
      );
    case "steps":
      return (
        <ol className="space-y-1.5">
          {block.items.map((it, i) => (
            <li key={i} className="text-[13px] text-oyster-muted leading-relaxed flex gap-2.5">
              <span className="shrink-0 w-4 h-4 rounded-full bg-oyster-accent/15 text-oyster-accent text-[10px] font-bold flex items-center justify-center mt-0.5">{i + 1}</span>
              <span>{it}</span>
            </li>
          ))}
        </ol>
      );
    case "callout":
      return <Callout tone={block.tone} text={block.text} />;
    case "prompts":
      return (
        <div className="space-y-1.5">
          {block.items.map((it, i) => (
            <PromptRow key={i} text={it} />
          ))}
        </div>
      );
  }
}

function Callout({ tone, text }: { tone: "info" | "warn" | "safety"; text: string }) {
  const styles = {
    info: { wrap: "bg-oyster-accent/10 border-oyster-accent/30", icon: Info, color: "text-oyster-accent" },
    warn: { wrap: "bg-amber-500/10 border-amber-500/30", icon: AlertTriangle, color: "text-amber-400" },
    safety: { wrap: "bg-red-500/10 border-red-500/30", icon: ShieldAlert, color: "text-red-400" },
  }[tone];
  const Icon = styles.icon;
  return (
    <div className={`flex gap-2.5 rounded-lg border px-3 py-2.5 ${styles.wrap}`}>
      <Icon size={15} className={`shrink-0 mt-0.5 ${styles.color}`} />
      <p className="text-[12.5px] text-oyster-text/90 leading-relaxed">{text}</p>
    </div>
  );
}

function PromptRow({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="group flex items-start gap-2 rounded-lg border border-oyster-border bg-oyster-bg/50 px-3 py-2">
      <p className="flex-1 text-[12.5px] text-oyster-muted leading-relaxed">&ldquo;{text}&rdquo;</p>
      <button
        onClick={copy}
        title={copied ? "Copied" : "Copy prompt"}
        aria-label="Copy prompt"
        className="cursor-pointer shrink-0 p-1 rounded text-oyster-muted hover:text-oyster-accent transition-colors"
      >
        {copied ? <Check size={13} className="text-oyster-accent" /> : <Copy size={13} />}
      </button>
    </div>
  );
}

function Glossary() {
  return (
    <div className="mt-4 pt-4 border-t border-oyster-border">
      <p className="text-[11px] font-semibold text-oyster-text uppercase tracking-wide mb-2.5">Glossary</p>
      <dl className="space-y-2.5">
        {GLOSSARY.map((g) => (
          <div key={g.term}>
            <dt className="text-[12.5px] font-medium text-oyster-text">{g.term}</dt>
            <dd className="text-[12.5px] text-oyster-muted leading-relaxed">{g.def}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function SearchView({
  results,
  onOpenArticle,
}: {
  results: { articles: { section: HandbookSection; article: HandbookArticle }[]; glossary: typeof GLOSSARY };
  onOpenArticle: (sectionId: string, articleId: string) => void;
}) {
  const empty = results.articles.length === 0 && results.glossary.length === 0;
  if (empty) {
    return <p className="text-[13px] text-oyster-muted text-center py-8">No results. Try a different word.</p>;
  }
  return (
    <div className="space-y-2">
      {results.articles.map(({ section, article }) => (
        <button
          key={article.id}
          onClick={() => onOpenArticle(section.id, article.id)}
          className="cursor-pointer w-full text-left border border-oyster-border rounded-xl px-3.5 py-2.5 hover:border-oyster-accent/40 hover:bg-oyster-surface/60 transition-colors outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/50"
        >
          <p className="text-[10px] text-oyster-muted uppercase tracking-wide">{section.title}</p>
          <p className="text-[13px] font-medium text-oyster-text">{article.title}</p>
        </button>
      ))}
      {results.glossary.length > 0 && (
        <div className="pt-2">
          <p className="text-[11px] font-semibold text-oyster-text uppercase tracking-wide mb-2">Glossary matches</p>
          <dl className="space-y-2">
            {results.glossary.map((g) => (
              <div key={g.term} className="border border-oyster-border rounded-lg px-3 py-2">
                <dt className="text-[12.5px] font-medium text-oyster-text">{g.term}</dt>
                <dd className="text-[12.5px] text-oyster-muted leading-relaxed">{g.def}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
