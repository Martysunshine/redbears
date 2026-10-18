"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { PanelLeftOpen, Layers, Loader2, AlertTriangle, CheckCircle2, Square, ArrowUp } from "lucide-react";
import {
  askKnowledgeStream,
  UI_MODELS,
  UI_MODEL_KEYS,
  type KnowledgeStreamFrame,
  type RankedCitation,
  type RerankInfo,
} from "@/lib/api";
import { CitationCard } from "@/components/CitationCard";
import { InvestigationWorkflow } from "@/components/InvestigationWorkflow";

interface RedBearsPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  selectedModel: string;
  onModelChange: (model: string) => void;
  /** The full Oyster chat experience (streaming, history, citations, model
   *  selector) — built by page.tsx, which owns the conversation state this
   *  needs. Rendered here, filling the Chat tab, so Chat/Ask/Investigate stay
   *  one switcher inside Red Bears rather than three separate surfaces. */
  chatPane?: React.ReactNode;
  chatRequest?: number;
}

const EXAMPLES = [
  "How does Kerberoasting work and how do I detect it?",
  "What is the CVE identifier of the Log4Shell vulnerability?",
  "How do I mitigate CWE-89 SQL injection?",
];

function RerankBadge({ info, requested }: { info: RerankInfo | null; requested: boolean }) {
  if (!requested) {
    return (
      <span className="text-[11px] px-2 py-1 rounded-md border border-oyster-border bg-oyster-surface text-oyster-muted">
        Nemotron reranking: off
      </span>
    );
  }
  if (!info) {
    return (
      <span className="text-[11px] px-2 py-1 rounded-md border border-oyster-border bg-oyster-surface text-oyster-muted">
        Nemotron reranking: waiting
      </span>
    );
  }
  const where = info.endpoint === "local" ? "local" : info.endpoint === "nvidia-hosted" ? "NVIDIA-hosted" : "remote";
  if (info.status === "ran") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md border border-green-500/20 bg-green-500/10 text-green-400">
        <CheckCircle2 size={12} />
        Nemotron reranked {info.candidates} → {info.returned} · {where} · {info.latency_ms} ms
        {info.order_changed ? " · order changed" : " · order unchanged"}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md border border-amber-500/20 bg-amber-500/10 text-amber-300">
      <AlertTriangle size={12} />
      {info.status === "disabled" ? "Reranking disabled" : "Reranking did not run — using existing retrieval order"}
      {info.reason ? ` (${info.reason})` : ""}
    </span>
  );
}

export function RedBearsPanel({ onToggleSidebar, sidebarOpen, selectedModel, onModelChange, chatPane, chatRequest = 0 }: RedBearsPanelProps) {
  const [tab, setTab] = useState<"chat" | "ask" | "investigate">("chat");
  useEffect(() => { setTab("chat"); }, [chatRequest]);
  // One shared model choice (Oyster | Huihui) for the whole app.
  const models = UI_MODELS;
  const model = UI_MODEL_KEYS.includes(selectedModel) ? selectedModel : UI_MODEL_KEYS[0];
  const [rerank, setRerank] = useState(true);
  const [question, setQuestion] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [answer, setAnswer] = useState("");
  const [finalAnswer, setFinalAnswer] = useState<string | null>(null);
  const [citations, setCitations] = useState<RankedCitation[]>([]);
  const [info, setInfo] = useState<RerankInfo | null>(null);
  const [ranWithRerank, setRanWithRerank] = useState(false);
  const [timing, setTiming] = useState<{ retrieval?: number; ttft?: number | null; total?: number }>({});
  const [flags, setFlags] = useState<string[]>([]);
  const [ranModel, setRanModel] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);

  const ask = useCallback(async (q: string) => {
    if (!q.trim() || running) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setRunning(true);
    setError(null);
    setAnswer("");
    setFinalAnswer(null);
    setCitations([]);
    setInfo(null);
    setFlags([]);
    setTiming({});
    setRanWithRerank(rerank);
    setRanModel(model);
    try {
      await askKnowledgeStream(q.trim(), model, rerank, (f: KnowledgeStreamFrame) => {
        if (f.type === "meta") {
          setCitations(f.citations);
          setInfo(f.rerank);
          setTiming((t) => ({ ...t, retrieval: f.retrieval_ms }));
        } else if (f.type === "token") {
          setAnswer((a) => a + f.text);
        } else if (f.type === "done") {
          setFinalAnswer(f.answer);
          setFlags(f.quality_flags);
          setTiming((t) => ({ ...t, ttft: f.ttft_ms, total: f.total_ms }));
        } else if (f.type === "error") {
          setError(f.detail);
        }
      }, ac.signal);
    } catch (e) {
      if (!ac.signal.aborted) setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setRunning(false);
    }
  }, [model, rerank, running]);

  const shown = finalAnswer ?? answer;
  const modelLabel = (k: string | null) => UI_MODELS.find((m) => m.key === k)?.label ?? k;
  const sec = (ms?: number | null) => (ms == null ? "–" : `${(ms / 1000).toFixed(1)}s`);

  const tabSwitcher = (
    <div role="tablist" aria-label="Red Bears view" className="ml-auto flex items-center gap-1 bg-oyster-surface border border-oyster-border rounded-lg p-0.5">
      <button role="tab" aria-selected={tab === "chat"} aria-label="Switch to Chat view" onClick={() => setTab("chat")}
              className={`text-xs px-3 py-1 rounded-md transition-colors ${tab === "chat" ? "bg-oyster-accent text-white" : "text-oyster-muted hover:text-oyster-text"}`}>
        Chat
      </button>
      <button role="tab" aria-selected={tab === "ask"} aria-label="Switch to Ask view" onClick={() => setTab("ask")}
              className={`text-xs px-3 py-1 rounded-md transition-colors ${tab === "ask" ? "bg-oyster-accent text-white" : "text-oyster-muted hover:text-oyster-text"}`}>
        Ask
      </button>
      <button role="tab" aria-selected={tab === "investigate"} aria-label="Switch to Investigate view" onClick={() => setTab("investigate")}
              className={`text-xs px-3 py-1 rounded-md transition-colors ${tab === "investigate" ? "bg-oyster-accent text-white" : "text-oyster-muted hover:text-oyster-text"}`}>
        Investigate
      </button>
    </div>
  );

  if (tab === "chat") {
    // ChatWindow is a full, self-contained panel (its own header, scroll
    // region and composer — see components/ChatWindow.tsx) built and owned by
    // page.tsx, which holds the conversation state it needs. It is rendered
    // directly here rather than nested inside the Ask/Investigate padded
    // wrapper below, so streaming/history/citations behave exactly as they do
    // for an anonymous visitor's plain Chat view. A slim strip carries the
    // Chat/Ask/Investigate switcher above it.
    return (
      <div className="flex flex-col flex-1 min-w-0 h-app">
        <div className="flex items-center gap-3 px-4 py-1.5 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
          <Layers size={13} className="text-oyster-muted shrink-0" />
          <span className="text-xs font-medium text-oyster-muted">Red Bears</span>
          {tabSwitcher}
        </div>
        <div className="flex-1 min-h-0 flex overflow-hidden">
          {chatPane ?? (
            <div className="flex-1 flex items-center justify-center text-sm text-oyster-muted">
              Chat is unavailable right now.
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button
            onClick={onToggleSidebar}
            aria-label="Open sidebar"
            className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface"
          >
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Layers size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Red Bears</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1 hidden sm:inline-block">
          retrieve → Nemotron rerank → answer with citations
        </span>
        {tabSwitcher}
      </header>

      {tab === "investigate" ? (
        <div className="flex-1 overflow-y-auto px-4 py-6">
          <InvestigationWorkflow />
        </div>
      ) : (
      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-5">
          <form
            onSubmit={(e) => { e.preventDefault(); void ask(question); }}
            className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-3"
          >
            <label htmlFor="rb-q" className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
              Ask a security question
            </label>
            <textarea
              id="rb-q"
              rows={2}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void ask(question); } }}
              placeholder="e.g. How does Kerberoasting work and how do I detect it?"
              className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors resize-none"
            />
            <div className="flex flex-col sm:flex-row sm:items-center gap-3">
              <select
                aria-label="Answer model"
                value={model}
                onChange={(e) => onModelChange(e.target.value)}
                disabled={running}
                className="bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50"
              >
                {models.map((m) => (
                  <option key={m.key} value={m.key}>{m.label}</option>
                ))}
              </select>
              <label className="flex items-center gap-2 text-sm text-oyster-text select-none cursor-pointer">
                <input type="checkbox" checked={rerank} onChange={(e) => setRerank(e.target.checked)} disabled={running} />
                Rerank evidence with Nemotron (reranker only)
              </label>
              <div className="sm:ml-auto flex items-center gap-2">
                {running ? (
                  <button
                    type="button"
                    onClick={() => abortRef.current?.abort()}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-oyster-border text-oyster-text"
                  >
                    <Square size={13} /> Stop
                  </button>
                ) : (
                  <button
                    type="submit"
                    disabled={!question.trim()}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                      !question.trim()
                        ? "bg-oyster-border text-oyster-muted cursor-not-allowed"
                        : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"
                    }`}
                  >
                    <ArrowUp size={14} /> Ask
                  </button>
                )}
              </div>
            </div>
            <p className="text-[11px] text-oyster-muted">
              {UI_MODELS.find((m) => m.key === model)?.description}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex}
                  type="button"
                  onClick={() => setQuestion(ex)}
                  className="text-[11px] text-oyster-muted hover:text-oyster-text border border-oyster-border rounded-md px-2 py-1 transition-colors"
                >
                  {ex}
                </button>
              ))}
            </div>
          </form>

          {error && (
            <div role="alert" className="flex items-start gap-2 text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              <AlertTriangle size={15} className="mt-0.5 shrink-0" /> <span>{error}</span>
            </div>
          )}

          {(running || shown || citations.length > 0) && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <RerankBadge info={info} requested={ranWithRerank} />
                <span className="text-[11px] text-oyster-muted">
                  {modelLabel(ranModel)} · retrieval {sec(timing.retrieval)} · first token {sec(timing.ttft)} · total {sec(timing.total)}
                </span>
                {running && <Loader2 size={13} className="animate-spin text-oyster-muted" />}
              </div>

              <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4">
                <p className="text-sm text-oyster-text leading-relaxed whitespace-pre-wrap">
                  {shown || (running ? "Retrieving evidence…" : "")}
                </p>
                {flags.length > 0 && (
                  <p className="mt-2 text-[11px] text-oyster-muted">Output checks: {flags.join(", ")}</p>
                )}
              </div>

              {citations.length > 0 && (
                <div className="space-y-1.5">
                  <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                    Sources ({citations.length}) — numbers match [n] in the answer
                  </h3>
                  {citations.map((c, i) => (
                    <div key={c.chunk_id ?? i}>
                      <CitationCard citation={c} index={c.n ?? i + 1} />
                      {c.rerank_score != null && (
                        <p className="text-[10px] text-oyster-muted px-3 pt-0.5">
                          Nemotron logit {c.rerank_score.toFixed(2)} · retrieval rank {c.retrieval_rank} → {c.n ?? i + 1}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      )}
    </div>
  );
}
