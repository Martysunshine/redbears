"use client";

import { useState } from "react";
import { Wrench, PanelLeftOpen, Loader2, AlertCircle } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { MODELS, getFixAdvice } from "@/lib/api";

interface FixAdvisorPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  selectedModel: string;
}

const COMMON_ISSUES: { title: string; endpoint: string; description: string }[] = [
  {
    title: "Unrestricted file upload",
    endpoint: "POST /documents/upload",
    description: "Server accepts any file type. Attacker can upload executable files or oversized payloads.",
  },
  {
    title: "Prompt injection via user input",
    endpoint: "POST /chat",
    description: "User input is passed directly to the LLM without sanitization. Attacker can override system prompt.",
  },
  {
    title: "RAG context leakage",
    endpoint: "POST /rag/chat",
    description: "Documents from the knowledge base are returned verbatim in citations, exposing sensitive internal content.",
  },
  {
    title: "Missing rate limiting on chat endpoint",
    endpoint: "POST /chat",
    description: "No rate limiting on the chat endpoint allows an attacker to exhaust Ollama compute resources.",
  },
  {
    title: "CORS misconfiguration",
    endpoint: "ALL endpoints",
    description: "CORS allows all origins or overly broad wildcard, allowing cross-origin requests from attacker sites.",
  },
];

export function FixAdvisorPanel({ onToggleSidebar, sidebarOpen, selectedModel }: FixAdvisorPanelProps) {
  const [title, setTitle] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [description, setDescription] = useState("");
  const [steps, setSteps] = useState("");
  const [stack, setStack] = useState("FastAPI + Next.js (Oyster)");
  const [model, setModel] = useState("deepseek-r1");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ title: string; advice: string } | null>(null);

  function fillPreset(preset: (typeof COMMON_ISSUES)[0]) {
    setTitle(preset.title);
    setEndpoint(preset.endpoint);
    setDescription(preset.description);
  }

  async function handleGetFix() {
    if (!title.trim() || !endpoint.trim() || !description.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await getFixAdvice(
        title.trim(),
        endpoint.trim(),
        description.trim(),
        steps.trim(),
        stack.trim(),
        model
      );
      setResult({ title: data.title, advice: data.advice });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Fix advisor failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button
            onClick={onToggleSidebar}
            className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface"
          >
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Wrench size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Fix Advisor</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          remediation guidance
        </span>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          {MODELS.find((m) => m.key === model)?.label ?? model}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-5">
          <div className="bg-oyster-surface border border-oyster-border rounded-xl p-5 space-y-4">
            {/* Quick presets */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Common Issues
              </label>
              <div className="flex flex-wrap gap-1.5">
                {COMMON_ISSUES.map((p) => (
                  <button
                    key={p.title}
                    onClick={() => fillPreset(p)}
                    className={`text-[11px] px-2.5 py-1 rounded-full border transition-all ${
                      title === p.title
                        ? "bg-oyster-accent/15 text-oyster-accent border-oyster-accent/30"
                        : "bg-oyster-bg text-oyster-muted border-oyster-border hover:text-oyster-text"
                    }`}
                  >
                    {p.title}
                  </button>
                ))}
              </div>
            </div>

            {/* Vulnerability title */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Vulnerability Title
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Unrestricted file upload"
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors"
              />
            </div>

            {/* Affected endpoint */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Affected Endpoint
              </label>
              <input
                type="text"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="e.g. POST /documents/upload"
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors font-mono"
              />
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Description
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Describe the vulnerability — what is wrong, what is the impact…"
                rows={3}
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50 transition-colors"
              />
            </div>

            {/* Steps */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Steps to Reproduce <span className="normal-case font-normal">(optional)</span>
              </label>
              <textarea
                value={steps}
                onChange={(e) => setSteps(e.target.value)}
                placeholder="Paste curl commands, request/response, or manual steps…"
                rows={3}
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50 transition-colors font-mono"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              {/* Stack */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">Stack</label>
                <input
                  type="text"
                  value={stack}
                  onChange={(e) => setStack(e.target.value)}
                  className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50 transition-colors"
                />
              </div>
              {/* Model */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">Model</label>
                <select
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50 transition-colors"
                >
                  {MODELS.map((m) => (
                    <option key={m.key} value={m.key}>
                      {m.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <button
              onClick={handleGetFix}
              disabled={!title.trim() || !endpoint.trim() || !description.trim() || loading}
              className={`
                w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all
                ${
                  !title.trim() || !endpoint.trim() || !description.trim() || loading
                    ? "bg-oyster-border text-oyster-muted cursor-not-allowed"
                    : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"
                }
              `}
            >
              {loading ? (
                <><Loader2 size={15} className="animate-spin" /> Generating fix advice…</>
              ) : (
                <><Wrench size={15} /> Get Fix Advice</>
              )}
            </button>
          </div>

          {error && (
            <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
              <AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" />
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          {result && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Wrench size={14} className="text-oyster-accent" />
                <span className="text-sm font-medium text-oyster-text">Fix Advice · {result.title}</span>
              </div>
              <div className="bg-oyster-surface border border-oyster-border rounded-xl px-5 py-4">
                <div className="prose prose-sm">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{result.advice}</ReactMarkdown>
                </div>
              </div>
            </div>
          )}

          {!result && !loading && !error && (
            <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
              <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
                <Wrench size={20} className="text-oyster-muted" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-oyster-text">Get remediation advice</p>
                <p className="text-xs text-oyster-muted max-w-xs">
                  Describe a vulnerability. The AI provides root cause analysis, immediate mitigation, proper fix with code examples, and verification steps.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
