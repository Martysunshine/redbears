"use client";

import { useState } from "react";
import { ClipboardList, PanelLeftOpen, Loader2, AlertCircle } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { MODELS, generateTestPlan } from "@/lib/api";
import { type Citation } from "@/types/chat";
import { CitationList } from "./CitationCard";

interface TestPlannerPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  selectedModel: string;
}

const OBJECTIVE_PRESETS = [
  "Find broken authentication and session issues",
  "Test input validation and injection vulnerabilities",
  "Check file upload abuse and path traversal",
  "Audit prompt injection and RAG data leakage",
  "Test API misconfiguration and exposed secrets",
  "Check rate limiting and abuse prevention",
];

export function TestPlannerPanel({ onToggleSidebar, sidebarOpen, selectedModel }: TestPlannerPanelProps) {
  const [target, setTarget] = useState("http://localhost:3000");
  const [objective, setObjective] = useState("");
  const [model, setModel] = useState("deepseek-r1");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    target: string;
    plan: string;
    citations: Citation[];
  } | null>(null);

  async function handleGenerate() {
    if (!target.trim() || !objective.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await generateTestPlan(target.trim(), objective.trim(), model);
      setResult({ target: data.target, plan: data.plan, citations: (data as { citations?: Citation[] }).citations ?? [] });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test plan generation failed");
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
        <ClipboardList size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Test Planner</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          scope-gated · safe test cases
        </span>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          {MODELS.find((m) => m.key === model)?.label ?? model}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-5">
          <div className="bg-oyster-surface border border-oyster-border rounded-xl p-5 space-y-4">
            {/* Target */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Target
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="http://localhost:3000"
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors font-mono"
              />
            </div>

            {/* Objective presets */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Objective
              </label>
              <div className="flex flex-wrap gap-1.5 mb-2">
                {OBJECTIVE_PRESETS.map((p) => (
                  <button
                    key={p}
                    onClick={() => setObjective(p)}
                    className={`text-[11px] px-2.5 py-1 rounded-full border transition-all ${
                      objective === p
                        ? "bg-oyster-accent/15 text-oyster-accent border-oyster-accent/30"
                        : "bg-oyster-bg text-oyster-muted border-oyster-border hover:text-oyster-text"
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
              <textarea
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                placeholder="Describe what you want to test…"
                rows={2}
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50 transition-colors"
              />
            </div>

            {/* Model */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Model
              </label>
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text outline-none focus:border-oyster-accent/50 transition-colors"
              >
                {MODELS.map((m) => (
                  <option key={m.key} value={m.key}>
                    {m.label} — {m.description}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={handleGenerate}
              disabled={!target.trim() || !objective.trim() || loading}
              className={`
                w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all
                ${
                  !target.trim() || !objective.trim() || loading
                    ? "bg-oyster-border text-oyster-muted cursor-not-allowed"
                    : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"
                }
              `}
            >
              {loading ? (
                <><Loader2 size={15} className="animate-spin" /> Generating test plan…</>
              ) : (
                <><ClipboardList size={15} /> Generate Test Plan</>
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
                <ClipboardList size={14} className="text-oyster-accent" />
                <span className="text-sm font-medium text-oyster-text">
                  Test Plan · {result.target}
                </span>
              </div>
              <div className="bg-oyster-surface border border-oyster-border rounded-xl px-5 py-4">
                <div className="prose prose-sm">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{result.plan}</ReactMarkdown>
                </div>
                {result.citations.length > 0 && (
                  <CitationList citations={result.citations} documentsQueried={result.citations.length} />
                )}
              </div>
            </div>
          )}

          {!result && !loading && !error && (
            <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
              <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
                <ClipboardList size={20} className="text-oyster-muted" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-oyster-text">Generate a scoped test plan</p>
                <p className="text-xs text-oyster-muted max-w-xs">
                  Pick a target and objective. The AI generates a structured checklist of safe test cases within your authorized scope.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
