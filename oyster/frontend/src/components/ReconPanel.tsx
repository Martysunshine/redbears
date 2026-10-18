"use client";

import { useState } from "react";
import { Map, PanelLeftOpen, Loader2, AlertCircle } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { MODELS } from "@/lib/api";
import { runRecon } from "@/lib/api";

interface ReconPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  selectedModel: string;
}

export function ReconPanel({ onToggleSidebar, sidebarOpen, selectedModel }: ReconPanelProps) {
  const [target, setTarget] = useState("http://localhost:3000");
  const [description, setDescription] = useState("");
  const [model, setModel] = useState("deepseek-r1");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ target: string; recon: string } | null>(null);

  async function handleRecon() {
    if (!target.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await runRecon(target.trim(), description.trim(), model);
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Recon failed");
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
        <Map size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Recon Assistant</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          attack surface mapping
        </span>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
          {MODELS.find((m) => m.key === model)?.label ?? model}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-5">
          <div className="bg-oyster-surface border border-oyster-border rounded-xl p-5 space-y-4">
            {/* Target URL */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Target URL
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="http://localhost:3000"
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors font-mono"
              />
            </div>

            {/* Description */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                App Description <span className="normal-case font-normal">(optional)</span>
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g. Next.js 14 frontend with FastAPI backend, user auth, file upload, RAG chat…"
                rows={3}
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
              onClick={handleRecon}
              disabled={!target.trim() || loading}
              className={`
                w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all
                ${
                  !target.trim() || loading
                    ? "bg-oyster-border text-oyster-muted cursor-not-allowed"
                    : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"
                }
              `}
            >
              {loading ? (
                <><Loader2 size={15} className="animate-spin" /> Mapping attack surface…</>
              ) : (
                <><Map size={15} /> Run Recon</>
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
                <Map size={14} className="text-oyster-accent" />
                <span className="text-sm font-medium text-oyster-text">
                  Attack Surface Map · {result.target}
                </span>
              </div>
              <div className="bg-oyster-surface border border-oyster-border rounded-xl px-5 py-4">
                <div className="prose prose-sm">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{result.recon}</ReactMarkdown>
                </div>
              </div>
            </div>
          )}

          {!result && !loading && !error && (
            <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
              <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
                <Map size={20} className="text-oyster-muted" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-medium text-oyster-text">Map your attack surface</p>
                <p className="text-xs text-oyster-muted max-w-xs">
                  Enter a target URL and optionally describe the app stack. The AI will map pages, APIs, forms, auth flows, and high-interest areas.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
