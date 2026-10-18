"use client";

import { useState, useEffect } from "react";
import { Shield, PanelLeftOpen, Loader2, AlertCircle, CheckCircle2 } from "lucide-react";
import { type ScopeConfig } from "@/types/chat";
import { setScope, getScope } from "@/lib/api";

const ALLOWED_TEST_OPTIONS = [
  "auth testing",
  "input validation",
  "file upload testing",
  "prompt injection testing",
  "RAG leakage testing",
  "API misconfiguration testing",
  "rate-limit testing",
];

interface ScopePanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
}

export function ScopePanel({ onToggleSidebar, sidebarOpen }: ScopePanelProps) {
  const [project, setProject] = useState("Demo Engagement");
  const [allowedTargets, setAllowedTargets] = useState(
    "http://localhost:3000\nhttp://localhost:8000\nhttps://www.google.com"
  );
  const [blockedTargets, setBlockedTargets] = useState(
    "third-party websites\nreal users\nexternal systems"
  );
  const [selectedTests, setSelectedTests] = useState<string[]>(ALLOWED_TEST_OPTIONS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [currentScope, setCurrentScope] = useState<{ scope: ScopeConfig; active: boolean } | null>(null);

  useEffect(() => {
    getScope()
      .then((data) => {
        setCurrentScope(data);
        if (data.active && data.scope.project) {
          setProject(data.scope.project);
          if (data.scope.allowed_targets?.length) {
            setAllowedTargets(data.scope.allowed_targets.join("\n"));
          }
          if (data.scope.blocked_targets?.length) {
            setBlockedTargets(data.scope.blocked_targets.join("\n"));
          }
          if (data.scope.allowed_tests?.length) {
            setSelectedTests(data.scope.allowed_tests);
          }
        }
      })
      .catch(() => {});
  }, []);

  function toggleTest(test: string) {
    setSelectedTests((prev) =>
      prev.includes(test) ? prev.filter((t) => t !== test) : [...prev, test]
    );
  }

  async function handleSave() {
    if (!project.trim()) return;
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const scope: ScopeConfig = {
        project: project.trim(),
        allowed_targets: allowedTargets
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        blocked_targets: blockedTargets
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        allowed_tests: selectedTests,
      };
      await setScope(scope);
      const data = await getScope();
      setCurrentScope(data);
      setSuccess(`Scope saved for "${project.trim()}"`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save scope");
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
        <Shield size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Scope Setup</span>
        <div className="ml-auto flex items-center gap-1.5 text-xs bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              currentScope?.active ? "bg-green-500" : "bg-yellow-500 animate-pulse"
            }`}
          />
          <span className="text-oyster-muted">
            {currentScope?.active ? `Active · ${currentScope.scope.project || "Scope Set"}` : "No active scope"}
          </span>
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-5">
          {/* Form */}
          <div className="bg-oyster-surface border border-oyster-border rounded-xl p-5 space-y-5">
            {/* Project name */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Project Name
              </label>
              <input
                type="text"
                value={project}
                onChange={(e) => setProject(e.target.value)}
                placeholder="e.g. Demo Engagement"
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors"
              />
            </div>

            {/* Allowed targets */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Allowed Targets <span className="normal-case font-normal">(one per line)</span>
              </label>
              <textarea
                value={allowedTargets}
                onChange={(e) => setAllowedTargets(e.target.value)}
                rows={4}
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50 transition-colors font-mono"
              />
              <p className="text-[11px] text-oyster-muted">
                Only these URLs will be authorized for testing
              </p>
            </div>

            {/* Blocked targets */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Blocked Targets <span className="normal-case font-normal">(one per line)</span>
              </label>
              <textarea
                value={blockedTargets}
                onChange={(e) => setBlockedTargets(e.target.value)}
                rows={3}
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50 transition-colors font-mono"
              />
            </div>

            {/* Allowed tests */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
                Allowed Test Types
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {ALLOWED_TEST_OPTIONS.map((test) => (
                  <button
                    key={test}
                    onClick={() => toggleTest(test)}
                    className={`
                      flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-left transition-all border
                      ${
                        selectedTests.includes(test)
                          ? "bg-oyster-accent/10 text-oyster-accent border-oyster-accent/30"
                          : "bg-oyster-bg text-oyster-muted border-oyster-border hover:border-oyster-border/80"
                      }
                    `}
                  >
                    <div
                      className={`w-3 h-3 rounded-sm border flex items-center justify-center shrink-0 ${
                        selectedTests.includes(test)
                          ? "bg-oyster-accent border-oyster-accent"
                          : "border-oyster-muted"
                      }`}
                    >
                      {selectedTests.includes(test) && (
                        <svg width="8" height="8" viewBox="0 0 8 8" fill="none">
                          <path d="M1 4l2 2 4-4" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      )}
                    </div>
                    {test}
                  </button>
                ))}
              </div>
            </div>

            {/* Save button */}
            <button
              onClick={handleSave}
              disabled={loading || !project.trim()}
              className={`
                w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-all
                ${
                  loading || !project.trim()
                    ? "bg-oyster-border text-oyster-muted cursor-not-allowed"
                    : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"
                }
              `}
            >
              {loading ? <Loader2 size={15} className="animate-spin" /> : <Shield size={15} />}
              {loading ? "Saving scope…" : "Save Scope"}
            </button>
          </div>

          {/* Error */}
          {error && (
            <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
              <AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" />
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          {/* Success */}
          {success && (
            <div className="flex items-start gap-3 bg-green-500/10 border border-green-500/30 rounded-xl px-4 py-3">
              <CheckCircle2 size={15} className="text-green-400 shrink-0 mt-0.5" />
              <p className="text-sm text-green-400">{success}</p>
            </div>
          )}

          {/* Active scope summary */}
          {currentScope?.active && (
            <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-3">
              <p className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">Current Active Scope</p>
              <div className="space-y-2">
                <ScopeRow label="Project" value={currentScope.scope.project || "—"} />
                <ScopeRow
                  label="Allowed Targets"
                  value={(currentScope.scope.allowed_targets ?? []).join(", ") || "—"}
                />
                <ScopeRow
                  label="Allowed Tests"
                  value={(currentScope.scope.allowed_tests ?? []).join(", ") || "all"}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScopeRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-[11px] font-medium text-oyster-muted w-28 shrink-0">{label}</span>
      <span className="text-[11px] text-oyster-text break-all">{value}</span>
    </div>
  );
}
