"use client";

import { useEffect, useState } from "react";
import { X, BookOpen, Check, Download, Loader2, RefreshCw, Trash2, Power, ExternalLink, ShieldAlert, AlertCircle } from "lucide-react";
import {
  type KnowledgePack,
  type KnowledgePublicMetrics,
  listKnowledgePacks,
  getKnowledgePublicMetrics,
  installKnowledgePack,
  uninstallKnowledgePack,
  setKnowledgePackEnabled,
} from "@/lib/api";

const DOMAIN_COLOR: Record<string, string> = {
  offensive: "text-red-300 bg-red-500/10 border-red-500/20",
  defensive: "text-sky-300 bg-sky-500/10 border-sky-500/20",
  "offensive-defensive": "text-purple-300 bg-purple-500/10 border-purple-500/20",
  governance: "text-amber-300 bg-amber-500/10 border-amber-500/20",
};

const RISK_COLOR: Record<string, string> = {
  high: "text-red-300 bg-red-500/10 border-red-500/20",
  critical: "text-red-300 bg-red-500/10 border-red-500/20",
  medium: "text-amber-300 bg-amber-500/10 border-amber-500/20",
};

export function KnowledgePacksModal({ onClose, onChanged }: { onClose: () => void; onChanged?: () => void }) {
  const [packs, setPacks] = useState<KnowledgePack[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [installedCount, setInstalledCount] = useState(0);
  const [enabledCount, setEnabledCount] = useState(0);
  const [metrics, setMetrics] = useState<KnowledgePublicMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const d = await listKnowledgePacks();
      setPacks(d.packs);
      setInstalledCount(d.installed);
      setEnabledCount(d.enabled ?? d.installed);
      setError(null);
    } catch {
      setError("Could not reach the backend. Is it running on :8001?");
    } finally {
      setLoading(false);
    }
    // Verified chunk-count headline — read from the active store, never hard-coded.
    getKnowledgePublicMetrics().then(setMetrics).catch(() => setMetrics(null));
  };

  useEffect(() => { refresh(); }, []);

  const toggleInstall = async (p: KnowledgePack) => {
    setBusy(p.id);
    setError(null);
    try {
      if (p.installed && !p.outdated) {
        await uninstallKnowledgePack(p.id);
      } else {
        const r = await installKnowledgePack(p.id);
        if (!r.ok && r.error) setError(r.error);
      }
      await refresh();
      onChanged?.();
    } catch {
      setError("Operation failed.");
    } finally {
      setBusy(null);
    }
  };

  const toggleEnabled = async (p: KnowledgePack) => {
    setBusy(p.id);
    try {
      await setKnowledgePackEnabled(p.id, !p.enabled);
      await refresh();
      onChanged?.();
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl max-h-[86vh] flex flex-col bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl">
        {/* header */}
        <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-oyster-border shrink-0">
          <BookOpen size={17} className="text-oyster-accent" />
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-oyster-text">Knowledge Packs</h2>
            <p className="text-[11px] text-oyster-muted">
              {metrics && metrics.meets_public_threshold
                ? `${metrics.unique_searchable_chunks.toLocaleString()} indexed knowledge chunks · ${metrics.source_count} sources · `
                : "Curated, source-attributed security knowledge · "}
              {installedCount} installed · {enabledCount} enabled · runs locally
            </p>
          </div>
          <button onClick={refresh} className="ml-auto cursor-pointer text-oyster-muted hover:text-oyster-text p-1.5 rounded-md hover:bg-oyster-surface" title="Refresh">
            <RefreshCw size={14} />
          </button>
          <button onClick={onClose} className="cursor-pointer text-oyster-muted hover:text-oyster-text p-1.5 rounded-md hover:bg-oyster-surface">
            <X size={16} />
          </button>
        </div>

        {error && (
          <div className="mx-3 mt-3 flex items-center gap-2 text-[11px] text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            <AlertCircle size={13} /> {error}
          </div>
        )}

        {/* body */}
        <div className="overflow-y-auto p-3 space-y-2">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-oyster-muted">
              <Loader2 size={20} className="animate-spin" />
            </div>
          ) : packs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-oyster-muted gap-2">
              <BookOpen size={22} />
              <p className="text-xs">No Knowledge Packs found on disk.</p>
            </div>
          ) : (
            packs.map((p) => (
              <div
                key={p.id}
                className={`flex items-start gap-3 p-3 rounded-xl border bg-oyster-surface/40 transition-colors ${
                  p.installed && p.enabled === false ? "border-oyster-border/50 opacity-60" : "border-oyster-border hover:border-oyster-accent/30"
                }`}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[13px] font-medium text-oyster-text">{p.title}</span>
                    <span className="text-[9px] text-oyster-muted font-mono">v{p.installed_version || p.version}</span>
                    <span className={`text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded border ${DOMAIN_COLOR[p.domain] || "text-oyster-muted bg-oyster-surface border-oyster-border"}`}>
                      {p.security_domain || p.domain}
                    </span>
                    {p.risk_classification && RISK_COLOR[p.risk_classification] && (
                      <span className={`text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded border inline-flex items-center gap-0.5 ${RISK_COLOR[p.risk_classification]}`}>
                        <ShieldAlert size={9} /> {p.risk_classification}
                      </span>
                    )}
                    {p.trust_level && (
                      <span className="text-[10px] text-oyster-muted">· {p.trust_level}</span>
                    )}
                    {p.installed && (
                      <span className="text-[10px] text-green-400 flex items-center gap-0.5">
                        <Check size={10} /> {p.chunk_count} chunks
                      </span>
                    )}
                    {p.installed && p.enabled === false && (
                      <span className="text-[9px] uppercase tracking-wide text-oyster-muted bg-oyster-surface px-1.5 py-0.5 rounded border border-oyster-border">disabled</span>
                    )}
                  </div>
                  <p className="text-[12px] text-oyster-muted mt-1 leading-relaxed">{p.description}</p>
                  <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                    {(p.source_urls ?? []).slice(0, 2).map((u) => (
                      <a key={u} href={u} target="_blank" rel="noopener noreferrer"
                         className="text-[10px] text-oyster-accent/90 hover:underline inline-flex items-center gap-0.5">
                        <ExternalLink size={9} /> {new URL(u).hostname.replace("www.", "")}
                      </a>
                    ))}
                    {p.last_reviewed_at && (
                      <span className="text-[10px] text-oyster-muted">reviewed {p.last_reviewed_at}</span>
                    )}
                    {p.licence && (
                      <span className="text-[10px] text-oyster-muted/70 truncate max-w-[220px]" title={p.licence}>
                        {p.licence.length > 44 ? p.licence.slice(0, 44) + "…" : p.licence}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  <button
                    onClick={() => toggleInstall(p)}
                    disabled={busy === p.id || !p.valid}
                    className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all disabled:opacity-50 ${
                      p.installed && !p.outdated
                        ? "text-oyster-muted hover:text-red-400 border border-oyster-border hover:border-red-400/40"
                        : "bg-oyster-accent hover:bg-oyster-accent-hover text-white hover:-translate-y-0.5"
                    }`}
                    title={p.installed && !p.outdated ? "Remove pack" : p.outdated ? "Update pack" : "Install pack"}
                  >
                    {busy === p.id ? (
                      <Loader2 size={13} className="animate-spin" />
                    ) : p.outdated ? (
                      <><RefreshCw size={13} /> Update</>
                    ) : p.installed ? (
                      <><Trash2 size={13} /> Remove</>
                    ) : (
                      <><Download size={13} /> Install</>
                    )}
                  </button>
                  {p.installed && (
                    <button
                      onClick={() => toggleEnabled(p)}
                      disabled={busy === p.id}
                      className={`flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11px] font-medium transition-colors disabled:opacity-50 border ${
                        p.enabled === false
                          ? "text-oyster-muted border-oyster-border hover:text-oyster-text"
                          : "text-green-400 border-green-500/30 hover:bg-green-500/10"
                      }`}
                      title={p.enabled === false ? "Enable for retrieval" : "Disable (kept installed)"}
                    >
                      <Power size={11} /> {p.enabled === false ? "Enable" : "Enabled"}
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        <div className="px-5 py-2.5 border-t border-oyster-border shrink-0">
          <p className="text-[11px] text-oyster-muted/80">
            Only <span className="text-oyster-text">enabled</span> packs are searched by the RAG Analyst and cited with source links. Fully local — no cloud.
          </p>
        </div>
      </div>
    </div>
  );
}
