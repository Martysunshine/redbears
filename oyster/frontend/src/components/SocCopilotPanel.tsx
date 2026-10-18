"use client";

import { useCallback, useEffect, useState } from "react";
import { PanelLeftOpen, Radar, Loader2, AlertCircle, Plus, X, FolderKanban, Wand2, Database } from "lucide-react";
import { socmatHealth } from "@/lib/api";
import * as socmat from "@/lib/socmat";
import { CaseDetail, SevBadge } from "@/components/soccopilot/CaseDetail";
import { RuleAuthoringView, LiveSiemView } from "@/components/soccopilot/GlobalTools";

type View = "cases" | "rules" | "siem";
const VIEWS: { id: View; label: string; icon: React.ElementType }[] = [
  { id: "cases", label: "Cases", icon: FolderKanban },
  { id: "rules", label: "Rule Authoring", icon: Wand2 },
  { id: "siem", label: "Live SIEM", icon: Database },
];

interface SocCopilotPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  activeProjectName: string;
}

// SOC Copilot — the defensive analyst workbench. Backend is the socmat SOC
// Copilot API mounted inside Oyster at /socmat/api, per-account isolated. This
// is the case-centric shell: dashboard stats + a case list on the left, the
// selected case's detail (evidence, detections, timeline, IOCs, MITRE, AI,
// report) on the right — all native, themed, no iframe.
export function SocCopilotPanel({ onToggleSidebar, sidebarOpen, activeProjectName }: SocCopilotPanelProps) {
  const [online, setOnline] = useState<boolean | null>(null);
  const [cases, setCases] = useState<socmat.Case[] | null>(null);
  const [summary, setSummary] = useState<socmat.DashboardSummary | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [view, setView] = useState<View>("cases");

  const refresh = useCallback(() => {
    socmat.getCases().then((cs) => {
      setCases(cs);
      setOnline(true);
      setSelected((cur) => (cur == null && cs.length ? cs[0].id : cur));
    }).catch((e) => { setOnline(false); setErr(e instanceof Error ? e.message : "unreachable"); });
    socmat.getDashboard().then(setSummary).catch(() => {});
  }, []);

  useEffect(() => {
    socmatHealth().then(() => setOnline(true)).catch(() => setOnline(false));
    refresh();
  }, [refresh]);

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button onClick={onToggleSidebar} className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface">
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Radar size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">SOC Copilot</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          {activeProjectName || "workbench"}
        </span>
        <div className="ml-3 flex items-center gap-0.5 bg-oyster-surface border border-oyster-border rounded-lg p-0.5">
          {VIEWS.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setView(id)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                view === id ? "bg-oyster-accent/15 text-oyster-accent" : "text-oyster-muted hover:text-oyster-text"
              }`}>
              <Icon size={12} /> {label}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <span className={`w-1.5 h-1.5 rounded-full ${online === true ? "bg-green-500" : online === false ? "bg-red-500" : "bg-yellow-500 animate-pulse"}`} />
          {online === null ? "connecting…" : online ? "online" : "offline"}
        </div>
      </header>

      {online === false ? (
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 max-w-md">
            <AlertCircle size={16} className="text-red-400 shrink-0 mt-0.5" />
            <div className="text-sm text-red-400">
              <p className="font-medium">SOC Copilot workbench is unreachable.</p>
              <p className="text-xs mt-1 text-red-400/80">{err}</p>
            </div>
          </div>
        </div>
      ) : view === "rules" ? (
        <div className="flex-1 min-h-0 overflow-y-auto"><RuleAuthoringView /></div>
      ) : view === "siem" ? (
        <div className="flex-1 min-h-0 overflow-y-auto"><LiveSiemView /></div>
      ) : (
        <div className="flex-1 min-h-0 flex">
          {/* Left: dashboard + case list */}
          <div className="w-72 shrink-0 border-r border-oyster-border flex flex-col min-h-0">
            {summary && (
              <div className="grid grid-cols-2 gap-px bg-oyster-border shrink-0">
                <Stat label="Cases" value={summary.total_cases} />
                <Stat label="Open" value={summary.open_cases} />
                <Stat label="Critical" value={summary.critical_cases} accent="text-red-400" />
                <Stat label="Evidence" value={summary.total_evidence} />
              </div>
            )}
            <div className="p-3 shrink-0">
              <button onClick={() => setCreating(true)}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white transition-colors">
                <Plus size={15} /> New case
              </button>
            </div>
            <div className="flex-1 min-h-0 overflow-y-auto px-2 pb-3 space-y-1">
              {cases === null ? (
                <div className="flex justify-center py-8"><Loader2 className="animate-spin text-oyster-muted" /></div>
              ) : cases.length === 0 ? (
                <p className="text-xs text-oyster-muted px-2 py-4 text-center">No cases yet. Create one to start.</p>
              ) : (
                cases.map((c) => (
                  <button key={c.id} onClick={() => setSelected(c.id)}
                    className={`w-full text-left px-2.5 py-2 rounded-lg transition-colors ${
                      selected === c.id ? "bg-oyster-accent/15" : "hover:bg-oyster-surface/60"
                    }`}>
                    <div className="flex items-center gap-1.5">
                      <SevBadge level={c.severity} />
                      <span className="text-[10px] text-oyster-muted ml-auto">{c.status}</span>
                    </div>
                    <p className={`text-sm mt-1 truncate ${selected === c.id ? "text-oyster-accent" : "text-oyster-text"}`}>{c.title}</p>
                  </button>
                ))
              )}
            </div>
          </div>

          {/* Right: case detail */}
          <div className="flex-1 min-w-0 flex flex-col min-h-0">
            {selected != null ? (
              <CaseDetail key={selected} caseId={selected} onChanged={refresh} />
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center p-6">
                <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
                  <Radar size={20} className="text-oyster-muted" />
                </div>
                <p className="text-sm font-medium text-oyster-text">Select or create a case</p>
                <p className="text-xs text-oyster-muted max-w-xs">Parse logs, run detections, map ATT&CK, extract IOCs, and write the report — all in one case.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {creating && (
        <NewCaseModal
          onClose={() => setCreating(false)}
          onCreated={(c) => { setCreating(false); setSelected(c.id); refresh(); }}
        />
      )}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="bg-oyster-bg px-3 py-2.5">
      <p className={`text-lg font-semibold ${accent ?? "text-oyster-text"}`}>{value}</p>
      <p className="text-[10px] text-oyster-muted uppercase tracking-wider">{label}</p>
    </div>
  );
}

function NewCaseModal({ onClose, onCreated }: { onClose: () => void; onCreated: (c: socmat.Case) => void }) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<socmat.Severity>("medium");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    if (!title.trim() || busy) return;
    setBusy(true); setErr(null);
    try { onCreated(await socmat.createCase({ title: title.trim(), severity, description: description.trim() || undefined })); }
    catch (e) { setErr(e instanceof Error ? e.message : "Create failed"); setBusy(false); }
  }

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true"
      onKeyDown={(e) => e.key === "Escape" && onClose()}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-oyster-text">New case</h2>
          <button onClick={onClose} className="text-oyster-muted hover:text-oyster-text"><X size={16} /></button>
        </div>
        {err && <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 text-sm text-red-400"><AlertCircle size={14} className="mt-0.5 shrink-0" />{err}</div>}
        <input autoFocus value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Case title"
          className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50" />
        <select value={severity} onChange={(e) => setSeverity(e.target.value as socmat.Severity)}
          className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50">
          {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} placeholder="Description (optional)"
          className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50" />
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 rounded-lg text-sm text-oyster-muted hover:text-oyster-text border border-oyster-border">Cancel</button>
          <button onClick={submit} disabled={!title.trim() || busy}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white disabled:opacity-50">
            {busy ? <><Loader2 size={14} className="animate-spin" /> Creating…</> : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
