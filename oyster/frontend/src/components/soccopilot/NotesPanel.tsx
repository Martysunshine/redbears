"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { PanelLeftOpen, StickyNote, Loader2, AlertCircle, Plus, Trash2, ChevronDown } from "lucide-react";
import * as socmat from "@/lib/socmat";

interface NotesPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
}

// Top-level Blue Team Notes — a cross-case analyst notebook. "All cases" shows
// the owner-wide aggregate (GET /notes); picking a case scopes to it and lets
// you add. Cooperates with SOC Copilot: notes added here appear in that case's
// Notes tab and vice-versa (same rows).
export function NotesPanel({ onToggleSidebar, sidebarOpen }: NotesPanelProps) {
  const [cases, setCases] = useState<socmat.Case[]>([]);
  const [scope, setScope] = useState<"all" | number>("all");
  const [notes, setNotes] = useState<socmat.AnalystNote[] | null>(null);
  const [body, setBody] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [online, setOnline] = useState<boolean | null>(null);

  const caseTitle = useMemo(() => {
    const m = new Map(cases.map((c) => [c.id, c.title] as const));
    return (id: number) => m.get(id) ?? `case #${id}`;
  }, [cases]);

  const load = useCallback(() => {
    const p = scope === "all" ? socmat.getAllNotes() : socmat.getNotes(scope);
    p.then((n) => { setNotes(n); setOnline(true); }).catch((e) => { setOnline(false); setErr(e.message); });
  }, [scope]);

  useEffect(() => { socmat.getCases().then(setCases).catch(() => {}); }, []);
  useEffect(load, [load]);

  async function add() {
    if (!body.trim() || busy || scope === "all") return;
    setBusy(true); setErr(null);
    try { await socmat.createNote(scope, { entity_type: "case", note_type: "general", body: body.trim() }); setBody(""); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Save failed"); }
    finally { setBusy(false); }
  }
  async function del(n: socmat.AnalystNote) {
    try { await socmat.deleteNote(n.case_id, n.id); load(); } catch { /* ignore */ }
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button onClick={onToggleSidebar} className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface">
            <PanelLeftOpen size={18} />
          </button>
        )}
        <StickyNote size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Notes</span>
        <div className="relative ml-2">
          <select value={String(scope)} onChange={(e) => setScope(e.target.value === "all" ? "all" : Number(e.target.value))}
            className="appearance-none bg-oyster-surface border border-oyster-border rounded-lg pl-3 pr-7 py-1 text-xs text-oyster-text outline-none focus:border-oyster-accent/50">
            <option value="all">All cases</option>
            {cases.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
          </select>
          <ChevronDown size={12} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-oyster-muted" />
        </div>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <span className={`w-1.5 h-1.5 rounded-full ${online === true ? "bg-green-500" : online === false ? "bg-red-500" : "bg-yellow-500 animate-pulse"}`} />
          {online === null ? "connecting…" : online ? "online" : "offline"}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-2xl mx-auto space-y-3">
          {err && <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/30 rounded-xl px-3.5 py-2.5"><AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" /><p className="text-sm text-red-400">{err}</p></div>}

          {scope === "all" ? (
            <p className="text-xs text-oyster-muted">Viewing notes across all cases. Pick a case above to add a note.</p>
          ) : (
            <div className="flex gap-2">
              <input value={body} onChange={(e) => setBody(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} placeholder="Add a note to this case…"
                className="flex-1 bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50" />
              <button onClick={add} disabled={!body.trim() || busy}
                className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white disabled:opacity-50 transition-colors">
                {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              </button>
            </div>
          )}

          {notes === null ? <Loader2 className="animate-spin text-oyster-muted" />
            : notes.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
                <div className="w-11 h-11 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center"><StickyNote size={18} className="text-oyster-muted" /></div>
                <p className="text-sm font-medium text-oyster-text">No notes {scope === "all" ? "yet" : "for this case"}</p>
                <p className="text-xs text-oyster-muted max-w-xs">Record observations, hypotheses and decisions. Notes are shared with the matching case in SOC Copilot.</p>
              </div>
            )
            : notes.map((n) => (
              <div key={n.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5 group">
                <div className="flex items-start gap-2">
                  <StickyNote size={13} className="text-oyster-muted mt-0.5 shrink-0" />
                  <p className="text-sm text-oyster-text flex-1">{n.body}</p>
                  <button onClick={() => del(n)} className="opacity-0 group-hover:opacity-100 text-oyster-muted hover:text-red-400 transition-opacity"><Trash2 size={13} /></button>
                </div>
                <div className="flex items-center gap-2 mt-1 text-[10px] text-oyster-muted/70">
                  {scope === "all" && <span className="text-oyster-accent/80">{caseTitle(n.case_id)}</span>}
                  <span>{n.note_type}</span>
                  <span>· {new Date(n.created_at).toLocaleString()}</span>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
