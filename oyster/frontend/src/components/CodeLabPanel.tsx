"use client";

import { useEffect, useMemo, useState } from "react";
import {
  PanelLeftOpen, Code2, Plus, Copy, Check, Trash2, Save, Bug, Loader2,
} from "lucide-react";
import { loadSnippets, saveSnippets, newSnippet, type CodeSnippet } from "@/lib/codelab";
import { createUserFinding } from "@/lib/api";
import type { Severity } from "@/types/chat";

interface CodeLabPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
}

// Red Team Code Lab — a COPY-ONLY Python scratchpad. Write, save, and organize
// snippets (browser-local), copy them to run in your OWN terminal, or promote a
// snippet to a Finding (with a comment) so it lands in the Findings panel.
// Nothing executes on the server.
export function CodeLabPanel({ onToggleSidebar, sidebarOpen }: CodeLabPanelProps) {
  const [snippets, setSnippets] = useState<CodeSnippet[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [comment, setComment] = useState("");
  const [severity, setSeverity] = useState<Severity>("info");
  const [copied, setCopied] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [finding, setFinding] = useState(false);

  useEffect(() => {
    const s = loadSnippets();
    setSnippets(s);
    if (s.length) select(s[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const active = useMemo(() => snippets.find((s) => s.id === activeId) ?? null, [snippets, activeId]);
  const dirty = active ? (name !== active.name || code !== active.code || comment !== active.comment) : (name !== "" || code !== "" || comment !== "");

  function select(s: CodeSnippet) {
    setActiveId(s.id); setName(s.name); setCode(s.code); setComment(s.comment); setMsg(null);
  }
  function create() {
    const s = newSnippet();
    const next = [s, ...snippets];
    setSnippets(next); saveSnippets(next); select(s);
  }
  function save() {
    setSaving(true); setMsg(null);
    const ts = Date.now();
    let next: CodeSnippet[];
    if (active) {
      next = snippets.map((s) => s.id === active.id ? { ...s, name: name.trim() || "Untitled snippet", code, comment, updatedAt: ts } : s);
    } else {
      const s = { ...newSnippet(), name: name.trim() || "Untitled snippet", code, comment, updatedAt: ts };
      next = [s, ...snippets]; setActiveId(s.id);
    }
    setSnippets(next); saveSnippets(next); setSaving(false); setMsg("Saved ✓");
  }
  function remove(id: string) {
    const next = snippets.filter((s) => s.id !== id);
    setSnippets(next); saveSnippets(next);
    if (activeId === id) { setActiveId(null); setName(""); setCode(""); setComment(""); }
  }
  async function copy() {
    try { await navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* no-op */ }
  }
  async function makeFinding() {
    if (!code.trim() || finding) return;
    setFinding(true); setMsg(null);
    const title = (name.trim() || "Code Lab snippet");
    const content = `**${title}**\n\n${comment ? comment + "\n\n" : ""}\`\`\`python\n${code}\n\`\`\``;
    const res = await createUserFinding({ title, content, notes: comment, severity, conv_mode: "codelab" });
    setFinding(false);
    setMsg(res ? "Saved as Finding ✓ (see Findings)" : "Could not save finding");
  }
  function onTab(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key !== "Tab") return;
    e.preventDefault();
    const ta = e.currentTarget;
    const s = ta.selectionStart, en = ta.selectionEnd;
    const nv = code.slice(0, s) + "    " + code.slice(en);
    setCode(nv);
    requestAnimationFrame(() => { ta.selectionStart = ta.selectionEnd = s + 4; });
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button onClick={onToggleSidebar} className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface">
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Code2 size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Code Lab</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          copy-only · runs in your terminal
        </span>
      </header>

      <div className="flex-1 min-h-0 flex">
        {/* Snippet list */}
        <div className="w-56 shrink-0 border-r border-oyster-border flex flex-col min-h-0">
          <div className="p-3 shrink-0">
            <button onClick={create} className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white transition-colors">
              <Plus size={15} /> New snippet
            </button>
          </div>
          <div className="flex-1 min-h-0 overflow-y-auto px-2 pb-3 space-y-1">
            {snippets.length === 0 ? (
              <p className="text-xs text-oyster-muted px-2 py-4 text-center">No saved snippets yet.</p>
            ) : snippets.map((s) => (
              <div key={s.id} className="group relative">
                <button onClick={() => select(s)} className={`w-full text-left px-2.5 py-2 rounded-lg transition-colors ${activeId === s.id ? "bg-oyster-accent/15" : "hover:bg-oyster-surface/60"}`}>
                  <p className={`text-sm truncate pr-5 ${activeId === s.id ? "text-oyster-accent" : "text-oyster-text"}`}>{s.name}</p>
                  <p className="text-[10px] text-oyster-muted">{new Date(s.updatedAt).toLocaleDateString()}</p>
                </button>
                <button onClick={() => remove(s.id)} className="absolute right-1 top-2 opacity-0 group-hover:opacity-100 text-oyster-muted hover:text-red-400 transition-opacity p-1"><Trash2 size={12} /></button>
              </div>
            ))}
          </div>
        </div>

        {/* Editor */}
        <div className="flex-1 min-w-0 flex flex-col min-h-0 p-4 gap-3">
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Snippet name"
            className="bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 shrink-0" />
          <textarea value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={onTab} spellCheck={false} placeholder="# Python code…"
            className="flex-1 min-h-0 bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-[13px] text-oyster-text font-mono leading-relaxed resize-none outline-none focus:border-oyster-accent/50 whitespace-pre" />
          <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Comment (used as the finding note)"
            className="bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 shrink-0" />
          <div className="flex items-center gap-2 shrink-0 flex-wrap">
            <button onClick={save} disabled={saving || !dirty}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white disabled:bg-oyster-border disabled:text-oyster-muted disabled:cursor-not-allowed transition-colors">
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />} Save
            </button>
            <button onClick={copy} disabled={!code.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium border border-oyster-border text-oyster-text hover:bg-oyster-surface disabled:opacity-50 transition-colors">
              {copied ? <><Check size={14} className="text-green-500" /> Copied</> : <><Copy size={14} /> Copy</>}
            </button>
            <div className="flex items-center gap-1.5 ml-auto">
              <select value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}
                className="bg-oyster-bg border border-oyster-border rounded-lg px-2 py-1.5 text-xs text-oyster-text outline-none focus:border-oyster-accent/50">
                {["info", "low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <button onClick={makeFinding} disabled={!code.trim() || finding}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium border border-oyster-accent/40 text-oyster-accent hover:bg-oyster-accent/10 disabled:opacity-50 transition-colors">
                {finding ? <Loader2 size={14} className="animate-spin" /> : <Bug size={14} />} Make Finding
              </button>
            </div>
          </div>
          {msg && <p className="text-xs text-oyster-muted shrink-0">{msg}</p>}
          <p className="text-[11px] text-oyster-muted/70 shrink-0">
            Snippets are stored in your browser only. Oyster never runs this code — copy it and run it in your own terminal.
          </p>
        </div>
      </div>
    </div>
  );
}
