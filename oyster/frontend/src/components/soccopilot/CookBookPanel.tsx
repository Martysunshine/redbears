"use client";

import { useEffect, useState } from "react";
import {
  PanelLeftOpen, BookMarked, Copy, Check, ListChecks, Terminal,
  ShieldAlert, ClipboardCheck, Loader2, AlertCircle, Link2, ChevronDown,
} from "lucide-react";
import * as socmat from "@/lib/socmat";
import { SHORTCUT_GROUPS, ATTACK_CARDS, CHECKLISTS } from "@/data/blueteam-cookbook";

interface CookBookPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
}

type Section = "playbooks" | "shortcuts" | "attack" | "checklists";
const SECTIONS: { id: Section; label: string; icon: React.ElementType }[] = [
  { id: "playbooks", label: "Playbooks", icon: ListChecks },
  { id: "shortcuts", label: "Shortcuts", icon: Terminal },
  { id: "attack", label: "ATT&CK", icon: ShieldAlert },
  { id: "checklists", label: "Checklists", icon: ClipboardCheck },
];

// Blue-team Cook Book — a reference library that cooperates with SOC Copilot:
// browse the live playbook templates (and attach one to a case), plus curated
// copyable shortcuts, ATT&CK detection cards, and triage checklists.
export function CookBookPanel({ onToggleSidebar, sidebarOpen }: CookBookPanelProps) {
  const [section, setSection] = useState<Section>("playbooks");
  const [copied, setCopied] = useState<string | null>(null);

  async function copy(key: string, text: string) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500); } catch { /* no-op */ }
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button onClick={onToggleSidebar} className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface">
            <PanelLeftOpen size={18} />
          </button>
        )}
        <BookMarked size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Cook Book</span>
        <div className="ml-3 flex items-center gap-0.5 bg-oyster-surface border border-oyster-border rounded-lg p-0.5 overflow-x-auto">
          {SECTIONS.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setSection(id)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium whitespace-nowrap transition-colors ${
                section === id ? "bg-oyster-accent/15 text-oyster-accent" : "text-oyster-muted hover:text-oyster-text"
              }`}>
              <Icon size={12} /> {label}
            </button>
          ))}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto">
          {section === "playbooks" && <PlaybooksLibrary copy={copy} copied={copied} />}
          {section === "shortcuts" && <Shortcuts copy={copy} copied={copied} />}
          {section === "attack" && <AttackRef copy={copy} copied={copied} />}
          {section === "checklists" && <Checklists copy={copy} copied={copied} />}
        </div>
      </div>
    </div>
  );
}

type CopyProps = { copy: (k: string, t: string) => void; copied: string | null };

function CopyBtn({ k, text, copy, copied }: { k: string; text: string } & CopyProps) {
  return (
    <button onClick={() => copy(k, text)} className="cursor-pointer flex items-center gap-1 text-[11px] text-oyster-muted hover:text-oyster-text transition-colors">
      {copied === k ? <><Check size={12} className="text-green-500" /> Copied</> : <><Copy size={12} /> Copy</>}
    </button>
  );
}

// ── Playbooks library (live templates + attach-to-case) ─────────────────────

function PlaybooksLibrary({ copy, copied }: CopyProps) {
  const [templates, setTemplates] = useState<socmat.PlaybookTemplateSummary[] | null>(null);
  const [openId, setOpenId] = useState<number | null>(null);
  const [detail, setDetail] = useState<socmat.PlaybookTemplateDetail | null>(null);
  const [cases, setCases] = useState<socmat.Case[]>([]);
  const [attachTo, setAttachTo] = useState<string>("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    socmat.getPlaybookTemplates().then(setTemplates).catch((e) => setErr(e.message));
    socmat.getCases().then(setCases).catch(() => {});
  }, []);

  async function open(id: number) {
    if (openId === id) { setOpenId(null); setDetail(null); return; }
    setOpenId(id); setDetail(null);
    try { setDetail(await socmat.getPlaybookTemplate(id)); } catch (e) { setErr(e instanceof Error ? e.message : "load failed"); }
  }
  async function attach(templateId: number) {
    if (!attachTo) { setMsg("Pick a case first."); return; }
    setMsg(null); setErr(null);
    try { await socmat.attachPlaybook(Number(attachTo), templateId); setMsg("Attached to case ✓"); }
    catch (e) { setErr(e instanceof Error ? e.message : "attach failed"); }
  }
  function stepsText(d: socmat.PlaybookTemplateDetail): string {
    return d.steps.map((s) => `${s.order}. ${s.title}\n   ${s.description}`).join("\n");
  }

  if (err) return <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/30 rounded-xl px-3.5 py-2.5"><AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" /><p className="text-sm text-red-400">{err}</p></div>;
  if (templates === null) return <Loader2 className="animate-spin text-oyster-muted" />;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-oyster-muted">Attach to case:</span>
        <div className="relative">
          <select value={attachTo} onChange={(e) => setAttachTo(e.target.value)}
            className="appearance-none bg-oyster-bg border border-oyster-border rounded-lg pl-3 pr-7 py-1.5 text-xs text-oyster-text outline-none focus:border-oyster-accent/50">
            <option value="">— select case —</option>
            {cases.map((c) => <option key={c.id} value={c.id}>#{c.id} {c.title}</option>)}
          </select>
          <ChevronDown size={12} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-oyster-muted" />
        </div>
        {msg && <span className="text-xs text-oyster-accent">{msg}</span>}
      </div>
      {templates.map((t) => (
        <div key={t.id} className="bg-oyster-surface border border-oyster-border rounded-xl overflow-hidden">
          <button onClick={() => open(t.id)} className="w-full flex items-center gap-2 px-3.5 py-2.5 text-left hover:bg-oyster-bg/40 transition-colors">
            <ListChecks size={14} className="text-oyster-accent shrink-0" />
            <span className="text-sm text-oyster-text font-medium">{t.name}</span>
            <span className="text-[10px] text-oyster-muted uppercase">{t.alert_type}</span>
            <span className="ml-auto text-[11px] text-oyster-muted">{t.step_count} steps</span>
            <ChevronDown size={13} className={`text-oyster-muted transition-transform ${openId === t.id ? "rotate-180" : ""}`} />
          </button>
          {openId === t.id && (
            <div className="px-3.5 pb-3 border-t border-oyster-border pt-2.5 space-y-2.5">
              {t.description && <p className="text-xs text-oyster-muted">{t.description}</p>}
              {detail === null ? <Loader2 size={14} className="animate-spin text-oyster-muted" /> : (
                <>
                  {detail.required_data_sources.length > 0 && (
                    <p className="text-[11px] text-oyster-muted"><span className="font-semibold text-oyster-text">Data sources:</span> {detail.required_data_sources.join(" · ")}</p>
                  )}
                  <ol className="space-y-1.5">
                    {detail.steps.map((s) => (
                      <li key={s.order} className="text-xs text-oyster-text/90">
                        <span className="text-oyster-accent font-medium">{s.order}.</span> <span className="font-medium">{s.title}</span>
                        <p className="text-oyster-muted mt-0.5 pl-4">{s.description}</p>
                      </li>
                    ))}
                  </ol>
                  <div className="flex items-center gap-3 pt-1">
                    <CopyBtn k={`pb-${t.id}`} text={stepsText(detail)} copy={copy} copied={copied} />
                    <button onClick={() => attach(t.id)} className="flex items-center gap-1 text-[11px] text-oyster-accent hover:underline">
                      <Link2 size={12} /> Attach to selected case
                    </button>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Shortcuts ───────────────────────────────────────────────────────────────

function Shortcuts({ copy, copied }: CopyProps) {
  return (
    <div className="space-y-6">
      {SHORTCUT_GROUPS.map((g) => (
        <section key={g.id} className="space-y-2">
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest px-1">{g.title}</h3>
          {g.snippets.map((s, i) => {
            const k = `${g.id}-${i}`;
            return (
              <div key={k} className="bg-oyster-surface border border-oyster-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-3 py-1.5 border-b border-oyster-border">
                  <span className="text-[11px] font-medium text-oyster-muted">{s.label}</span>
                  <CopyBtn k={k} text={s.code} copy={copy} copied={copied} />
                </div>
                <pre className="px-3 py-2.5 text-[12px] text-oyster-text font-mono overflow-x-auto leading-relaxed whitespace-pre">{s.code}</pre>
                {s.note && <p className="px-3 pb-2 text-[11px] text-oyster-muted/80">{s.note}</p>}
              </div>
            );
          })}
        </section>
      ))}
    </div>
  );
}

// ── ATT&CK quick reference ──────────────────────────────────────────────────

function AttackRef({ copy, copied }: CopyProps) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {ATTACK_CARDS.map((a) => (
        <div key={a.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-3 space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-oyster-accent">{a.id}</span>
            <span className="text-sm text-oyster-text font-medium">{a.name}</span>
            <span className="ml-auto"><CopyBtn k={`atk-${a.id}`} text={`${a.id} ${a.name} — ${a.tactic}\nDetection: ${a.detection}\nLog source: ${a.logSource}`} copy={copy} copied={copied} /></span>
          </div>
          <p className="text-[11px] text-oyster-muted uppercase tracking-wide">{a.tactic}</p>
          <p className="text-xs text-oyster-text/90"><span className="text-oyster-muted">Detect:</span> {a.detection}</p>
          <p className="text-[11px] text-oyster-muted"><span className="font-semibold">Log:</span> {a.logSource}</p>
        </div>
      ))}
    </div>
  );
}

// ── Checklists board ────────────────────────────────────────────────────────

function Checklists({ copy, copied }: CopyProps) {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {CHECKLISTS.map((cl) => (
        <div key={cl.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-4 py-3.5 space-y-2">
          <div className="flex items-center gap-2">
            <ClipboardCheck size={15} className="text-oyster-accent" />
            <span className="text-sm text-oyster-text font-medium">{cl.name}</span>
            <span className="ml-auto"><CopyBtn k={`cl-${cl.id}`} text={`${cl.name}\n${cl.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`} copy={copy} copied={copied} /></span>
          </div>
          <p className="text-[11px] text-oyster-muted italic">{cl.when}</p>
          <ol className="space-y-1">
            {cl.steps.map((s, i) => (
              <li key={i} className="text-xs text-oyster-text/90 flex gap-2"><span className="text-oyster-accent shrink-0">{i + 1}.</span>{s}</li>
            ))}
          </ol>
        </div>
      ))}
    </div>
  );
}
