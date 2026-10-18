"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Loader2, AlertCircle, Upload, FileText, Radar, Clock, Crosshair,
  Sparkles, ScrollText, ShieldAlert, Download, RefreshCw,
  Network, Link2, Share2, Gauge, ListChecks, CheckCircle2, StickyNote, Plus, Trash2,
} from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import * as socmat from "@/lib/socmat";

const SEV_CLASS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-sky-400 bg-sky-500/10 border-sky-500/30",
  info: "text-oyster-muted bg-oyster-surface border-oyster-border",
};
export function SevBadge({ level }: { level: string }) {
  const cls = SEV_CLASS[level?.toLowerCase()] ?? SEV_CLASS.info;
  return (
    <span className={`text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border ${cls}`}>
      {level}
    </span>
  );
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

type Tab =
  | "overview" | "evidence" | "detections" | "network" | "timeline" | "iocs"
  | "mitre" | "correlation" | "graph" | "coverage" | "playbooks"
  | "dispositions" | "notes" | "ai" | "report";
const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: "overview", label: "Overview", icon: FileText },
  { id: "evidence", label: "Evidence", icon: Upload },
  { id: "detections", label: "Detections", icon: Radar },
  { id: "network", label: "Network", icon: Network },
  { id: "timeline", label: "Timeline", icon: Clock },
  { id: "iocs", label: "IOCs", icon: Crosshair },
  { id: "mitre", label: "MITRE", icon: ShieldAlert },
  { id: "correlation", label: "Correlation", icon: Link2 },
  { id: "graph", label: "Graph", icon: Share2 },
  { id: "coverage", label: "Coverage", icon: Gauge },
  { id: "playbooks", label: "Playbooks", icon: ListChecks },
  { id: "dispositions", label: "Dispositions", icon: CheckCircle2 },
  { id: "notes", label: "Notes", icon: StickyNote },
  { id: "ai", label: "AI Assistant", icon: Sparkles },
  { id: "report", label: "Report", icon: ScrollText },
];

const STATUSES: socmat.CaseStatus[] = ["open", "investigating", "contained", "escalated", "closed"];

function Empty({ icon: Icon, title, hint }: { icon: React.ElementType; title: string; hint: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
      <div className="w-11 h-11 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
        <Icon size={18} className="text-oyster-muted" />
      </div>
      <p className="text-sm font-medium text-oyster-text">{title}</p>
      <p className="text-xs text-oyster-muted max-w-xs">{hint}</p>
    </div>
  );
}

function Err({ msg }: { msg: string }) {
  return (
    <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/30 rounded-xl px-3.5 py-2.5">
      <AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" />
      <p className="text-sm text-red-400">{msg}</p>
    </div>
  );
}

const busyBtn =
  "flex items-center justify-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white disabled:bg-oyster-border disabled:text-oyster-muted disabled:cursor-not-allowed transition-colors";

export function CaseDetail({ caseId, onChanged }: { caseId: number; onChanged: () => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [c, setC] = useState<socmat.Case | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const reload = useCallback(() => {
    socmat.getCase(caseId).then(setC).catch((e) => setErr(e.message));
  }, [caseId]);

  useEffect(() => {
    setC(null);
    setErr(null);
    setTab("overview");
    reload();
  }, [caseId, reload]);

  if (err) return <div className="p-6"><Err msg={err} /></div>;
  if (!c) return <div className="flex items-center justify-center py-24"><Loader2 className="animate-spin text-oyster-muted" /></div>;

  return (
    <div className="flex flex-col min-h-0 flex-1">
      {/* Case header */}
      <div className="px-5 pt-4 pb-3 border-b border-oyster-border">
        <div className="flex items-center gap-2.5 flex-wrap">
          <SevBadge level={c.severity} />
          <h2 className="text-base font-semibold text-oyster-text">{c.title}</h2>
          <span className="text-xs text-oyster-muted">#{c.id}</span>
          <span className="ml-auto text-xs text-oyster-muted">{c.status}</span>
        </div>
        {c.description && <p className="text-sm text-oyster-muted mt-1.5 leading-relaxed">{c.description}</p>}
        <div className="flex gap-4 mt-2 text-[11px] text-oyster-muted flex-wrap">
          {c.affected_host && <span>host: <span className="text-oyster-text/80 font-mono">{c.affected_host}</span></span>}
          {c.affected_user && <span>user: <span className="text-oyster-text/80 font-mono">{c.affected_user}</span></span>}
          {c.affected_ip && <span>ip: <span className="text-oyster-text/80 font-mono">{c.affected_ip}</span></span>}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-0.5 px-4 pt-2 border-b border-oyster-border overflow-x-auto shrink-0">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[13px] font-medium border-b-2 -mb-px whitespace-nowrap transition-colors ${
              tab === id
                ? "border-oyster-accent text-oyster-accent"
                : "border-transparent text-oyster-muted hover:text-oyster-text"
            }`}
          >
            <Icon size={13} /> {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4">
        {tab === "overview" && <Overview c={c} onSaved={() => { reload(); onChanged(); }} />}
        {tab === "evidence" && <EvidenceTab caseId={caseId} />}
        {tab === "detections" && <DetectionsTab caseId={caseId} />}
        {tab === "network" && <NetworkTab caseId={caseId} />}
        {tab === "timeline" && <TimelineTab caseId={caseId} />}
        {tab === "iocs" && <IocsTab caseId={caseId} />}
        {tab === "mitre" && <MitreTab caseId={caseId} />}
        {tab === "correlation" && <CorrelationTab caseId={caseId} />}
        {tab === "graph" && <GraphTab caseId={caseId} />}
        {tab === "coverage" && <CoverageTab caseId={caseId} />}
        {tab === "playbooks" && <PlaybooksTab caseId={caseId} />}
        {tab === "dispositions" && <DispositionsTab caseId={caseId} />}
        {tab === "notes" && <NotesTab caseId={caseId} />}
        {tab === "ai" && <AiTab caseId={caseId} />}
        {tab === "report" && <ReportTab caseId={caseId} />}
      </div>
    </div>
  );
}

// ── Overview ────────────────────────────────────────────────────────────────

function Overview({ c, onSaved }: { c: socmat.Case; onSaved: () => void }) {
  const [status, setStatus] = useState<socmat.CaseStatus>(c.status);
  const [severity, setSeverity] = useState<socmat.Severity>(c.severity);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const dirty = status !== c.status || severity !== c.severity;

  async function save() {
    setSaving(true); setErr(null);
    try { await socmat.updateCase(c.id, { status, severity }); onSaved(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Save failed"); }
    finally { setSaving(false); }
  }

  return (
    <div className="max-w-xl space-y-4">
      {err && <Err msg={err} />}
      <div className="grid grid-cols-2 gap-3">
        <label className="space-y-1.5">
          <span className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">Severity</span>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as socmat.Severity)}
            className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50">
            {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="space-y-1.5">
          <span className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value as socmat.CaseStatus)}
            className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50">
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      </div>
      <button onClick={save} disabled={!dirty || saving} className={busyBtn}>
        {saving ? <><Loader2 size={14} className="animate-spin" /> Saving…</> : "Save changes"}
      </button>
      <div className="text-[11px] text-oyster-muted pt-2 border-t border-oyster-border">
        Created {new Date(c.created_at).toLocaleString()} · Updated {new Date(c.updated_at).toLocaleString()} · Source {c.source}
      </div>
    </div>
  );
}

// ── Evidence ────────────────────────────────────────────────────────────────

function EvidenceTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<socmat.Evidence[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [analyzing, setAnalyzing] = useState<number | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(() => {
    socmat.getEvidence(caseId).then(setItems).catch((e) => setErr(e.message));
  }, [caseId]);
  useEffect(load, [load]);

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true); setErr(null);
    try { await socmat.uploadEvidence(caseId, file, ""); load(); }
    catch (er) { setErr(er instanceof Error ? er.message : "Upload failed"); }
    finally { setBusy(false); e.target.value = ""; }
  }

  async function analyze(evId: number, kind: "windows" | "yara") {
    setAnalyzing(evId); setErr(null); setNote(null);
    try {
      if (kind === "windows") {
        const r = await socmat.runWindowsAnalysis(caseId, evId);
        setNote(`Windows logs: ${r.total_events} events, ${r.suspicious_findings.length} suspicious, +${r.timeline_events_added} timeline`);
      } else {
        const r = await socmat.runYaraTriage(caseId, evId);
        setNote(`YARA triage: risk ${r.risk_score}, ${r.yara_matches.length} match(es)`);
      }
    } catch (e) { setErr(e instanceof Error ? e.message : "Analysis failed"); }
    finally { setAnalyzing(null); }
  }

  return (
    <div className="max-w-2xl space-y-3">
      {err && <Err msg={err} />}
      <div className="flex items-center gap-3 flex-wrap">
        <label className={`${busyBtn} cursor-pointer w-fit`}>
          {busy ? <><Loader2 size={14} className="animate-spin" /> Uploading…</> : <><Upload size={14} /> Upload evidence</>}
          <input type="file" className="hidden" onChange={onFile} disabled={busy} />
        </label>
        {note && <span className="text-xs text-oyster-muted">{note}</span>}
      </div>
      {items === null ? (
        <Loader2 className="animate-spin text-oyster-muted" />
      ) : items.length === 0 ? (
        <Empty icon={Upload} title="No evidence yet" hint="Upload logs, PCAPs, or suspicious files (≤50 MB), then analyze them to generate detections and timeline events." />
      ) : (
        <div className="space-y-2">
          {items.map((ev) => (
            <div key={ev.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2">
                <FileText size={14} className="text-oyster-muted shrink-0" />
                <span className="text-sm text-oyster-text truncate">{ev.original_filename}</span>
                <span className="ml-auto text-[11px] text-oyster-muted">{bytes(ev.file_size)}</span>
              </div>
              <div className="text-[10px] text-oyster-muted font-mono mt-1 truncate">sha256:{ev.sha256}</div>
              <div className="flex items-center gap-2 mt-2">
                <button onClick={() => analyze(ev.id, "windows")} disabled={analyzing === ev.id}
                  className="text-[11px] px-2 py-1 rounded-md border border-oyster-border text-oyster-muted hover:text-oyster-text hover:bg-oyster-bg/60 disabled:opacity-50 transition-colors">
                  {analyzing === ev.id ? "…" : "Analyze Windows logs"}
                </button>
                <button onClick={() => analyze(ev.id, "yara")} disabled={analyzing === ev.id}
                  className="text-[11px] px-2 py-1 rounded-md border border-oyster-border text-oyster-muted hover:text-oyster-text hover:bg-oyster-bg/60 disabled:opacity-50 transition-colors">
                  {analyzing === ev.id ? "…" : "YARA triage"}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Detections (Sigma + YARA) ───────────────────────────────────────────────

function DetectionsTab({ caseId }: { caseId: number }) {
  const [findings, setFindings] = useState<socmat.DetectionFinding[] | null>(null);
  const [yara, setYara] = useState<socmat.MalwareTriageResult[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(() => {
    socmat.getSigmaFindings(caseId).then(setFindings).catch((e) => setErr(e.message));
    socmat.getYaraResults(caseId).then(setYara).catch(() => {});
  }, [caseId]);
  useEffect(load, [load]);

  async function runSigma() {
    setRunning(true); setErr(null); setNote(null);
    try {
      const r = await socmat.runSigma(caseId);
      setNote(`${r.rules_run} rules over ${r.events_scanned} events → ${r.findings_created} new finding(s)`);
      load();
    } catch (e) { setErr(e instanceof Error ? e.message : "Sigma run failed"); }
    finally { setRunning(false); }
  }

  return (
    <div className="max-w-3xl space-y-4">
      {err && <Err msg={err} />}
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={runSigma} disabled={running} className={busyBtn}>
          {running ? <><Loader2 size={14} className="animate-spin" /> Running Sigma…</> : <><Radar size={14} /> Run Sigma rules</>}
        </button>
        {note && <span className="text-xs text-oyster-muted">{note}</span>}
      </div>

      <section className="space-y-2">
        <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">Sigma findings</h3>
        {findings === null ? <Loader2 className="animate-spin text-oyster-muted" />
          : findings.length === 0 ? <Empty icon={Radar} title="No Sigma findings" hint="Upload Windows/Sysmon evidence and run Sigma rules to generate detections." />
          : findings.map((f) => (
            <div key={f.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2 flex-wrap">
                <SevBadge level={f.severity} />
                <span className="text-sm text-oyster-text">{f.rule_title}</span>
                <span className="ml-auto text-[10px] text-oyster-muted font-mono">{f.rule_id}</span>
              </div>
              <p className="text-xs text-oyster-muted mt-1">{f.match_reason}</p>
            </div>
          ))}
      </section>

      <section className="space-y-2">
        <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">YARA triage</h3>
        {yara.length === 0 ? <p className="text-xs text-oyster-muted">No YARA triage yet — run it from a file in the Evidence tab.</p>
          : yara.map((y) => (
            <div key={y.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2">
                <ShieldAlert size={14} className={y.risk_score > 0 ? "text-orange-400" : "text-oyster-muted"} />
                <span className="text-sm text-oyster-text truncate">{y.original_filename}</span>
                <span className="ml-auto text-[11px] text-oyster-muted">risk {y.risk_score}</span>
              </div>
              {y.yara_matches.length > 0 && (
                <div className="text-[11px] text-oyster-muted mt-1">matches: {y.yara_matches.map((m) => m.rule).join(", ")}</div>
              )}
            </div>
          ))}
      </section>
    </div>
  );
}

// ── Timeline ────────────────────────────────────────────────────────────────

function TimelineTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<socmat.TimelineEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { socmat.getTimeline(caseId).then(setItems).catch((e) => setErr(e.message)); }, [caseId]);

  if (err) return <Err msg={err} />;
  if (items === null) return <Loader2 className="animate-spin text-oyster-muted" />;
  if (items.length === 0) return <Empty icon={Clock} title="Empty timeline" hint="Timeline events are added automatically when you analyze evidence (e.g. Windows logs)." />;
  return (
    <div className="max-w-2xl space-y-2">
      {items.map((ev) => (
        <div key={ev.id} className="flex gap-3 bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
          <div className="text-[11px] text-oyster-muted font-mono whitespace-nowrap pt-0.5">
            {new Date(ev.timestamp).toLocaleString()}
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2"><SevBadge level={ev.severity} /><span className="text-sm text-oyster-text">{ev.event_type}</span></div>
            <p className="text-xs text-oyster-muted mt-0.5">{ev.description}</p>
            <span className="text-[10px] text-oyster-muted/70">{ev.source}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── IOCs ────────────────────────────────────────────────────────────────────

function IocsTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<socmat.Ioc[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(() => { socmat.getIocs(caseId).then(setItems).catch((e) => setErr(e.message)); }, [caseId]);
  useEffect(load, [load]);

  async function extract() {
    setBusy(true); setErr(null); setNote(null);
    try { const r = await socmat.extractIocs(caseId); setNote(`extracted ${r.extracted} IOC(s)`); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Extract failed"); }
    finally { setBusy(false); }
  }

  return (
    <div className="max-w-2xl space-y-3">
      {err && <Err msg={err} />}
      <div className="flex items-center gap-2">
        <button onClick={extract} disabled={busy} className={busyBtn}>
          {busy ? <><Loader2 size={14} className="animate-spin" /> Extracting…</> : <><Crosshair size={14} /> Extract IOCs</>}
        </button>
        {note && <span className="text-xs text-oyster-muted">{note}</span>}
      </div>
      {items === null ? <Loader2 className="animate-spin text-oyster-muted" />
        : items.length === 0 ? <Empty icon={Crosshair} title="No IOCs" hint="Extract indicators (IPs, domains, hashes, URLs) from this case's evidence and findings." />
        : (
          <div className="space-y-1.5">
            {items.map((io) => (
              <div key={io.id} className="flex items-center gap-2 bg-oyster-surface border border-oyster-border rounded-lg px-3 py-1.5">
                <span className="text-[10px] font-semibold uppercase text-oyster-accent bg-oyster-accent/10 px-1.5 py-0.5 rounded">{io.ioc_type}</span>
                <span className="text-sm text-oyster-text font-mono truncate">{io.value}</span>
                <span className="ml-auto text-[10px] text-oyster-muted">{io.confidence}</span>
              </div>
            ))}
          </div>
        )}
    </div>
  );
}

// ── MITRE ───────────────────────────────────────────────────────────────────

function MitreTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<socmat.MitreMapping[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => { socmat.getMitre(caseId).then(setItems).catch((e) => setErr(e.message)); }, [caseId]);
  useEffect(load, [load]);

  async function run() {
    setBusy(true); setErr(null);
    try { await socmat.runMitre(caseId); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Mapping failed"); }
    finally { setBusy(false); }
  }

  return (
    <div className="max-w-2xl space-y-3">
      {err && <Err msg={err} />}
      <button onClick={run} disabled={busy} className={busyBtn}>
        {busy ? <><Loader2 size={14} className="animate-spin" /> Mapping…</> : <><ShieldAlert size={14} /> Map to ATT&CK</>}
      </button>
      {items === null ? <Loader2 className="animate-spin text-oyster-muted" />
        : items.length === 0 ? <Empty icon={ShieldAlert} title="No ATT&CK mappings" hint="Map this case's detections to MITRE ATT&CK techniques and tactics." />
        : (
          <div className="space-y-2">
            {items.map((m) => (
              <div key={m.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-mono text-oyster-accent">{m.technique_id}</span>
                  <span className="text-sm text-oyster-text">{m.technique_name}</span>
                  <span className="ml-auto text-[10px] text-oyster-muted">{m.confidence}</span>
                </div>
                <p className="text-[11px] text-oyster-muted mt-0.5">Tactic: {m.tactic}</p>
              </div>
            ))}
          </div>
        )}
    </div>
  );
}

// ── AI Assistant ────────────────────────────────────────────────────────────

function AiTab({ caseId }: { caseId: number }) {
  const [analysis, setAnalysis] = useState<socmat.AIAnalysis | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"summarize" | "recommend" | null>(null);

  async function run(mode: "summarize" | "recommend") {
    setBusy(mode); setErr(null);
    try { setAnalysis(mode === "summarize" ? await socmat.aiSummarize(caseId) : await socmat.aiRecommend(caseId)); }
    catch (e) { setErr(e instanceof Error ? e.message : "AI call failed"); }
    finally { setBusy(null); }
  }

  return (
    <div className="max-w-2xl space-y-3">
      {err && <Err msg={err} />}
      <div className="flex items-center gap-2">
        <button onClick={() => run("summarize")} disabled={busy !== null} className={busyBtn}>
          {busy === "summarize" ? <><Loader2 size={14} className="animate-spin" /> Analyzing…</> : <><Sparkles size={14} /> Summarize case</>}
        </button>
        <button onClick={() => run("recommend")} disabled={busy !== null}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium border border-oyster-border text-oyster-text hover:bg-oyster-surface disabled:opacity-50 transition-colors">
          {busy === "recommend" ? <><Loader2 size={14} className="animate-spin" /> Thinking…</> : "Recommend next steps"}
        </button>
      </div>
      {analysis && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-[11px] text-oyster-muted">
            <span className="px-1.5 py-0.5 rounded bg-oyster-surface border border-oyster-border">{analysis.provider}</span>
            <span>confidence: {analysis.confidence}</span>
            <span>· {analysis.likely_incident_type}</span>
          </div>
          <div className="bg-oyster-surface border border-oyster-border rounded-xl px-4 py-3 prose prose-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{analysis.summary}</ReactMarkdown>
          </div>
          {analysis.key_evidence.length > 0 && (
            <Listing title="Key evidence" items={analysis.key_evidence} />
          )}
          {analysis.recommended_next_steps.length > 0 && (
            <Listing title="Recommended next steps" items={analysis.recommended_next_steps} />
          )}
          {analysis.missing_evidence.length > 0 && (
            <Listing title="Missing evidence" items={analysis.missing_evidence} />
          )}
          <p className="text-[10px] text-oyster-muted/70 italic">{analysis.disclaimer}</p>
        </div>
      )}
      {!analysis && busy === null && (
        <Empty icon={Sparkles} title="AI investigation assistant" hint="Grounded in this case's stored findings only, via Oyster's local model. Nothing leaves the machine." />
      )}
    </div>
  );
}

function Listing({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h4 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest mb-1.5">{title}</h4>
      <ul className="space-y-1">
        {items.map((it, i) => (
          <li key={i} className="text-sm text-oyster-text/90 flex gap-2"><span className="text-oyster-accent">•</span>{it}</li>
        ))}
      </ul>
    </div>
  );
}

// ── Report ──────────────────────────────────────────────────────────────────

function ReportTab({ caseId }: { caseId: number }) {
  const [content, setContent] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"gen" | "pdf" | null>(null);

  const loadContent = useCallback(() => {
    socmat.getReport(caseId)
      .then((r) => (r ? socmat.getReportContent(caseId).then(setContent) : setContent("")))
      .catch(() => setContent(""));
  }, [caseId]);
  useEffect(loadContent, [loadContent]);

  async function generate() {
    setBusy("gen"); setErr(null);
    try { await socmat.generateReport(caseId); loadContent(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Generate failed"); }
    finally { setBusy(null); }
  }
  async function pdf() {
    setBusy("pdf"); setErr(null);
    try { await socmat.downloadReportPdf(caseId); }
    catch (e) { setErr(e instanceof Error ? e.message : "PDF failed"); }
    finally { setBusy(null); }
  }

  return (
    <div className="max-w-3xl space-y-3">
      {err && <Err msg={err} />}
      <div className="flex items-center gap-2">
        <button onClick={generate} disabled={busy !== null} className={busyBtn}>
          {busy === "gen" ? <><Loader2 size={14} className="animate-spin" /> Generating…</> : <><RefreshCw size={14} /> Generate report</>}
        </button>
        <button onClick={pdf} disabled={busy !== null}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium border border-oyster-border text-oyster-text hover:bg-oyster-surface disabled:opacity-50 transition-colors">
          {busy === "pdf" ? <><Loader2 size={14} className="animate-spin" /> …</> : <><Download size={14} /> PDF</>}
        </button>
      </div>
      {content === null ? <Loader2 className="animate-spin text-oyster-muted" />
        : content === "" ? <Empty icon={ScrollText} title="No report yet" hint="Generate a Markdown incident report from this case's findings; download it as PDF." />
        : (
          <div className="bg-oyster-surface border border-oyster-border rounded-xl px-5 py-4 prose prose-sm">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
          </div>
        )}
    </div>
  );
}

// ── Network (PCAP / Zeek / Suricata) ────────────────────────────────────────

function NetworkTab({ caseId }: { caseId: number }) {
  const [evidence, setEvidence] = useState<socmat.Evidence[]>([]);
  const [pcap, setPcap] = useState<socmat.PcapResult[]>([]);
  const [zeek, setZeek] = useState<socmat.ZeekResult[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(() => {
    socmat.getEvidence(caseId).then(setEvidence).catch(() => {});
    socmat.getPcap(caseId).then(setPcap).catch(() => {});
    socmat.getZeek(caseId).then(setZeek).catch(() => {});
  }, [caseId]);
  useEffect(load, [load]);

  async function run(kind: "pcap" | "zeek" | "suricata", evId: number) {
    setBusy(`${kind}-${evId}`); setErr(null); setNote(null);
    try {
      if (kind === "pcap") { const r = await socmat.runPcap(caseId, evId); setNote(`PCAP: ${r.total_packets} pkts, risk ${r.risk_score}, ${r.findings.length} finding(s)`); }
      else if (kind === "zeek") { const r = await socmat.runZeek(caseId, evId); setNote(`Zeek: ${r.total_records} records, risk ${r.risk_score}`); }
      else { const r = await socmat.runSuricata(caseId, evId); setNote(`Suricata: ${r.total_alerts} alerts, ${r.unique_signatures} signatures`); }
      load();
    } catch (e) { setErr(e instanceof Error ? e.message : "Analysis failed"); }
    finally { setBusy(null); }
  }

  return (
    <div className="max-w-3xl space-y-4">
      {err && <Err msg={err} />}
      {note && <p className="text-xs text-oyster-muted">{note}</p>}
      <section className="space-y-2">
        <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">Analyze evidence</h3>
        {evidence.length === 0 ? <p className="text-xs text-oyster-muted">Upload PCAP or Zeek/Suricata logs in the Evidence tab first.</p>
          : evidence.map((ev) => (
            <div key={ev.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2"><FileText size={13} className="text-oyster-muted" /><span className="text-sm text-oyster-text truncate">{ev.original_filename}</span></div>
              <div className="flex gap-2 mt-2">
                {(["pcap", "zeek", "suricata"] as const).map((k) => (
                  <button key={k} onClick={() => run(k, ev.id)} disabled={busy !== null}
                    className="text-[11px] px-2 py-1 rounded-md border border-oyster-border text-oyster-muted hover:text-oyster-text hover:bg-oyster-bg/60 disabled:opacity-50 transition-colors">
                    {busy === `${k}-${ev.id}` ? "…" : k.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
          ))}
      </section>
      {pcap.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">PCAP results</h3>
          {pcap.map((p) => (
            <div key={p.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2"><Network size={13} className={p.risk_score > 0 ? "text-orange-400" : "text-oyster-muted"} /><span className="text-sm text-oyster-text truncate">{p.original_filename}</span><span className="ml-auto text-[11px] text-oyster-muted">risk {p.risk_score}</span></div>
              <p className="text-xs text-oyster-muted mt-1">{p.summary}</p>
              {p.findings.slice(0, 4).map((f, i) => <div key={i} className="text-[11px] text-oyster-muted/90 mt-1 flex gap-1.5"><SevBadge level={f.severity} /> {f.description}</div>)}
            </div>
          ))}
        </section>
      )}
      {zeek.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">Zeek results</h3>
          {zeek.map((z) => (
            <div key={z.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <div className="flex items-center gap-2"><Network size={13} className={z.risk_score > 0 ? "text-orange-400" : "text-oyster-muted"} /><span className="text-sm text-oyster-text truncate">{z.original_filename}</span><span className="ml-auto text-[11px] text-oyster-muted">{z.log_type} · risk {z.risk_score}</span></div>
              <p className="text-xs text-oyster-muted mt-1">{z.summary}</p>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}

// ── Correlation ─────────────────────────────────────────────────────────────

function CorrelationTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<socmat.CorrelatedFinding[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { socmat.getCorrelation(caseId).then(setItems).catch((e) => setErr(e.message)); }, [caseId]);
  useEffect(load, [load]);
  async function run() { setBusy(true); setErr(null); try { await socmat.runCorrelation(caseId); load(); } catch (e) { setErr(e instanceof Error ? e.message : "Correlation failed"); } finally { setBusy(false); } }
  return (
    <div className="max-w-2xl space-y-3">
      {err && <Err msg={err} />}
      <button onClick={run} disabled={busy} className={busyBtn}>{busy ? <><Loader2 size={14} className="animate-spin" /> Correlating…</> : <><Link2 size={14} /> Run correlation</>}</button>
      {items === null ? <Loader2 className="animate-spin text-oyster-muted" />
        : items.length === 0 ? <Empty icon={Link2} title="No correlated findings" hint="Correlation links detections that share entities (hosts, users, IPs) into higher-confidence findings." />
        : items.map((f) => (
          <div key={f.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
            <div className="flex items-center gap-2 flex-wrap"><SevBadge level={f.severity} /><span className="text-sm text-oyster-text">{f.title}</span><span className="ml-auto text-[10px] text-oyster-muted">{f.confidence}</span></div>
            <p className="text-xs text-oyster-muted mt-1">{f.summary}</p>
            {f.entities.length > 0 && <div className="flex flex-wrap gap-1 mt-1.5">{f.entities.map((e, i) => <span key={i} className="text-[10px] font-mono bg-oyster-bg border border-oyster-border rounded px-1.5 py-0.5 text-oyster-muted">{e.type}:{e.value}</span>)}</div>}
            {f.recommended_action && <p className="text-[11px] text-oyster-accent mt-1.5">→ {f.recommended_action}</p>}
          </div>
        ))}
    </div>
  );
}

// ── Entity graph ────────────────────────────────────────────────────────────

function GraphTab({ caseId }: { caseId: number }) {
  const [g, setG] = useState<socmat.GraphResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { socmat.getGraph(caseId).then(setG).catch((e) => setErr(e.message)); }, [caseId]);
  if (err) return <Err msg={err} />;
  if (!g) return <Loader2 className="animate-spin text-oyster-muted" />;
  if (g.nodes.length === 0) return <Empty icon={Share2} title="Empty entity graph" hint="The graph links this case's hosts, users, IPs, processes, detections and IOCs as evidence accrues." />;
  const byType: Record<string, socmat.GraphNode[]> = {};
  for (const n of g.nodes) (byType[n.type] ??= []).push(n);
  return (
    <div className="max-w-3xl space-y-4">
      <div className="flex gap-4 text-xs text-oyster-muted">
        <span><span className="text-oyster-text font-semibold">{g.metadata.total_nodes}</span> nodes</span>
        <span><span className="text-oyster-text font-semibold">{g.metadata.total_edges}</span> edges</span>
      </div>
      {Object.entries(byType).map(([type, nodes]) => (
        <section key={type} className="space-y-1.5">
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">{type} ({nodes.length})</h3>
          <div className="flex flex-wrap gap-1.5">
            {nodes.map((n) => (
              <span key={n.id} className={`text-[11px] rounded-lg px-2 py-1 border ${SEV_CLASS[n.severity?.toLowerCase()] ?? "bg-oyster-surface border-oyster-border text-oyster-text"}`}>{n.label}</span>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

// ── Coverage + telemetry gaps ───────────────────────────────────────────────

function CoverageTab({ caseId }: { caseId: number }) {
  const [cov, setCov] = useState<socmat.CaseCoverage | null>(null);
  const [gaps, setGaps] = useState<socmat.TelemetryGap[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    socmat.getCoverage(caseId).then(setCov).catch((e) => setErr(e.message));
    socmat.getTelemetryGaps(caseId).then((r) => setGaps(r.gaps)).catch(() => {});
  }, [caseId]);
  if (err) return <Err msg={err} />;
  if (!cov) return <Loader2 className="animate-spin text-oyster-muted" />;
  return (
    <div className="max-w-2xl space-y-4">
      <div className="bg-oyster-surface border border-oyster-border rounded-xl px-4 py-3">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-oyster-text">ATT&CK coverage</span>
          <span className="text-sm font-semibold text-oyster-accent">{cov.coverage_percent}%</span>
        </div>
        <div className="h-2 rounded-full bg-oyster-bg overflow-hidden"><div className="h-full bg-oyster-accent" style={{ width: `${cov.coverage_percent}%` }} /></div>
        <p className="text-[11px] text-oyster-muted mt-2">{cov.mitre_covered_techniques}/{cov.mitre_total_techniques} techniques · {cov.rules_triggered.length} rules triggered · {cov.rules_blocked.length} blocked by missing data</p>
      </div>
      {cov.missing_log_sources.length > 0 && (
        <div className="text-xs text-oyster-muted"><span className="font-semibold text-oyster-text">Missing log sources:</span> {cov.missing_log_sources.join(", ")}</div>
      )}
      {gaps.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest">Telemetry gaps</h3>
          {gaps.map((g, i) => (
            <div key={i} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
              <p className="text-sm text-oyster-text">{g.missing_log_source}</p>
              <p className="text-xs text-oyster-muted mt-0.5">{g.why_it_matters}</p>
              <p className="text-[11px] text-oyster-accent mt-1">→ {g.recommendation}</p>
            </div>
          ))}
        </section>
      )}
    </div>
  );
}

// ── Playbooks ───────────────────────────────────────────────────────────────

function PlaybooksTab({ caseId }: { caseId: number }) {
  const [data, setData] = useState<{ playbooks: socmat.CasePlaybook[]; suggestions: socmat.PlaybookSuggestion[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { socmat.getCasePlaybooks(caseId).then(setData).catch((e) => setErr(e.message)); }, [caseId]);
  useEffect(load, [load]);
  async function attach(tid: number) { setBusy(true); setErr(null); try { await socmat.attachPlaybook(caseId, tid); load(); } catch (e) { setErr(e instanceof Error ? e.message : "Attach failed"); } finally { setBusy(false); } }
  async function toggleStep(pbId: number, s: socmat.PlaybookStep) {
    const next = s.status === "done" ? "pending" : "done";
    try { await socmat.updatePlaybookStep(caseId, pbId, s.id, { status: next }); load(); } catch (e) { setErr(e instanceof Error ? e.message : "Update failed"); }
  }
  if (err) return <Err msg={err} />;
  if (!data) return <Loader2 className="animate-spin text-oyster-muted" />;
  return (
    <div className="max-w-2xl space-y-4">
      {data.suggestions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {data.suggestions.map((s) => (
            <button key={s.template_id} onClick={() => attach(s.template_id)} disabled={busy}
              className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border border-oyster-accent/40 text-oyster-accent hover:bg-oyster-accent/10 disabled:opacity-50 transition-colors">
              <Plus size={12} /> {s.name}
            </button>
          ))}
        </div>
      )}
      {data.playbooks.length === 0 ? <Empty icon={ListChecks} title="No playbooks attached" hint="Attach an investigation playbook to work a structured checklist for this alert type." />
        : data.playbooks.map((pb) => (
          <div key={pb.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-3">
            <div className="flex items-center gap-2 mb-2"><ListChecks size={14} className="text-oyster-accent" /><span className="text-sm text-oyster-text font-medium">{pb.name}</span><span className="ml-auto text-[11px] text-oyster-muted">{pb.progress_percent}%</span></div>
            <div className="space-y-1">
              {pb.steps.map((s) => (
                <button key={s.id} onClick={() => toggleStep(pb.id, s)} className="w-full flex items-start gap-2 text-left px-2 py-1.5 rounded-lg hover:bg-oyster-bg/50 transition-colors">
                  <CheckCircle2 size={14} className={`mt-0.5 shrink-0 ${s.status === "done" ? "text-green-500" : "text-oyster-muted/40"}`} />
                  <span className={`text-xs ${s.status === "done" ? "text-oyster-muted line-through" : "text-oyster-text"}`}>{s.step_order}. {s.title}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
    </div>
  );
}

// ── Dispositions ────────────────────────────────────────────────────────────

function DispositionsTab({ caseId }: { caseId: number }) {
  const [data, setData] = useState<{ dispositions: socmat.FindingDisposition[]; summary: socmat.DispositionSummary } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { socmat.getDispositions(caseId).then(setData).catch((e) => setErr(e.message)); }, [caseId]);
  if (err) return <Err msg={err} />;
  if (!data) return <Loader2 className="animate-spin text-oyster-muted" />;
  return (
    <div className="max-w-2xl space-y-3">
      <div className="flex flex-wrap gap-2 text-[11px]">
        <Chip label="Total" v={data.summary.total} />
        <Chip label="True +" v={data.summary.true_positive} cls="text-red-400" />
        <Chip label="False +" v={data.summary.false_positive} cls="text-sky-400" />
        <Chip label="Needs review" v={data.summary.needs_review} />
        <Chip label="Escalated" v={data.summary.escalated} cls="text-orange-400" />
      </div>
      {data.dispositions.length === 0 ? <Empty icon={CheckCircle2} title="No dispositions yet" hint="Triage detections as true/false positive, benign, escalated, etc. — dispositions summarise the case's verdicts." />
        : data.dispositions.map((d) => (
          <div key={d.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5">
            <div className="flex items-center gap-2"><span className="text-[10px] font-mono text-oyster-muted">{d.finding_type}:{d.finding_id}</span><span className="ml-auto text-[11px] font-medium text-oyster-accent">{d.disposition.replace(/_/g, " ")}</span></div>
            {d.reason && <p className="text-xs text-oyster-muted mt-1">{d.reason}</p>}
          </div>
        ))}
    </div>
  );
}
function Chip({ label, v, cls }: { label: string; v: number; cls?: string }) {
  return <span className="bg-oyster-surface border border-oyster-border rounded-lg px-2 py-1"><span className={`font-semibold ${cls ?? "text-oyster-text"}`}>{v}</span> <span className="text-oyster-muted">{label}</span></span>;
}

// ── Analyst notes ───────────────────────────────────────────────────────────

function NotesTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<socmat.AnalystNote[] | null>(null);
  const [body, setBody] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => { socmat.getNotes(caseId).then(setItems).catch((e) => setErr(e.message)); }, [caseId]);
  useEffect(load, [load]);
  async function add() {
    if (!body.trim() || busy) return;
    setBusy(true); setErr(null);
    try { await socmat.createNote(caseId, { entity_type: "case", note_type: "general", body: body.trim() }); setBody(""); load(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Save failed"); }
    finally { setBusy(false); }
  }
  return (
    <div className="max-w-2xl space-y-3">
      {err && <Err msg={err} />}
      <div className="flex gap-2">
        <input value={body} onChange={(e) => setBody(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} placeholder="Add an analyst note…"
          className="flex-1 bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50" />
        <button onClick={add} disabled={!body.trim() || busy} className={busyBtn}>{busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}</button>
      </div>
      {items === null ? <Loader2 className="animate-spin text-oyster-muted" />
        : items.length === 0 ? <Empty icon={StickyNote} title="No notes" hint="Record observations, hypotheses and decisions as you investigate." />
        : items.map((n) => (
          <div key={n.id} className="bg-oyster-surface border border-oyster-border rounded-xl px-3.5 py-2.5 group">
            <div className="flex items-start gap-2">
              <StickyNote size={13} className="text-oyster-muted mt-0.5 shrink-0" />
              <p className="text-sm text-oyster-text flex-1">{n.body}</p>
              <button onClick={() => socmat.deleteNote(caseId, n.id).then(load).catch(() => {})} className="opacity-0 group-hover:opacity-100 text-oyster-muted hover:text-red-400 transition-opacity"><Trash2 size={13} /></button>
            </div>
            <span className="text-[10px] text-oyster-muted/70">{new Date(n.created_at).toLocaleString()}</span>
          </div>
        ))}
    </div>
  );
}
