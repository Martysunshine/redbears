"use client";
import { useEffect, useState } from "react";
import { cancelResearch, getResearch, researchStatus, startResearch, validateResearchLab, type ResearchRun } from "@/lib/api";

const STARTER = "What evidence is needed to assess broken access control in a web application, and how can we validate whether our detection covers it?";
const button = "px-3 py-2 rounded-lg bg-oyster-accent text-white disabled:opacity-40 text-sm";

export function ResearchPanel() {
  const [question, setQuestion] = useState(STARTER);
  const [run, setRun] = useState<ResearchRun | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [config, setConfig] = useState<{missing: string[]; model: string; lab_available: boolean} | null>(null);
  const active = run?.status === "running" || run?.status === "lab_running";
  useEffect(() => {
    void researchStatus().then(setConfig).catch(e => setError(e.message));
    const id = sessionStorage.getItem("redbears-research-run");
    if (id) void getResearch(id).then(setRun).catch(() => sessionStorage.removeItem("redbears-research-run"));
  }, []);
  useEffect(() => {
    if (!run || !active) return;
    let stopped = false;
    const timer = setInterval(() => { void getResearch(run.id).then(r => { if (!stopped) setRun(r); }).catch(e => { if (!stopped) setError(e.message); }); }, 900);
    return () => { stopped = true; clearInterval(timer); };
  }, [run?.id, active]);
  async function perform(action: () => Promise<ResearchRun>) {
    setBusy(true); setError("");
    try { const r = await action(); setRun(r); sessionStorage.setItem("redbears-research-run", r.id); }
    catch(e) { setError(e instanceof Error ? e.message : "Research request failed"); }
    finally { setBusy(false); }
  }
  return <section className="space-y-4 border border-oyster-border rounded-xl p-4 bg-oyster-surface/40">
    <div><h2 className="text-lg font-semibold">Evidence-led investigation</h2><p className="text-xs text-oyster-muted">Token Factory reasoning · Tavily web research · optional isolated validation</p></div>
    {config && <p className="text-xs text-oyster-muted">{config.missing.length ? `Configure locally in .env or Integrations: ${config.missing.join(", ")}. No live research is possible until configured.` : `Research model: ${config.model}`}</p>}
    <form onSubmit={e => {e.preventDefault(); void perform(() => startResearch(question));}} className="space-y-3">
      <label htmlFor="research-question" className="text-sm">Research question</label>
      <textarea id="research-question" rows={4} value={question} onChange={e => setQuestion(e.target.value)} minLength={10} maxLength={3000} required className="w-full p-3 rounded-lg bg-oyster-bg border border-oyster-border text-sm" />
      <div className="flex flex-wrap gap-2"><button className={button} disabled={busy || active || question.trim().length < 10}>Start research</button>
      {active && run && <button type="button" className={button} disabled={busy || run.status === "lab_running"} onClick={() => void perform(() => cancelResearch(run.id))}>Cancel research</button>}</div>
    </form>
    {error && <p role="alert" className="text-red-300 text-sm">{error}</p>}
    {run && <>
      <p role="status" className="text-sm">{run.status.replaceAll("_", " ")} · {run.model || "model not configured"} · {run.usage.searches} searches · {run.usage.reads} page reads</p>
      <h3 className="font-medium">Actual activity</h3><ol className="space-y-2 text-xs text-oyster-muted max-h-72 overflow-y-auto" aria-label="Research activity">
        {run.events.map(e => <li key={e.seq}><span className="text-oyster-text">{e.seq}. {e.type.replaceAll("_", " ")}</span> — {String(e.summary ?? e.query ?? e.purpose ?? e.reason ?? e.detail ?? (Array.isArray(e.source_ids) ? e.source_ids.join(", ") : ""))}</li>)}
      </ol>
      {run.report && <div className="space-y-3"><h3 className="font-medium">Report</h3><p className="text-sm">{run.report.summary}</p>
        {run.report.claims.map((c,i) => <div key={i} className="border-l-2 border-oyster-accent pl-3 space-y-1"><p className="text-[11px] uppercase text-oyster-muted">{c.kind.replaceAll("_", " ")} · {c.support.replaceAll("_", " ")}</p><p className="text-sm">{c.text} {c.source_id && <a className="text-oyster-accent underline" href={`#research-${c.source_id}`}>[{c.source_id}]</a>}</p>{c.quote && <blockquote className="text-xs text-oyster-muted">“{c.quote}”</blockquote>}</div>)}
        <p className="text-xs text-oyster-muted">{run.report.support_note}</p>
        {run.report.scenario_id && <div className="space-y-2"><p className="text-sm">Proposed lab: {run.report.scenario_id} — {run.report.scenario_reason}</p><button className={button} disabled={busy || active || !!run.lab || run.status !== "completed" || !config?.lab_available} onClick={() => void perform(() => validateResearchLab(run.id))}>Validate in isolated Juice Shop lab</button></div>}
      </div>}
      {run.lab && <div className="rounded-lg border border-oyster-border p-3 space-y-2"><h3>Lab observation</h3><p className="text-sm">Simulation: {run.lab.simulation} · Baseline detection: {run.lab.detection}</p><p className="text-sm">Retest simulation: {run.lab.retest_simulation} · Improved detection: {run.lab.retest_detection}</p><p className="text-xs">Benign events: {run.lab.benign_events_checked} · False positive: {String(run.lab.false_positive_on_benign)}</p><p className="text-xs text-oyster-muted">{run.lab.limitations}</p></div>}
      <h3 className="font-medium">Evidence ledger</h3>{run.sources.map(s => <details id={`research-${s.id}`} key={s.id} className="text-xs border border-oyster-border rounded-lg p-3"><summary>[{s.id}] {s.title} · {s.extracted ? "page read" : "search snippet"}</summary><a href={s.url} target="_blank" rel="noopener noreferrer" className="text-oyster-accent break-all">{s.url}</a><p>Retrieved: {s.retrieved_at}{s.published_at && ` · Published: ${s.published_at}`}{s.updated_at && ` · Updated: ${s.updated_at}`}</p><blockquote className="whitespace-pre-wrap mt-2">{s.passage}</blockquote></details>)}
    </>}
    <p className="text-xs text-oyster-muted">Juice Shop is a deliberately vulnerable benchmark. Prior model knowledge cannot be ruled out. Scenario tools and detection rules are implemented in advance. IDOR ownership comes from the harness. Improving detection does not fix the application.</p>
  </section>;
}
