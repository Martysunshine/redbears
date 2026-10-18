"use client";

import { useEffect, useState } from "react";
import { Loader2, AlertCircle, Wand2, Copy, Check, Database, Search } from "lucide-react";
import * as socmat from "@/lib/socmat";

function Err({ msg }: { msg: string }) {
  return (
    <div className="flex items-start gap-2.5 bg-red-500/10 border border-red-500/30 rounded-xl px-3.5 py-2.5">
      <AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" />
      <p className="text-sm text-red-400">{msg}</p>
    </div>
  );
}

// ── Rule Authoring — deterministic Sigma/SPL/KQL/ES|QL generator ─────────────

export function RuleAuthoringView() {
  const [desc, setDesc] = useState("");
  const [draft, setDraft] = useState<socmat.RuleDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  async function generate() {
    if (!desc.trim() || busy) return;
    setBusy(true); setErr(null); setDraft(null);
    try { setDraft(await socmat.authorRules(desc.trim())); }
    catch (e) { setErr(e instanceof Error ? e.message : "Generation failed"); }
    finally { setBusy(false); }
  }
  async function copy(key: string, text: string) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500); } catch { /* no-op */ }
  }

  const queries = draft ? [
    { key: "sigma", label: "Sigma", code: draft.sigma_yaml },
    { key: "spl", label: "Splunk SPL", code: draft.spl_query },
    { key: "kql", label: "Elastic KQL", code: draft.kql_query },
    { key: "esql", label: "ES|QL", code: draft.esql_query },
  ] : [];

  return (
    <div className="max-w-3xl mx-auto px-4 py-6 space-y-4">
      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-oyster-text">Rule Authoring</h2>
        <p className="text-xs text-oyster-muted">Describe a behaviour to detect; get a Sigma rule plus Splunk / Elastic queries. Deterministic — no data leaves the machine.</p>
      </div>
      {err && <Err msg={err} />}
      <div className="flex gap-2">
        <input value={desc} onChange={(e) => setDesc(e.target.value)} onKeyDown={(e) => e.key === "Enter" && generate()}
          placeholder="e.g. PowerShell spawning from Office with encoded command"
          className="flex-1 bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50" />
        <button onClick={generate} disabled={!desc.trim() || busy}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white disabled:opacity-50 transition-colors">
          {busy ? <><Loader2 size={14} className="animate-spin" /> Drafting…</> : <><Wand2 size={14} /> Generate</>}
        </button>
      </div>
      {draft && (
        <div className="space-y-3">
          <div className="text-xs text-oyster-muted">
            Detected: <span className="text-oyster-text">{draft.event_type_label}</span>
            {draft.keyword_extracted && <> · keyword <span className="font-mono text-oyster-text">{draft.keyword_extracted}</span></>}
          </div>
          {queries.map((q) => q.code && (
            <div key={q.key} className="bg-oyster-surface border border-oyster-border rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-3 py-1.5 border-b border-oyster-border">
                <span className="text-[11px] font-medium text-oyster-muted">{q.label}</span>
                <button onClick={() => copy(q.key, q.code)} className="cursor-pointer flex items-center gap-1 text-[11px] text-oyster-muted hover:text-oyster-text transition-colors">
                  {copied === q.key ? <><Check size={12} className="text-green-500" /> Copied</> : <><Copy size={12} /> Copy</>}
                </button>
              </div>
              <pre className="px-3 py-2.5 text-[12px] text-oyster-text font-mono overflow-x-auto leading-relaxed whitespace-pre">{q.code}</pre>
            </div>
          ))}
          {draft.false_positives.length > 0 && (
            <div className="text-xs text-oyster-muted"><span className="font-semibold text-oyster-text">False positives:</span> {draft.false_positives.join("; ")}</div>
          )}
          {draft.validation_warnings.length > 0 && (
            <div className="text-xs text-yellow-500/90">{draft.validation_warnings.join(" · ")}</div>
          )}
          <p className="text-[10px] text-oyster-muted/70 italic">{draft.quality_disclaimer}</p>
        </div>
      )}
    </div>
  );
}

// ── Live SIEM — Splunk + Elastic (env-gated, honest disabled state) ─────────

export function LiveSiemView() {
  return (
    <div className="max-w-3xl mx-auto px-4 py-6 space-y-6">
      <LiveConnector kind="splunk" />
      <LiveConnector kind="elastic" />
    </div>
  );
}

function LiveConnector({ kind }: { kind: "splunk" | "elastic" }) {
  const [status, setStatus] = useState<socmat.SplunkLiveStatus | socmat.ElasticLiveStatus | null>(null);
  const [q, setQ] = useState("");
  const [result, setResult] = useState<socmat.LiveQuery | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    (kind === "splunk" ? socmat.getSplunkStatus() : socmat.getElasticStatus())
      .then(setStatus).catch((e) => setErr(e.message));
  }, [kind]);

  async function run() {
    if (!q.trim() || busy) return;
    setBusy(true); setErr(null); setResult(null);
    try { setResult(kind === "splunk" ? await socmat.runSplunkSearch(q.trim()) : await socmat.runElasticSearch(q.trim())); }
    catch (e) { setErr(e instanceof Error ? e.message : "Query failed"); }
    finally { setBusy(false); }
  }

  const configured = status?.configured ?? false;
  const connected = status?.connected ?? false;
  const label = kind === "splunk" ? "Splunk" : "Elasticsearch";
  const placeholder = kind === "splunk" ? "search index=* | head 20" : "FROM logs-* | LIMIT 20";
  const envHint = kind === "splunk" ? "SPLUNK_URL + SPLUNK_TOKEN" : "ELASTIC_URL + ELASTIC_API_KEY";

  return (
    <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Database size={15} className="text-oyster-muted" />
        <span className="text-sm font-medium text-oyster-text">{label}</span>
        <span className={`ml-auto flex items-center gap-1.5 text-[11px] px-2 py-0.5 rounded-md border ${
          connected ? "text-green-400 border-green-500/30 bg-green-500/10" : configured ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" : "text-oyster-muted border-oyster-border bg-oyster-bg"
        }`}>
          <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-green-500" : configured ? "bg-yellow-500" : "bg-oyster-muted"}`} />
          {connected ? "connected" : configured ? "configured" : "not configured"}
        </span>
      </div>
      {err && <Err msg={err} />}
      {!configured ? (
        <p className="text-xs text-oyster-muted">
          Read-only live queries are disabled until <span className="font-mono text-oyster-text">{envHint}</span> are set in the backend environment. This connector never writes.
        </p>
      ) : (
        <>
          <div className="flex gap-2">
            <input value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && run()} placeholder={placeholder}
              className="flex-1 bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text font-mono placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50" />
            <button onClick={run} disabled={!q.trim() || busy}
              className="flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-medium bg-oyster-accent hover:bg-oyster-accent-hover text-white disabled:opacity-50 transition-colors">
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            </button>
          </div>
          {result && (
            <div className="space-y-1.5">
              <p className="text-[11px] text-oyster-muted">{result.result_count} result(s) · {result.status}{result.error_message ? ` · ${result.error_message}` : ""}</p>
              {result.result_sample && <pre className="bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-[11px] text-oyster-text font-mono overflow-x-auto max-h-64">{result.result_sample}</pre>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
