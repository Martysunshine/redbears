"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Terminal, PanelLeftOpen, Loader2, AlertCircle, ShieldCheck, ShieldAlert, ShieldX,
  Play, Check, X, Power, StopCircle, FileText, Bug, ScrollText, ChevronRight, Clock,
} from "lucide-react";
import {
  listExecutionTools, setExecutionToolEnabled, createProposal, approveProposal,
  rejectProposal, executeProposal, getExecution, cancelExecution, listExecutionAudit,
  type ExecutionTool, type ToolActionDef, type PolicyDecision, type ExecutionProposal,
  type ToolExecution, type ExecutionOutput, type Observation, type AuditEvent,
} from "@/lib/api";

interface Props {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  activeProjectName: string;
}

const RISK_CLS: Record<string, string> = {
  informational: "text-sky-300 bg-sky-500/10 border-sky-500/20",
  low: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20",
  medium: "text-amber-300 bg-amber-500/10 border-amber-500/20",
  high: "text-red-300 bg-red-500/10 border-red-500/20",
  critical: "text-red-300 bg-red-500/10 border-red-500/20",
};

const STATUS_CLS: Record<string, string> = {
  succeeded: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20",
  completed: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20",
  running: "text-sky-300 bg-sky-500/10 border-sky-500/20",
  awaiting_approval: "text-amber-300 bg-amber-500/10 border-amber-500/20",
  blocked: "text-red-300 bg-red-500/10 border-red-500/20",
  failed: "text-red-300 bg-red-500/10 border-red-500/20",
  timed_out: "text-red-300 bg-red-500/10 border-red-500/20",
  cancelled: "text-oyster-muted bg-oyster-surface border-oyster-border",
};

const SEV_CLS: Record<string, string> = {
  high: "text-red-300", critical: "text-red-300", medium: "text-amber-300",
  low: "text-sky-300", info: "text-oyster-muted",
};

type Tab = "raw" | "parsed" | "evidence" | "audit";

export function ExecutionPanel({ onToggleSidebar, sidebarOpen, activeProjectName }: Props) {
  const [tools, setTools] = useState<ExecutionTool[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [toolId, setToolId] = useState("");
  const [actionId, setActionId] = useState("");
  const [target, setTarget] = useState("http://127.0.0.1:8001/health");
  const [params, setParams] = useState<Record<string, string>>({});
  const [objective, setObjective] = useState("");

  const [proposal, setProposal] = useState<ExecutionProposal | null>(null);
  const [policy, setPolicy] = useState<PolicyDecision | null>(null);
  const [execution, setExecution] = useState<ToolExecution | null>(null);
  const [output, setOutput] = useState<ExecutionOutput | null>(null);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [tab, setTab] = useState<Tab>("parsed");
  const [busy, setBusy] = useState<string | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const tool = tools.find((t) => t.id === toolId);
  const action: ToolActionDef | undefined = tool?.actions.find((a) => a.id === actionId);

  const refreshTools = useCallback(async () => {
    try {
      const d = await listExecutionTools();
      setTools(d.tools);
      setError(null);
      if (!toolId && d.tools.length) {
        setToolId(d.tools[0].id);
        setActionId(d.tools[0].actions[0]?.id ?? "");
      }
    } catch {
      setError("Cannot reach the backend on :8001.");
    } finally {
      setLoading(false);
    }
  }, [toolId]);

  const refreshAudit = useCallback(async () => {
    try { setAudit((await listExecutionAudit()).audit); } catch { /* ignore */ }
  }, []);

  useEffect(() => { refreshTools(); refreshAudit(); }, [refreshTools, refreshAudit]);
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  // reset params when action changes
  useEffect(() => { setParams({}); }, [toolId, actionId]);

  function resetRun() {
    setProposal(null); setPolicy(null); setExecution(null);
    setOutput(null); setObservations([]);
  }

  async function handlePropose() {
    if (!tool || !action) return;
    setBusy("propose"); setError(null); resetRun();
    try {
      const coerced: Record<string, unknown> = {};
      Object.entries(params).forEach(([k, v]) => { if (v !== "") coerced[k] = v; });
      const r = await createProposal({
        tool_id: tool.id, action_id: action.id, targets: target.trim() ? [target.trim()] : [],
        parameters: coerced, objective: objective.trim(),
      });
      setProposal(r.proposal); setPolicy(r.policy); setTab("parsed");
      refreshAudit();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Proposal failed");
    } finally { setBusy(null); }
  }

  async function handleApprove() {
    if (!proposal) return;
    setBusy("approve");
    try {
      await approveProposal(proposal.id);
      setProposal({ ...proposal, status: "approved" });
      refreshAudit();
    } catch (e) { setError(e instanceof Error ? e.message : "Approve failed"); }
    finally { setBusy(null); }
  }

  async function handleReject() {
    if (!proposal) return;
    setBusy("reject");
    try { await rejectProposal(proposal.id); setProposal({ ...proposal, status: "rejected" }); refreshAudit(); }
    catch (e) { setError(e instanceof Error ? e.message : "Reject failed"); }
    finally { setBusy(null); }
  }

  async function handleExecute() {
    if (!proposal) return;
    setBusy("execute"); setError(null);
    setExecution({ ...(execution ?? {} as ToolExecution), status: "running" } as ToolExecution);
    try {
      const r = await executeProposal(proposal.id);
      setExecution(r.execution); setOutput(r.output); setObservations(r.observations);
      setTab(r.observations.length ? "parsed" : "raw");
      refreshAudit();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Execution refused");
      setExecution(null);
    } finally { setBusy(null); }
  }

  async function handleCancel() {
    if (!execution?.id) return;
    try { await cancelExecution(execution.id); const v = await getExecution(execution.id); setExecution(v.execution); }
    catch { /* ignore */ }
  }

  async function handleToggleTool(t: ExecutionTool) {
    setBusy(t.id);
    try { await setExecutionToolEnabled(t.id, !t.enabled); await refreshTools(); }
    finally { setBusy(null); }
  }

  const decisionBadge = (d: PolicyDecision) => {
    if (d.decision === "allow") return { icon: ShieldCheck, cls: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20", label: "Allowed" };
    if (d.decision === "requires_approval") return { icon: ShieldAlert, cls: "text-amber-300 bg-amber-500/10 border-amber-500/20", label: "Approval required" };
    return { icon: ShieldX, cls: "text-red-300 bg-red-500/10 border-red-500/20", label: "Blocked" };
  };

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      {/* Header — ALWAYS shows the active mode */}
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button onClick={onToggleSidebar} className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface">
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Terminal size={15} className="text-oyster-accent shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Execute</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          authorized tool execution
        </span>
        <div className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border">
          <ShieldCheck size={12} className="text-oyster-accent" /> {activeProjectName}
        </div>
      </header>

      {error && (
        <div className="mx-4 mt-3 flex items-center gap-2 text-[12px] text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          <AlertCircle size={14} /> {error}
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-4 py-5">
        <div className="max-w-5xl mx-auto mb-4">
          <ExecuteExplainer />
        </div>
        <div className="max-w-5xl mx-auto grid grid-cols-1 lg:grid-cols-[1.1fr_1fr] gap-5">
          {/* LEFT: tools + proposal builder */}
          <div className="space-y-4">
            {/* Tool availability */}
            <section className="bg-oyster-surface border border-oyster-border rounded-xl p-4">
              <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider mb-2.5">Tool registry</h3>
              {loading ? (
                <div className="flex justify-center py-6 text-oyster-muted"><Loader2 size={18} className="animate-spin" /></div>
              ) : (
                <div className="space-y-1.5">
                  {tools.map((t) => (
                    <div key={t.id} className={`flex items-center gap-2 p-2 rounded-lg border ${toolId === t.id ? "border-oyster-accent/40 bg-oyster-accent/5" : "border-oyster-border"}`}>
                      <button onClick={() => { setToolId(t.id); setActionId(t.actions[0]?.id ?? ""); }} className="flex-1 flex items-center gap-2 text-left min-w-0">
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${t.availability.available ? "bg-green-500" : "bg-oyster-muted"}`} />
                        <span className="text-[13px] text-oyster-text font-medium truncate">{t.name}</span>
                        {!t.availability.available && <span className="text-[9px] uppercase text-oyster-muted border border-oyster-border rounded px-1">unavailable</span>}
                        {t.enabled === false && <span className="text-[9px] uppercase text-oyster-muted border border-oyster-border rounded px-1">disabled</span>}
                      </button>
                      {t.availability.available && (
                        <button onClick={() => handleToggleTool(t)} disabled={busy === t.id}
                          title={t.enabled ? "Disable for this project" : "Enable"}
                          className={`p-1 rounded ${t.enabled ? "text-green-400 hover:bg-green-500/10" : "text-oyster-muted hover:text-oyster-text"}`}>
                          <Power size={13} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
              {tool && !tool.availability.available && (
                <p className="mt-2 text-[11px] text-oyster-muted leading-relaxed">
                  {tool.availability.reason} {tool.install_hint && <span className="block mt-1 text-oyster-text/70">Install: <code>{tool.install_hint}</code></span>}
                </p>
              )}
            </section>

            {/* Proposal builder */}
            <section className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-3">
              <h3 className="text-[11px] font-semibold text-oyster-muted uppercase tracking-wider">Build execution proposal</h3>
              <div>
                <label className="text-[11px] text-oyster-muted">Action</label>
                <select value={actionId} onChange={(e) => setActionId(e.target.value)}
                  className="mt-1 w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-[13px] text-oyster-text outline-none">
                  {(tool?.actions ?? []).map((a) => (
                    <option key={a.id} value={a.id}>{a.name} · class {a.execution_class} ({a.risk_level})</option>
                  ))}
                </select>
                {action && <p className="mt-1 text-[11px] text-oyster-muted">{action.description}</p>}
              </div>

              {action && action.target_types.includes("none") ? null : (
                <div>
                  <label className="text-[11px] text-oyster-muted">Target</label>
                  <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="http://127.0.0.1:8001/health"
                    className="mt-1 w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-[13px] text-oyster-text outline-none font-mono" />
                </div>
              )}

              {/* dynamic params */}
              {action && Object.entries(action.param_schema).map(([name, spec]) => (
                <div key={name}>
                  <label className="text-[11px] text-oyster-muted">{name} <span className="opacity-60">({spec.type})</span></label>
                  {spec.enum ? (
                    <select value={params[name] ?? String(spec.default ?? "")} onChange={(e) => setParams((p) => ({ ...p, [name]: e.target.value }))}
                      className="mt-1 w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-[13px] text-oyster-text outline-none">
                      {spec.enum.map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : (
                    <input value={params[name] ?? ""} placeholder={String(spec.default ?? "")}
                      onChange={(e) => setParams((p) => ({ ...p, [name]: e.target.value }))}
                      className="mt-1 w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-[13px] text-oyster-text outline-none font-mono" />
                  )}
                </div>
              ))}

              <div>
                <label className="text-[11px] text-oyster-muted">Objective (optional)</label>
                <input value={objective} onChange={(e) => setObjective(e.target.value)} placeholder="Why this action is needed"
                  className="mt-1 w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-[13px] text-oyster-text outline-none" />
              </div>

              <button onClick={handlePropose} disabled={busy === "propose" || !action}
                className="w-full flex items-center justify-center gap-2 bg-oyster-accent hover:bg-oyster-accent-hover text-white rounded-lg py-2 text-[13px] font-medium disabled:opacity-50">
                {busy === "propose" ? <Loader2 size={14} className="animate-spin" /> : <ChevronRight size={14} />} Create proposal
              </button>
            </section>
          </div>

          {/* RIGHT: decision + approval + execution */}
          <div className="space-y-4">
            {!proposal && !policy && (
              <section className="bg-oyster-surface border border-oyster-border rounded-xl p-6 text-center text-oyster-muted">
                <ShieldCheck size={26} className="mx-auto mb-2 opacity-50" />
                <p className="text-[13px]">Build a proposal to see the deterministic scope + policy decision.</p>
                <p className="text-[11px] mt-1">The model can propose — it can never run an unrestricted shell.</p>
              </section>
            )}

            {/* Policy decision */}
            {policy && (() => {
              const b = decisionBadge(policy); const Icon = b.icon;
              return (
                <section className={`border rounded-xl p-4 ${b.cls}`}>
                  <div className="flex items-center gap-2 mb-2">
                    <Icon size={16} /> <span className="text-[13px] font-semibold">{b.label}</span>
                    {proposal && <span className={`ml-auto text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded border ${RISK_CLS[proposal.risk_level] ?? ""}`}>{proposal.risk_level} risk</span>}
                  </div>
                  {proposal && (
                    <div className="text-[11px] font-mono text-oyster-text bg-oyster-bg/60 rounded-lg px-2.5 py-1.5 mb-2 break-all">
                      {proposal.sanitized_command}
                    </div>
                  )}
                  <ul className="space-y-1 text-[11px] leading-relaxed">
                    {policy.reasons.map((r, i) => <li key={i} className="flex gap-1.5"><span className="opacity-60">·</span><span>{r}</span></li>)}
                  </ul>
                  {policy.matched_scope_entries.length > 0 && (
                    <p className="mt-2 text-[11px]">Scope rule: <code className="text-oyster-text">{policy.matched_scope_entries.join(", ")}</code></p>
                  )}
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[10px] opacity-80">
                    <span>timeout {policy.maximum_runtime}s</span>
                    <span>max output {(policy.maximum_output_size / 1024).toFixed(0)} KB</span>
                    {proposal && <span>expires {new Date(proposal.expires_at).toLocaleTimeString()}</span>}
                  </div>
                </section>
              );
            })()}

            {/* Approval card */}
            {proposal && policy?.decision === "requires_approval" && ["awaiting_approval", "approved"].includes(proposal.status) && (
              <section className="bg-oyster-surface border border-amber-500/30 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert size={15} className="text-amber-300" />
                  <span className="text-[13px] font-semibold text-oyster-text">Human approval</span>
                  <span className={`ml-auto text-[10px] uppercase px-1.5 py-0.5 rounded border ${STATUS_CLS[proposal.status] ?? ""}`}>{proposal.status.replace(/_/g, " ")}</span>
                </div>
                <dl className="text-[11px] grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 mb-3">
                  <dt className="text-oyster-muted">Tool</dt><dd className="text-oyster-text">{proposal.tool_id}.{proposal.action_id}</dd>
                  <dt className="text-oyster-muted">Target</dt><dd className="text-oyster-text break-all">{proposal.targets.join(", ") || "—"}</dd>
                  <dt className="text-oyster-muted">Risk</dt><dd className="text-oyster-text">{proposal.risk_level} · class {proposal.execution_class}</dd>
                  <dt className="text-oyster-muted">Effect</dt><dd className="text-oyster-text">{proposal.network_required ? "network request to target" : "local only"}</dd>
                  <dt className="text-oyster-muted">Cleanup</dt><dd className="text-oyster-text">{proposal.cleanup_required ? "required" : "none"}</dd>
                </dl>
                {proposal.status === "awaiting_approval" ? (
                  <div className="flex gap-2">
                    <button onClick={handleApprove} disabled={busy === "approve"}
                      className="flex-1 flex items-center justify-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg py-1.5 text-[12px] font-medium disabled:opacity-50">
                      {busy === "approve" ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />} Approve
                    </button>
                    <button onClick={handleReject} disabled={busy === "reject"}
                      className="flex-1 flex items-center justify-center gap-1.5 border border-oyster-border text-oyster-muted hover:text-red-300 hover:border-red-400/40 rounded-lg py-1.5 text-[12px] font-medium">
                      <X size={13} /> Reject
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 text-[12px] text-emerald-300"><Check size={14} /> Approved — ready to execute</div>
                )}
              </section>
            )}

            {/* Execute button */}
            {proposal && ["approved"].includes(proposal.status) && !execution && (
              <button onClick={handleExecute} disabled={busy === "execute"}
                className="w-full flex items-center justify-center gap-2 bg-oyster-accent hover:bg-oyster-accent-hover text-white rounded-lg py-2.5 text-[13px] font-medium disabled:opacity-50">
                {busy === "execute" ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Execute now
              </button>
            )}

            {/* Live execution + output */}
            {execution && (
              <section className="bg-oyster-surface border border-oyster-border rounded-xl overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-oyster-border">
                  {execution.status === "running" ? <Loader2 size={14} className="animate-spin text-sky-300" /> : <Terminal size={14} className="text-oyster-muted" />}
                  <span className="text-[13px] font-medium text-oyster-text">Execution</span>
                  <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${STATUS_CLS[execution.status] ?? "text-oyster-muted bg-oyster-surface border-oyster-border"}`}>
                    {execution.status.replace(/_/g, " ")}
                  </span>
                  {execution.status === "running" && (
                    <button onClick={handleCancel} className="ml-auto flex items-center gap-1 text-[11px] text-red-300 hover:text-red-200">
                      <StopCircle size={13} /> Cancel
                    </button>
                  )}
                </div>

                {execution.output_hash && (
                  <div className="px-4 py-1.5 text-[10px] text-oyster-muted border-b border-oyster-border/60 flex flex-wrap gap-x-4">
                    <span>exit {execution.exit_code}</span>
                    {execution.tool_version && <span>{execution.tool_version}</span>}
                    <span className="font-mono">sha256 {execution.output_hash.slice(0, 16)}…</span>
                  </div>
                )}

                {/* tabs */}
                <div className="flex border-b border-oyster-border text-[11px]">
                  {([["parsed", "Parsed", FileText], ["raw", "Raw", ScrollText], ["evidence", "Evidence", Bug], ["audit", "Audit", Clock]] as [Tab, string, typeof FileText][]).map(([id, label, Icon]) => (
                    <button key={id} onClick={() => setTab(id)}
                      className={`flex items-center gap-1.5 px-3 py-2 ${tab === id ? "text-oyster-accent border-b-2 border-oyster-accent -mb-px" : "text-oyster-muted hover:text-oyster-text"}`}>
                      <Icon size={12} /> {label}
                    </button>
                  ))}
                </div>

                <div className="p-3 max-h-[320px] overflow-y-auto">
                  {tab === "parsed" && (
                    observations.length ? (
                      <ul className="space-y-1.5">
                        {observations.map((o, i) => (
                          <li key={i} className="flex items-start gap-2 text-[12px]">
                            <span className={`mt-0.5 text-[9px] uppercase ${SEV_CLS[o.severity] ?? "text-oyster-muted"}`}>{o.severity}</span>
                            <div><span className="text-oyster-text">{o.title}</span>{o.detail && <span className="text-oyster-muted block text-[11px]">{o.detail}</span>}</div>
                          </li>
                        ))}
                      </ul>
                    ) : <p className="text-[12px] text-oyster-muted">No parsed observations.</p>
                  )}
                  {tab === "raw" && (
                    <pre className="text-[11px] text-oyster-muted whitespace-pre-wrap font-mono leading-relaxed">
                      {output?.stdout || output?.stderr || execution.error_summary || "(no output)"}
                      {output?.truncated && "\n… [truncated]"}
                    </pre>
                  )}
                  {tab === "evidence" && (
                    observations.length ? (
                      <p className="text-[12px] text-oyster-muted">{observations.length} evidence record(s) created from this run (chain-of-custody hash {execution.output_hash?.slice(0, 12)}…). See the Evidence store.</p>
                    ) : <p className="text-[12px] text-oyster-muted">No evidence minted.</p>
                  )}
                  {tab === "audit" && (
                    <ul className="space-y-1 text-[11px]">
                      {audit.slice(0, 12).map((a) => (
                        <li key={a.id} className="flex items-center gap-2">
                          <span className="text-oyster-muted/60 font-mono">{new Date(a.ts).toLocaleTimeString()}</span>
                          <span className="text-oyster-text">{a.event.replace(/_/g, " ")}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </section>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// A dismissible explainer so Execute doesn't read as "blind buttons": it names
// what the engine is, the 4-step flow, and why nmap/semgrep may be unavailable.
function ExecuteExplainer() {
  const [open, setOpen] = useState(true);
  useEffect(() => {
    try { if (localStorage.getItem("oyster.execute.explainer.dismissed") === "1") setOpen(false); } catch { /* no-op */ }
  }, []);
  function dismiss() {
    setOpen(false);
    try { localStorage.setItem("oyster.execute.explainer.dismissed", "1"); } catch { /* no-op */ }
  }
  if (!open) return null;
  return (
    <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4 relative">
      <button onClick={dismiss} aria-label="Dismiss" className="absolute right-2.5 top-2.5 text-oyster-muted hover:text-oyster-text"><X size={14} /></button>
      <div className="flex items-center gap-2 mb-1.5">
        <ShieldCheck size={15} className="text-oyster-accent" />
        <span className="text-sm font-medium text-oyster-text">What Execute does</span>
      </div>
      <p className="text-xs text-oyster-muted leading-relaxed">
        This runs <span className="text-oyster-text">real</span>, scope-checked, approval-gated security tools and stores hashed evidence — it is not a demo. The flow:
      </p>
      <ol className="text-xs text-oyster-muted mt-2 space-y-1">
        <li><span className="text-oyster-accent font-medium">1.</span> Pick a tool + action, enter an in-scope target → <span className="text-oyster-text">build a proposal</span>.</li>
        <li><span className="text-oyster-accent font-medium">2.</span> The engine returns a <span className="text-oyster-text">policy decision</span> (allow / needs approval / blocked, with reasons).</li>
        <li><span className="text-oyster-accent font-medium">3.</span> <span className="text-oyster-text">Approve</span> it (higher-risk actions require this).</li>
        <li><span className="text-oyster-accent font-medium">4.</span> <span className="text-oyster-text">Execute</span> → real run, parsed output, evidence + audit trail.</li>
      </ol>
      <p className="text-[11px] text-oyster-muted/80 mt-2 leading-relaxed">
        <span className="text-oyster-text">HTTP / TLS / File</span> tools work out of the box. <span className="text-oyster-text">Nmap / Semgrep</span> show “unavailable” until their binaries are installed on the server — output is never faked. If every tool 503s, an operator has set <span className="font-mono">OYSTER_EXECUTION_ENGINE_ENABLED=false</span>.
      </p>
    </div>
  );
}
