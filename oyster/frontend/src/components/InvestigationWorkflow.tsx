"use client";
import { ResearchPanel } from "./ResearchPanel";

// The investigation workflow tab inside Red Bears: Research -> Investigate ->
// Prepare lab -> Validate -> Detect -> Improve and verify, run as one
// pipeline (services/investigation/workflow.py) against the isolated Juice
// Shop lab. Shows each stage's REAL outcome — "skipped"/"unavailable" when an
// integration has no credential, never a fabricated success — plus the
// scenario catalogue (including the labelled-unavailable placeholders),
// running lab instances, and the verified-finding -> Devin handoff flow.

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, FlaskConical, Loader2,
  MinusCircle, PlayCircle, Send, ShieldAlert, ShieldCheck, Trash2,
} from "lucide-react";
import {
  cleanupLabInstance, devinHandoff, devinPreview, listLabInstances, listScenarios,
  listVerifiedFindings, promoteFinding, runInvestigation,
  type InvestigationRecord, type LabInstanceView, type ScenarioCatalogueEntry,
  type StageResultView, type VerifiedFinding,
} from "@/lib/api";

const STAGE_LABELS: Record<string, string> = {
  research: "Research", investigate: "Investigate", prepare_lab: "Prepare lab",
  validate: "Validate", detect: "Detect", improve_and_verify: "Improve and verify",
};

function StageStatusIcon({ status }: { status: StageResultView["status"] }) {
  if (status === "ok") return <CheckCircle2 size={14} className="text-green-400" />;
  if (status === "unavailable") return <AlertTriangle size={14} className="text-amber-300" />;
  return <MinusCircle size={14} className="text-oyster-muted" />;
}

function SimulationBadge({ sim }: { sim: string }) {
  const cls = sim === "reproduced" ? "text-red-300 bg-red-500/10 border-red-500/20"
    : sim === "not_reproduced" ? "text-green-400 bg-green-500/10 border-green-500/20"
    : "text-oyster-muted bg-oyster-surface border-oyster-border";
  return <span className={`text-[11px] px-2 py-0.5 rounded-md border ${cls}`}>Simulation: {sim.replace("_", " ")}</span>;
}

function DetectionBadge({ label, detection }: { label: string; detection: string }) {
  const cls = detection === "detected" ? "text-green-400 bg-green-500/10 border-green-500/20"
    : detection === "missed" ? "text-red-300 bg-red-500/10 border-red-500/20"
    : "text-oyster-muted bg-oyster-surface border-oyster-border";
  const Icon = detection === "detected" ? ShieldCheck : detection === "missed" ? ShieldAlert : MinusCircle;
  return (
    <span className={`inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-md border ${cls}`}>
      <Icon size={11} />{label}: {detection}
    </span>
  );
}

function ScenarioCard({ scenario, selected, onSelect }: {
  scenario: ScenarioCatalogueEntry; selected: boolean; onSelect: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={`rounded-lg border p-3 transition-colors ${
      selected ? "border-oyster-accent/50 bg-oyster-accent/5" : "border-oyster-border bg-oyster-bg/40"}`}>
      <div className="flex items-start justify-between gap-2">
        <button disabled={!scenario.available} onClick={onSelect} className="text-left flex-1 min-w-0 disabled:cursor-not-allowed">
          <div className="flex items-center gap-2">
            <span className={`text-sm font-medium ${scenario.available ? "text-oyster-text" : "text-oyster-muted"}`}>{scenario.title}</span>
            {!scenario.available && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-oyster-surface text-oyster-muted border border-oyster-border">unavailable</span>
            )}
          </div>
          <p className="text-[11px] text-oyster-muted mt-0.5">{scenario.description}</p>
        </button>
        {scenario.available && (
          <button onClick={() => setExpanded((v) => !v)} className="text-oyster-muted hover:text-oyster-text shrink-0">
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        )}
      </div>
      {expanded && scenario.available && (
        <div className="mt-2 pt-2 border-t border-oyster-border/60 text-[11px] text-oyster-muted space-y-1">
          <p><span className="text-oyster-text">Permitted target:</span> {scenario.permitted_target}</p>
          <p><span className="text-oyster-text">Budget:</span> {scenario.max_requests} requests, {scenario.timeout_s}s timeout</p>
          <p><span className="text-oyster-text">Success criteria:</span> {scenario.success_criteria.map((c) => c.name).join(", ")}</p>
          <p><span className="text-oyster-text">Telemetry:</span> {scenario.required_telemetry.join("; ")}</p>
          <p><span className="text-oyster-text">Cleanup:</span> {scenario.cleanup}</p>
        </div>
      )}
    </div>
  );
}

function StageRow({ stage }: { stage: StageResultView }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border border-oyster-border/60 bg-oyster-bg/30">
      <button onClick={() => setOpen((v) => !v)} className="w-full flex items-center gap-2 px-2.5 py-1.5 text-left">
        <StageStatusIcon status={stage.status} />
        <span className="text-xs font-medium text-oyster-text w-32 shrink-0">{STAGE_LABELS[stage.stage] ?? stage.stage}</span>
        <span className="text-[11px] text-oyster-muted truncate">{stage.detail}</span>
        {open ? <ChevronDown size={12} className="ml-auto shrink-0 text-oyster-muted" /> : <ChevronRight size={12} className="ml-auto shrink-0 text-oyster-muted" />}
      </button>
      {open && (
        <pre className="text-[10px] text-oyster-muted px-2.5 pb-2 overflow-x-auto whitespace-pre-wrap">
          {JSON.stringify(stage.data, null, 1)}
        </pre>
      )}
    </div>
  );
}

export function InvestigationWorkflow() {
  const [scenarios, setScenarios] = useState<ScenarioCatalogueEntry[]>([]);
  const [instances, setInstances] = useState<LabInstanceView[]>([]);
  const [findings, setFindings] = useState<VerifiedFinding[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [record, setRecord] = useState<InvestigationRecord | null>(null);
  const [promoting, setPromoting] = useState(false);
  const [devinRepo, setDevinRepo] = useState("");
  const [devinBusy, setDevinBusy] = useState<string | null>(null);
  const [devinInfo, setDevinInfo] = useState<Record<string, unknown> | null>(null);

  const refresh = useCallback(async () => {
    const [s, i, f] = await Promise.all([listScenarios(), listLabInstances(), listVerifiedFindings()]);
    setScenarios(s.scenarios);
    setInstances(i.instances);
    setFindings(f.findings);
    if (!selected) {
      const first = s.scenarios.find((x) => x.available);
      if (first) setSelected(first.id);
    }
  }, [selected]);

  useEffect(() => { void refresh().catch(e => setError(e.message)); }, [refresh]);

  const run = useCallback(async () => {
    if (!selected) return;
    setRunning(true);
    setError(null);
    setRecord(null);
    try {
      const rec = await runInvestigation(selected);
      setRecord(rec);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Investigation run failed");
    } finally {
      setRunning(false);
    }
  }, [selected, refresh]);

  const promote = useCallback(async () => {
    if (!record) return;
    setPromoting(true);
    try {
      const scenario = scenarios.find((s) => s.id === record.scenario_id);
      await promoteFinding(record.investigation_id, `${scenario?.title ?? record.scenario_id} (lab)`, "operator");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not save finding");
    } finally {
      setPromoting(false);
    }
  }, [record, scenarios, refresh]);

  const stopInstance = useCallback(async (id: string) => {
    await cleanupLabInstance(id);
    await refresh();
  }, [refresh]);

  const previewDevin = useCallback(async (findingId: string) => {
    if (!devinRepo.trim()) return;
    setDevinBusy(findingId);
    try {
      const r = await devinPreview(findingId, devinRepo.trim());
      setDevinInfo(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Devin preview failed");
    } finally {
      setDevinBusy(null);
    }
  }, [devinRepo]);

  const sendToDevin = useCallback(async (findingId: string) => {
    if (!devinRepo.trim()) return;
    setDevinBusy(findingId);
    try {
      await devinHandoff(findingId, devinRepo.trim());
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Devin handoff failed — see docs/CHECKPOINT.md for whether Devin is configured.");
    } finally {
      setDevinBusy(null);
    }
  }, [devinRepo, refresh]);

  return (
    <div className="max-w-3xl mx-auto space-y-5">
      <ResearchPanel />
      <h2 className="text-sm font-semibold">Direct lab checks (without deep research)</h2>
      <div>
        <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-wider mb-2">Scenario catalogue</h3>
        <div className="space-y-1.5">
          {scenarios.map((s) => (
            <ScenarioCard key={s.id} scenario={s} selected={selected === s.id} onSelect={() => setSelected(s.id)} />
          ))}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button onClick={run} disabled={!selected || running}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${
                  !selected || running ? "bg-oyster-border text-oyster-muted cursor-not-allowed" : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"}`}>
          {running ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
          Run investigation
        </button>
        <span className="text-[11px] text-oyster-muted">Research → Investigate → Prepare lab → Validate → Detect → Improve and verify</span>
      </div>

      {error && (
        <div role="alert" className="flex items-start gap-2 text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
          <AlertTriangle size={15} className="mt-0.5 shrink-0" /> <span>{error}</span>
        </div>
      )}

      {record && (
        <div className="space-y-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <SimulationBadge sim={record.simulation} />
            {record.detection_baseline && (
              <DetectionBadge label={`Baseline (${record.detection_baseline.is_demo_baseline ? "demo config" : "rule"})`}
                              detection={record.detection_baseline.detection} />
            )}
            {record.detection_improved_retest && (
              <DetectionBadge label="Improved rule, retested on a fresh instance"
                              detection={record.detection_improved_retest.retest_detection.detection} />
            )}
            <span className="text-[11px] text-oyster-muted">{record.duration_s.toFixed(1)}s · lab {record.lab_version}@{record.lab_commit.slice(0, 7)}</span>
          </div>
          <div className="space-y-1">
            {record.stages.map((s, i) => <StageRow key={i} stage={s} />)}
          </div>
          <button onClick={promote} disabled={promoting || record.simulation !== "reproduced" || record.detection_improved_retest?.retest_simulation !== "reproduced"}
                  className="flex items-center gap-2 text-[12px] px-3 py-1.5 rounded-lg border border-oyster-border text-oyster-text hover:border-oyster-accent/40 disabled:opacity-50">
            {promoting ? <Loader2 size={12} className="animate-spin" /> : <FlaskConical size={12} />}
            Save as verified finding
          </button>
        </div>
      )}

      {instances.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-wider mb-1.5">Running lab instances</h3>
          <div className="space-y-1">
            {instances.map((i) => (
              <div key={i.id} className="flex items-center gap-2 text-[11px] text-oyster-muted bg-oyster-bg/40 border border-oyster-border rounded-md px-2.5 py-1.5">
                <span className="font-mono">{i.id}</span>
                <span>{i.scenario_id}</span>
                <span className={i.status === "ready" ? "text-green-400" : "text-amber-300"}>{i.status}</span>
                <button onClick={() => void stopInstance(i.id)} className="ml-auto text-oyster-muted hover:text-red-400" title="Stop and clean up">
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {findings.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold text-oyster-muted uppercase tracking-wider mb-1.5">Verified findings</h3>
          <div className="space-y-2">
            {findings.map((f) => (
              <div key={f.id} className="rounded-lg border border-oyster-border bg-oyster-bg/40 p-3 space-y-1.5">
                <p className="text-sm text-oyster-text font-medium">{f.title}</p>
                <div className="flex flex-wrap gap-1.5">
                  <SimulationBadge sim={f.simulation} />
                  {f.detection_baseline && <DetectionBadge label="Baseline" detection={f.detection_baseline.detection} />}
                </div>
                {f.devin_session?.url ? (
                  <a href={f.devin_session.url} target="_blank" rel="noopener noreferrer"
                     className="text-[11px] text-oyster-accent hover:underline">
                    Devin session: {f.devin_session.status} — {f.devin_session.url}
                  </a>
                ) : (
                  <div className="flex items-center gap-2">
                    <input value={devinRepo} onChange={(e) => setDevinRepo(e.target.value)} placeholder="owner/repo"
                           className="text-[11px] bg-oyster-surface border border-oyster-border rounded-md px-2 py-1 text-oyster-text outline-none w-40" />
                    <button onClick={() => void previewDevin(f.id)} disabled={devinBusy === f.id}
                            className="text-[11px] px-2 py-1 rounded-md border border-oyster-border text-oyster-text hover:border-oyster-accent/40 disabled:opacity-50">
                      Preview evidence
                    </button>
                    <button onClick={() => void sendToDevin(f.id)} disabled={devinBusy === f.id}
                            className="flex items-center gap-1 text-[11px] px-2 py-1 rounded-md bg-oyster-accent text-white hover:bg-oyster-accent-hover disabled:opacity-50">
                      <Send size={11} />Investigate with Devin
                    </button>
                  </div>
                )}
                {devinInfo && devinInfo.evidence_package != null && devinBusy === null && (
                  <div className="mt-1 rounded-md bg-oyster-bg/60 border border-oyster-border/60 p-2">
                    <p className="text-[10px] text-oyster-muted mb-1">
                      {String(devinInfo.devin_configured) === "true"
                        ? (String(devinInfo.repo_allowed) === "true" ? "Devin is configured and this repo is allowed." : "Devin is configured, but this repository is not in the allowed list — handoff will be refused.")
                        : "Devin is not configured on this backend — handoff will be refused; this preview only shows the evidence package."}
                    </p>
                    <pre className="text-[10px] text-oyster-muted overflow-x-auto whitespace-pre-wrap max-h-40">
                      {JSON.stringify(devinInfo.evidence_package, null, 1)}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
