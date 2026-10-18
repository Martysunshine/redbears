"use client";

// Integrations settings — Nemotron reasoning, Tavily, Devin. Lives inside
// Account Settings (not a main nav section) since it is server-side
// credential configuration, exactly like the rest of this modal.
//
// Status is never invented: "Connected" only ever reflects the last real
// connection test's result. Credentials are write-only from the browser's
// point of view — nothing typed here is ever read back; only a masked shape
// ("tvly…xy (42 chars)") and whether a value is set at all.

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Circle, Loader2, RefreshCw, Unplug } from "lucide-react";
import {
  disconnectIntegration,
  listIntegrations,
  setIntegrationCredentials,
  testIntegration,
  type IntegrationStatus,
} from "@/lib/api";

const FIELD_LABELS: Record<string, Record<string, string>> = {
  nemotron_reasoning: {
    NEBIUS_API_KEY: "Nebius Token Factory API key",
    NEMOTRON_REASONING_MODEL: "Model id (from this account's /models list)",
  },
  tavily: { TAVILY_API_KEY: "Tavily API key" },
  devin: { DEVIN_API_KEY: "Devin API key (cog_…)", DEVIN_ORG_ID: "Devin organization id" },
  opencve: { OPENCVE_API_TOKEN: "OpenCVE organisation API token (opc_org.…)" },
};

function StatusBadge({ status }: { status: IntegrationStatus["status"] }) {
  if (status === "connected")
    return <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-md border border-green-500/20 bg-green-500/10 text-green-400"><CheckCircle2 size={11} />Connected</span>;
  if (status === "unavailable")
    return <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-md border border-amber-500/20 bg-amber-500/10 text-amber-300"><AlertTriangle size={11} />Unavailable</span>;
  return <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-md border border-oyster-border bg-oyster-surface text-oyster-muted"><Circle size={10} />Not configured</span>;
}

function IntegrationRow({ integration, onChanged }: { integration: IntegrationStatus; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<{ status: string; detail: string } | null>(null);
  const labels = FIELD_LABELS[integration.id] || {};

  const test = useCallback(async () => {
    setBusy(true);
    try {
      const r = await testIntegration(integration.id);
      setTestResult({ status: r.status, detail: r.detail });
    } catch (e) {
      setTestResult({ status: "unavailable", detail: e instanceof Error ? e.message : "Test failed" });
    } finally {
      setBusy(false);
      onChanged();
    }
  }, [integration.id, onChanged]);

  const save = useCallback(async () => {
    const nonEmpty = Object.fromEntries(Object.entries(fields).filter(([, v]) => v.trim()));
    if (Object.keys(nonEmpty).length === 0) { setEditing(false); return; }
    setBusy(true);
    try {
      await setIntegrationCredentials(integration.id, nonEmpty);
      setFields({});
      setEditing(false);
      onChanged();
    } finally {
      setBusy(false);
    }
  }, [fields, integration.id, onChanged]);

  const disconnect = useCallback(async () => {
    setBusy(true);
    try {
      await disconnectIntegration(integration.id);
      setTestResult(null);
    } finally {
      setBusy(false);
      onChanged();
    }
  }, [integration.id, onChanged]);

  return (
    <div className="rounded-lg border border-oyster-border bg-oyster-bg/40 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-oyster-text">{integration.label}</span>
            <StatusBadge status={integration.status} />
          </div>
          <p className="mt-0.5 text-[11px] text-oyster-muted leading-snug">{integration.role}</p>
          {integration.model && <p className="mt-0.5 text-[11px] text-oyster-muted">Model: <span className="text-oyster-text">{integration.model}</span></p>}
          {integration.api_key_shape && <p className="mt-0.5 text-[11px] text-oyster-muted">Key: <span className="font-mono">{integration.api_key_shape}</span></p>}
          <p className="mt-1 text-[11px] text-oyster-muted">{integration.detail}</p>
          {testResult && (
            <p className={`mt-1 text-[11px] ${testResult.status === "connected" ? "text-green-400" : "text-amber-300"}`}>
              Last test: {testResult.detail}
            </p>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button onClick={test} disabled={busy} title="Test connection"
                  className="p-1.5 rounded-md text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface disabled:opacity-50">
            {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          </button>
          {integration.configured && (
            <button onClick={disconnect} disabled={busy} title="Disconnect"
                    className="p-1.5 rounded-md text-oyster-muted hover:text-red-400 hover:bg-red-500/10 disabled:opacity-50">
              <Unplug size={14} />
            </button>
          )}
          <button onClick={() => setEditing((v) => !v)}
                  className="text-[11px] px-2 py-1 rounded-md border border-oyster-border text-oyster-text hover:border-oyster-accent/40">
            Configure
          </button>
        </div>
      </div>

      {editing && (
        <div className="mt-2.5 pt-2.5 border-t border-oyster-border/60 space-y-2">
          <p className="text-[10px] text-oyster-muted">
            Stored server-side, in this process&apos;s memory only — never written to disk by this
            panel, never echoed back to the browser. For a real deployment, set these via your
            host&apos;s secret manager instead; see docs/SECURITY.md.
          </p>
          {Object.entries(labels).map(([field, label]) => (
            <div key={field}>
              <label className="block text-[10px] text-oyster-muted mb-0.5">{label}</label>
              <input
                type={field.includes("API_KEY") ? "password" : "text"}
                value={fields[field] ?? ""}
                onChange={(e) => setFields((f) => ({ ...f, [field]: e.target.value }))}
                placeholder={field.includes("API_KEY") ? "Paste key — never shown again" : ""}
                className="w-full bg-oyster-surface border border-oyster-border rounded-md px-2 py-1.5 text-xs text-oyster-text outline-none focus:border-oyster-accent/50"
              />
            </div>
          ))}
          <div className="flex gap-2">
            <button onClick={save} disabled={busy}
                    className="text-[11px] px-2.5 py-1.5 rounded-md bg-oyster-accent text-white hover:bg-oyster-accent-hover disabled:opacity-50">
              Save
            </button>
            <button onClick={() => { setEditing(false); setFields({}); }}
                    className="text-[11px] px-2.5 py-1.5 rounded-md border border-oyster-border text-oyster-muted">
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function IntegrationsPanel() {
  const [integrations, setIntegrations] = useState<IntegrationStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const r = await listIntegrations();
      setIntegrations(r.integrations);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load integrations");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p className="text-[11px] text-red-300">{error}</p>;
  if (!integrations) return <p className="text-[11px] text-oyster-muted">Loading…</p>;

  return (
    <div className="space-y-2">
      {integrations.map((i) => (
        <IntegrationRow key={i.id} integration={i} onChanged={load} />
      ))}
    </div>
  );
}
