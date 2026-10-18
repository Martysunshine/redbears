// Typed client for the SOC Copilot (socmat) workbench mounted at /socmat/api.
// Every call goes through socmatFetch (Supabase bearer auth + per-account
// isolation on the backend). Paths mirror socmat's own routers; the socmat
// frontend hit these under a "/api" proxy that stripped the prefix, so the
// backend paths are root-relative ("/cases", "/dashboard/summary", …).

import { socmatFetch, socmatError } from "@/lib/api";

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) await socmatError(res);
  return res.json() as Promise<T>;
}

// ── Types ───────────────────────────────────────────────────────────────────

export type Severity = "low" | "medium" | "high" | "critical";
export type CaseStatus = "open" | "investigating" | "contained" | "escalated" | "closed";

export interface Case {
  id: number;
  title: string;
  description: string | null;
  severity: Severity;
  status: CaseStatus;
  source: string;
  affected_host: string | null;
  affected_user: string | null;
  affected_ip: string | null;
  created_at: string;
  updated_at: string;
}

export interface DashboardSummary {
  total_cases: number;
  open_cases: number;
  investigating_cases: number;
  critical_cases: number;
  high_cases: number;
  total_evidence: number;
  total_timeline_events: number;
  total_reports: number;
  recent_cases: { id: number; title: string; severity: string; status: string; created_at: string }[];
  recent_timeline: {
    id: number; case_id: number; event_type: string; description: string;
    severity: string; timestamp: string; source: string;
  }[];
}

export interface Evidence {
  id: number;
  case_id: number;
  filename: string;
  original_filename: string;
  file_type: string | null;
  file_size: number;
  sha256: string;
  uploaded_at: string;
  notes: string | null;
}

export interface TimelineEvent {
  id: number;
  case_id: number;
  timestamp: string;
  source: string;
  event_type: string;
  description: string;
  severity: string;
  raw_reference: string | null;
  created_at: string;
}

export interface AIAnalysis {
  provider: string;
  mode: string;
  case_id: number;
  generated_at: string;
  summary: string;
  key_evidence: string[];
  likely_incident_type: string;
  confidence: string;
  recommended_next_steps: string[];
  missing_evidence: string[];
  disclaimer: string;
}

export interface Ioc {
  id: number;
  case_id: number;
  ioc_type: string;
  value: string;
  confidence: string;
  tags: string[];
  first_seen?: string;
  created_at: string;
}
export interface ExtractIocsResponse { extracted: number; iocs: Ioc[] }

export interface MitreMapping {
  id: number;
  case_id: number;
  tactic: string;
  technique_id: string;
  technique_name: string;
  evidence_reference: { source: string; detail: string }[];
  confidence: string;
  created_at: string;
}

export interface DetectionFinding {
  id: number;
  case_id: number;
  rule_id: string;
  rule_title: string;
  severity: string;
  matched_event_id: number;
  match_reason: string;
  event_id_str: string | null;
  event_timestamp: string | null;
  created_at: string;
}
export interface SigmaRunResult {
  rules_run: number;
  events_scanned: number;
  findings_created: number;
  findings: DetectionFinding[];
}

export interface YaraMatch { rule: string; tags: string[]; meta: Record<string, string>; strings_matched: string[] }
export interface MalwareTriageResult {
  id: number;
  case_id: number;
  evidence_id: number;
  original_filename: string;
  sha256: string | null;
  file_type: string | null;
  file_size: number | null;
  yara_matches: YaraMatch[];
  suspicious_strings: { powershell: string[]; lolbas: string[]; base64: string[]; urls: string[]; ips: string[] };
  risk_score: number;
  summary: string;
  created_at: string;
}

export interface WindowsAnalysisResult {
  evidence_id: number;
  total_events: number;
  events_by_id: Record<string, number>;
  suspicious_findings: { event_id: string; severity: string; description: string; host: string | null; user: string | null; count: number }[];
  timeline_events_added: number;
  normalized_events_saved: number;
}

export interface Report {
  id: number;
  case_id: number;
  report_path: string;
  format: string;
  generated_at: string;
  summary: string | null;
}

// ── Dashboard ───────────────────────────────────────────────────────────────

export const getDashboard = () =>
  socmatFetch("/dashboard/summary").then(json<DashboardSummary>);

// ── Cases ───────────────────────────────────────────────────────────────────

export const getCases = () => socmatFetch("/cases").then(json<Case[]>);
export const getCase = (id: number) => socmatFetch(`/cases/${id}`).then(json<Case>);
export const createCase = (data: Partial<Case> & { title: string }) =>
  socmatFetch("/cases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(json<Case>);
export const updateCase = (id: number, data: Partial<Case>) =>
  socmatFetch(`/cases/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  }).then(json<Case>);
export const deleteCase = (id: number) =>
  socmatFetch(`/cases/${id}`, { method: "DELETE" }).then((r) => { if (!r.ok) return socmatError(r); });

// ── Evidence + timeline ─────────────────────────────────────────────────────

export const getEvidence = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/evidence`).then(json<Evidence[]>);
export const uploadEvidence = (caseId: number, file: File, notes: string) => {
  const form = new FormData();
  form.append("file", file);
  form.append("notes", notes);
  return socmatFetch(`/cases/${caseId}/evidence`, { method: "POST", body: form }).then(json<Evidence>);
};
export const getTimeline = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/timeline`).then(json<TimelineEvent[]>);

// ── AI assistant (Ollama-backed) ────────────────────────────────────────────

export const aiSummarize = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/ai/summarize`, { method: "POST" }).then(json<AIAnalysis>);
export const aiRecommend = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/ai/recommend`, { method: "POST" }).then(json<AIAnalysis>);

// ── IOCs ────────────────────────────────────────────────────────────────────

export const extractIocs = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/iocs/extract`, { method: "POST" }).then(json<ExtractIocsResponse>);
export const getIocs = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/iocs`).then(json<Ioc[]>);

// ── MITRE ATT&CK ────────────────────────────────────────────────────────────

export const runMitre = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/mitre/map`, { method: "POST" }).then(json<MitreMapping[]>);
export const getMitre = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/mitre/map`).then(json<MitreMapping[]>);

// ── Detections: Sigma + YARA + Windows ──────────────────────────────────────

export const runSigma = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/sigma/run`, { method: "POST" }).then(json<SigmaRunResult>);
export const getSigmaFindings = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/sigma/findings`).then(json<DetectionFinding[]>);
export const getYaraResults = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/analyze/yara`).then(json<MalwareTriageResult[]>);
export const runYaraTriage = (caseId: number, evidenceId: number) =>
  socmatFetch(`/cases/${caseId}/analyze/yara`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ evidence_id: evidenceId }),
  }).then(json<MalwareTriageResult>);
export const runWindowsAnalysis = (caseId: number, evidenceId: number) =>
  socmatFetch(`/cases/${caseId}/analyze/windows-logs?evidence_id=${evidenceId}`, { method: "POST" })
    .then(json<WindowsAnalysisResult>);

// ── Reports ─────────────────────────────────────────────────────────────────

export const generateReport = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/report/generate`, { method: "POST" }).then(json<Report>);
export const getReport = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/report`).then(json<Report | null>);
export const getReportContent = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/report/content`).then(async (r) => {
    if (!r.ok) return socmatError(r);
    return r.text();
  });
export async function downloadReportPdf(caseId: number): Promise<void> {
  const res = await socmatFetch(`/cases/${caseId}/report/pdf`);
  if (!res.ok) return socmatError(res);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `case-${caseId}-incident-report.pdf`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── Network analysis (PCAP / Zeek / Suricata) ───────────────────────────────

export interface PcapResult {
  id: number; case_id: number; evidence_id: number; original_filename: string;
  total_packets: number; total_bytes: number; duration_seconds: number;
  protocol_counts: Record<string, number>;
  top_talkers: { host: string; packets: number; bytes_sent: number; destinations: number }[];
  dns_queries: { src_ip: string; query: string; query_type: string }[];
  http_requests: { src_ip: string; dst_ip: string; method: string; host: string; uri: string; user_agent: string }[];
  tls_hosts: { host: string; dst_ip: string }[];
  findings: { category: string; severity: string; description: string; host: string | null; details: string | null }[];
  risk_score: number; summary: string; created_at: string;
}
export interface ZeekResult {
  id: number; case_id: number; evidence_id: number; original_filename: string; log_type: string;
  total_records: number; risk_score: number; summary: string;
  findings: { category: string; severity: string; description: string; host: string | null; count: number | null; details: string | null }[];
  top_talkers: { host: string; connection_count: number; total_bytes: number; destinations: number }[];
  dns_summary: { total_queries: number; unique_domains: number; top_queried: string[]; suspicious_domains: string[] } | null;
  http_summary: { total_requests: number; unique_hosts: number; top_hosts: string[]; suspicious_agents: string[] } | null;
  created_at: string;
}
export interface SuricataResult {
  evidence_id: number; total_alerts: number; unique_signatures: number;
  top_src_ips: { value: string; count: number }[];
  top_dest_ips: { value: string; count: number }[];
  top_signatures: { value: string; count: number }[];
  suspicious_findings: { severity: string; description: string; src_ip: string; dest_ip: string; signature: string }[];
  timeline_events_added: number; normalized_events_saved: number;
}

export const runPcap = (caseId: number, evidenceId: number) =>
  socmatFetch(`/cases/${caseId}/analyze/pcap`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence_id: evidenceId }) }).then(json<PcapResult>);
export const getPcap = (caseId: number) => socmatFetch(`/cases/${caseId}/analyze/pcap`).then(json<PcapResult[]>);
export const runZeek = (caseId: number, evidenceId: number) =>
  socmatFetch(`/cases/${caseId}/analyze/zeek`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ evidence_id: evidenceId }) }).then(json<ZeekResult>);
export const getZeek = (caseId: number) => socmatFetch(`/cases/${caseId}/analyze/zeek`).then(json<ZeekResult[]>);
export const runSuricata = (caseId: number, evidenceId: number) =>
  socmatFetch(`/cases/${caseId}/analyze/suricata?evidence_id=${evidenceId}`, { method: "POST" }).then(json<SuricataResult>);

// ── Correlation ─────────────────────────────────────────────────────────────

export interface CorrelatedFinding {
  id: number; case_id: number; title: string; severity: string; confidence: string;
  entities: { type: string; value: string }[];
  related_event_ids: number[]; related_finding_ids: number[];
  summary: string; recommended_action: string; created_at: string;
}
export const runCorrelation = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/correlate`, { method: "POST" }).then(json<CorrelatedFinding[]>);
export const getCorrelation = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/correlate`).then(json<CorrelatedFinding[]>);

// ── Entity graph ────────────────────────────────────────────────────────────

export interface GraphNode { id: string; type: string; label: string; severity: string; confidence: string }
export interface GraphEdge { id: string; source: string; target: string; type: string; label: string }
export interface GraphResponse {
  nodes: GraphNode[]; edges: GraphEdge[];
  metadata: { total_nodes: number; total_edges: number; node_type_counts: Record<string, number>; case_id: number };
}
export const getGraph = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/graph`).then(json<GraphResponse>);

// ── Coverage + telemetry gaps ───────────────────────────────────────────────

export interface RuleCoverage {
  rule_id: string; rule_title: string; rule_type: string; required_logsource: string;
  mapped_mitre_techniques: string[]; severity: string; triggered_in_case: boolean;
  blocked_by_missing_data: boolean; missing_fields: string[];
}
export interface CaseCoverage {
  case_id: number; rules_triggered: RuleCoverage[]; rules_not_triggered: RuleCoverage[]; rules_blocked: RuleCoverage[];
  available_log_sources: string[]; missing_log_sources: string[];
  mitre_covered_techniques: number; mitre_total_techniques: number; coverage_percent: number;
}
export interface TelemetryGap { missing_log_source: string; why_it_matters: string; affected_detection_rules: string[]; related_mitre_techniques: string[]; recommendation: string }
export const getCoverage = (caseId: number) => socmatFetch(`/cases/${caseId}/coverage`).then(json<CaseCoverage>);
export const getTelemetryGaps = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/telemetry-gaps`).then(json<{ case_id: number; gaps: TelemetryGap[]; available_log_sources: string[]; gap_count: number }>);

// ── Playbooks ───────────────────────────────────────────────────────────────

export interface PlaybookStep { id: number; step_order: number; title: string; description: string | null; status: string; analyst_notes: string | null }
export interface CasePlaybook { id: number; case_id: number; name: string; status: string; progress_percent: number; steps: PlaybookStep[] }
export interface PlaybookSuggestion { template_id: number; name: string; alert_type: string; reason: string }
export interface PlaybookTemplateSummary { id: number; name: string; description: string | null; alert_type: string; severity: string; step_count: number }
export interface PlaybookTemplateDetail extends PlaybookTemplateSummary { required_data_sources: string[]; steps: { order: number; title: string; description: string }[] }
export const getPlaybookTemplates = () => socmatFetch(`/playbooks/templates`).then(json<PlaybookTemplateSummary[]>);
export const getPlaybookTemplate = (id: number) => socmatFetch(`/playbooks/templates/${id}`).then(json<PlaybookTemplateDetail>);
export const getCasePlaybooks = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/playbooks`).then(json<{ playbooks: CasePlaybook[]; suggestions: PlaybookSuggestion[] }>);
export const attachPlaybook = (caseId: number, templateId: number) =>
  socmatFetch(`/cases/${caseId}/playbooks`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ template_id: templateId }) }).then(json<CasePlaybook>);
export const updatePlaybookStep = (caseId: number, pbId: number, stepId: number, data: { status?: string; analyst_notes?: string }) =>
  socmatFetch(`/cases/${caseId}/playbooks/${pbId}/steps/${stepId}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) }).then(json<PlaybookStep>);

// ── Dispositions ────────────────────────────────────────────────────────────

export const DISPOSITIONS = ["needs_review", "true_positive", "false_positive", "benign", "suspicious", "escalated", "duplicate", "insufficient_data"] as const;
export type DispositionValue = typeof DISPOSITIONS[number];
export interface FindingDisposition {
  id: number; case_id: number; finding_type: string; finding_id: string;
  disposition: DispositionValue; confidence: "low" | "medium" | "high"; reason: string | null;
  analyst_name: string | null; follow_up_action: string | null; created_at: string; updated_at: string;
}
export interface DispositionSummary { total: number; true_positive: number; false_positive: number; benign: number; suspicious: number; needs_review: number; escalated: number; duplicate: number; insufficient_data: number }
export const getDispositions = (caseId: number) =>
  socmatFetch(`/cases/${caseId}/dispositions`).then(json<{ case_id: number; dispositions: FindingDisposition[]; summary: DispositionSummary }>);
export const createDisposition = (caseId: number, data: { finding_type: string; finding_id: string; disposition?: DispositionValue; confidence?: string; reason?: string }) =>
  socmatFetch(`/cases/${caseId}/dispositions`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) }).then(json<FindingDisposition>);

// ── Analyst notes ───────────────────────────────────────────────────────────

export interface AnalystNote { id: number; case_id: number; entity_type: string; note_type: string; body: string; author_name: string | null; created_at: string }
export const getNotes = (caseId: number) => socmatFetch(`/cases/${caseId}/notes`).then(json<AnalystNote[]>);
/** Owner-wide feed across all the caller's cases (each note carries case_id). */
export const getAllNotes = () => socmatFetch(`/notes`).then(json<AnalystNote[]>);
export const createNote = (caseId: number, data: { entity_type: string; note_type: string; body: string }) =>
  socmatFetch(`/cases/${caseId}/notes`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) }).then(json<AnalystNote>);
export const deleteNote = (caseId: number, noteId: number) =>
  socmatFetch(`/cases/${caseId}/notes/${noteId}`, { method: "DELETE" }).then((r) => { if (!r.ok) return socmatError(r); });

// ── Rule authoring (global; deterministic Sigma/SPL/KQL/ES|QL generator) ─────

export interface RuleDraft {
  event_type_detected: string; event_type_label: string; keyword_extracted: string;
  sigma_yaml: string; spl_query: string; kql_query: string; esql_query: string;
  false_positives: string[]; log_source_notes: string[]; validation_warnings: string[]; quality_disclaimer: string;
}
export const authorRules = (description: string, eventType?: string) =>
  socmatFetch(`/rules/author`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ description, event_type: eventType }) }).then(json<RuleDraft>);
export const getEventTypes = () => socmatFetch(`/rules/author/event-types`).then(json<{ value: string; label: string }[]>);

// ── Live SIEM (Splunk / Elastic — env-gated, honest disabled state) ─────────

export interface SplunkLiveStatus { configured: boolean; connected: boolean; server_info: { version: string; product_name: string; server_name: string; os: string } | null; error: string | null; warning: string }
export interface ElasticLiveStatus { configured: boolean; connected: boolean; cluster_info: { cluster_name: string; status: string; number_of_nodes: number; active_shards: number } | null; error: string | null; warning: string }
export interface LiveQuery { id: number; result_count: number; result_sample: string | null; status: string; error_message: string | null; executed_at: string; warning: string }

export const getSplunkStatus = () => socmatFetch(`/splunk/live/status`).then(json<SplunkLiveStatus>);
export const runSplunkSearch = (spl_query: string, caseId?: number) =>
  socmatFetch(`/splunk/live/search`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spl_query, case_id: caseId, max_results: 100 }) }).then(json<LiveQuery>);
export const getElasticStatus = () => socmatFetch(`/elastic/live/status`).then(json<ElasticLiveStatus>);
export const runElasticSearch = (esql_query: string, caseId?: number) =>
  socmatFetch(`/elastic/live/search`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ esql_query, case_id: caseId, max_results: 100 }) }).then(json<LiveQuery>);
