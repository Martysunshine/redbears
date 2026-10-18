"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  PanelLeftOpen,
  ShieldQuestion,
  Search,
  Loader2,
  AlertCircle,
  AlertTriangle,
  Sparkles,
  Check,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  ArrowUp,
  ArrowDown,
  ArrowUpDown,
  Bug,
  FileWarning,
  Crosshair,
  Target,
  ShieldCheck,
  HelpCircle,
  Info,
  Layers,
  ClipboardCheck,
  BookOpenCheck,
  Clock,
  LifeBuoy,
  Cloud,
  ListFilter,
  ShieldOff,
  Package,
} from "lucide-react";
import {
  askSecurityIntelligence,
  classifySecurityQuestion,
  resolveCitation,
  type SecurityIntelAnswer,
  type SecurityIntelClassification,
  type SecurityIntelConfidence,
  type SecurityIntelExactItem,
  type SecurityIntelListingRow,
  type SecurityIntelSource,
  type CitationSource,
} from "@/lib/api";

interface SecurityIntelligencePanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  selectedModel: string;
}

const EXAMPLES = [
  "Tell me about CVE-2021-44228",
  "list known exploited vulnerabilities",
  "how do I detect T1055 process injection",
  "how do I mitigate CWE-89 SQL injection",
  "incident response steps for a ransomware outbreak",
  "kubernetes cluster hardening best practices",
  "what vulnerabilities affect the npm package left-pad",
  "what should I patch first: CVE-2021-44228 or CVE-2023-24489",
];

const ROUTE_META: Record<string, { label: string; cls: string }> = {
  exact_lookup: { label: "Exact identifier lookup", cls: "text-oyster-accent bg-oyster-accent/10 border-oyster-accent/20" },
  vulnerability_filter: { label: "Vulnerability listing", cls: "text-sky-300 bg-sky-500/10 border-sky-500/20" },
  package_vulnerabilities: { label: "Package/ecosystem vulnerability lookup", cls: "text-teal-300 bg-teal-500/10 border-teal-500/20" },
  version_check: { label: "Package version check", cls: "text-teal-300 bg-teal-500/10 border-teal-500/20" },
  prioritization: { label: "Patch prioritization", cls: "text-orange-300 bg-orange-500/10 border-orange-500/20" },
  detection: { label: "Detection question", cls: "text-purple-300 bg-purple-500/10 border-purple-500/20" },
  mitigation: { label: "Mitigation question", cls: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20" },
  incident_response: { label: "Incident response question", cls: "text-red-300 bg-red-500/10 border-red-500/20" },
  cloud: { label: "Cloud security question", cls: "text-cyan-300 bg-cyan-500/10 border-cyan-500/20" },
  compliance: { label: "Compliance / standards question", cls: "text-indigo-300 bg-indigo-500/10 border-indigo-500/20" },
  general: { label: "General security question", cls: "text-oyster-muted bg-oyster-surface border-oyster-border" },
};

const ROUTE_ICON: Record<string, React.ElementType> = {
  detection: Search,
  mitigation: ClipboardCheck,
  incident_response: LifeBuoy,
  cloud: Cloud,
  compliance: BookOpenCheck,
  package_vulnerabilities: Package,
  version_check: Package,
  prioritization: ArrowUpDown,
  general: HelpCircle,
};

const BAND_CLS: Record<string, string> = {
  critical: "text-red-300 bg-red-500/15",
  high: "text-orange-300 bg-orange-500/15",
  medium: "text-amber-300 bg-amber-500/15",
  low: "text-sky-300 bg-sky-500/15",
};

const VERSION_STATUS_CLS: Record<string, string> = {
  vulnerable: "text-red-300 bg-red-500/15",
  not_affected_by_installed_advisories: "text-green-400 bg-green-500/10",
  not_found: "text-oyster-muted bg-oyster-surface",
  indeterminate: "text-amber-300 bg-amber-500/15",
};

const CONFIDENCE_META: Record<SecurityIntelConfidence["level"], { label: string; cls: string }> = {
  grounded: { label: "Grounded in local knowledge base", cls: "text-green-400 bg-green-500/10 border-green-500/20" },
  partial: { label: "Partial data — some fields may be incomplete", cls: "text-amber-300 bg-amber-500/10 border-amber-500/20" },
  none: { label: "No supporting data found", cls: "text-red-300 bg-red-500/10 border-red-500/20" },
};

const SEV_CLS: Record<string, string> = {
  CRITICAL: "text-red-300 bg-red-500/15",
  HIGH: "text-orange-300 bg-orange-500/15",
  MEDIUM: "text-amber-300 bg-amber-500/15",
  LOW: "text-sky-300 bg-sky-500/15",
  NONE: "text-oyster-muted bg-oyster-surface",
};

function severityCls(sev?: string | null): string {
  if (!sev) return "text-oyster-muted bg-oyster-surface";
  return SEV_CLS[sev.toUpperCase()] ?? "text-oyster-muted bg-oyster-surface";
}

function formatDate(iso?: string | null): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function classifyHintText(c: SecurityIntelClassification): string {
  const ids = [
    ...c.identifiers.cve,
    ...c.identifiers.cwe,
    ...c.identifiers.capec,
    ...c.identifiers.attack,
    ...c.identifiers.d3fend,
    ...c.identifiers.nist_control,
    ...c.identifiers.ghsa,
    ...c.identifiers.osv,
  ];
  if (c.route === "exact_lookup" && ids.length > 0) return `Exact match: ${ids.join(", ")}`;
  return ROUTE_META[c.route]?.label ?? c.route;
}

function kindFromIdentifier(id: string): { label: string; icon: React.ElementType } {
  if (/^CVE-/i.test(id)) return { label: "CVE", icon: Bug };
  if (/^CWE-/i.test(id)) return { label: "CWE", icon: FileWarning };
  if (/^CAPEC-/i.test(id)) return { label: "CAPEC", icon: Crosshair };
  if (/^d3f:/i.test(id)) return { label: "D3FEND", icon: ShieldCheck };
  if (/^T\d/i.test(id)) return { label: "ATT&CK", icon: Target };
  if (/^GHSA-/i.test(id)) return { label: "GHSA", icon: ShieldOff };
  if (/^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}/i.test(id)) return { label: "CSF", icon: BookOpenCheck };
  if (/^(PO|PS|PW|RV)\.\d/i.test(id)) return { label: "SSDF", icon: BookOpenCheck };
  if (/^[A-Z]{2}-\d/i.test(id)) return { label: "SP 800-53", icon: BookOpenCheck };
  if (/^(PYSEC|GO|RUSTSEC|GSD|OSV|MAL|BIT|HSEC)-/i.test(id)) return { label: "OSV", icon: Layers };
  return { label: "Identifier", icon: HelpCircle };
}

// -----------------------------------------------------------------------
// Small shared pieces
// -----------------------------------------------------------------------

function ConfidenceBadge({ confidence }: { confidence: SecurityIntelConfidence }) {
  const meta = CONFIDENCE_META[confidence.level] ?? CONFIDENCE_META.partial;
  return (
    <span className={`inline-flex items-center gap-1.5 text-[11px] font-medium px-2 py-1 rounded-lg border ${meta.cls}`}>
      {confidence.level === "grounded" ? <Check size={12} /> : <AlertTriangle size={12} />}
      {meta.label}
    </span>
  );
}

function InfoCard({
  icon: Icon,
  title,
  accent,
  children,
}: {
  icon: React.ElementType;
  title: string;
  accent?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-1.5">
      <div className="flex items-center gap-2">
        <Icon size={14} className={accent ?? "text-oyster-accent"} />
        <h3 className="text-xs font-semibold text-oyster-text uppercase tracking-wide">{title}</h3>
      </div>
      <div className="text-sm text-oyster-muted leading-relaxed">{children}</div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Exact-lookup identifier card (CVE / CWE / CAPEC / ATT&CK / D3FEND)
// -----------------------------------------------------------------------

function ExactItemCard({ item }: { item: SecurityIntelExactItem }) {
  const kind = kindFromIdentifier(item.identifier);
  const Icon = kind.icon;
  const severityLines = item.severity_and_exploitation
    ? item.severity_and_exploitation.split(";").map((s) => s.trim()).filter(Boolean)
    : [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-oyster-text bg-oyster-surface border border-oyster-border px-2.5 py-1 rounded-lg">
          <Icon size={14} className="text-oyster-accent shrink-0" />
          {item.identifier}
        </span>
        <span className="text-[10px] uppercase tracking-wide text-oyster-muted bg-oyster-bg px-1.5 py-0.5 rounded border border-oyster-border">
          {kind.label}
        </span>
        {item.is_withdrawn && (
          <span className="inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-red-300 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
            <ShieldOff size={10} /> Withdrawn
          </span>
        )}
        {(item.retrieved_at || item.last_modified) && (
          <span className="text-[11px] text-oyster-muted ml-auto flex items-center gap-1">
            <Clock size={11} />
            {item.last_modified ? `Updated ${formatDate(item.last_modified)}` : `Retrieved ${formatDate(item.retrieved_at)}`}
          </span>
        )}
      </div>

      <InfoCard icon={Info} title="Direct Answer">
        <p className="whitespace-pre-wrap text-oyster-text/90">{item.direct_answer || "No summary available."}</p>
      </InfoCard>

      <InfoCard icon={AlertTriangle} title="Severity &amp; Exploitation" accent="text-amber-400">
        {severityLines.length > 0 ? (
          <ul className="space-y-1">
            {severityLines.map((line, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="text-amber-400/70 shrink-0">•</span>
                <span>{line}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p>No severity or exploitation data recorded.</p>
        )}
      </InfoCard>

      <InfoCard icon={Layers} title="Affected Systems">
        <p className="whitespace-pre-wrap">{item.affected_systems || "No affected-product data stored for this identifier."}</p>
      </InfoCard>

      <InfoCard icon={ClipboardCheck} title="Defensive Actions" accent="text-emerald-400">
        <p className="whitespace-pre-wrap">{item.defensive_actions || "No mitigations recorded."}</p>
      </InfoCard>

      <InfoCard icon={Search} title="Detection Guidance" accent="text-purple-400">
        <p className="whitespace-pre-wrap">
          {item.detection_guidance || "No Sigma/YARA detection coverage found in the imported set."}
        </p>
      </InfoCard>

      <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-2">
        <div className="flex items-center gap-2">
          <BookOpenCheck size={14} className="text-oyster-accent" />
          <h3 className="text-xs font-semibold text-oyster-text uppercase tracking-wide">Sources</h3>
        </div>
        {item.sources && item.sources.length > 0 ? (
          <ul className="space-y-1.5">
            {item.sources.map((s, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <ExternalLink size={12} className="text-oyster-muted mt-1 shrink-0" />
                <span className="min-w-0">
                  {s.source_url ? (
                    <a
                      href={s.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-oyster-accent hover:underline break-words"
                    >
                      {s.title || s.source_url}
                    </a>
                  ) : (
                    <span className="text-oyster-text">{s.title || "Untitled source"}</span>
                  )}
                  {s.publisher && <span className="text-[11px] text-oyster-muted"> · {s.publisher}</span>}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-oyster-muted">No sources recorded for this identifier.</p>
        )}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Not-found state — required per the backend's non-fabrication guarantee.
// -----------------------------------------------------------------------

function NotFoundState({ question, confidence }: { question: string; confidence: SecurityIntelConfidence }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 text-center py-14 px-4 bg-oyster-surface border border-oyster-border rounded-xl">
      <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
        <ShieldOff size={20} className="text-red-400" />
      </div>
      <p className="text-sm font-semibold text-oyster-text">Not found in local knowledge base</p>
      <p className="text-xs text-oyster-muted max-w-sm leading-relaxed">
        &ldquo;{question}&rdquo; looks like an exact identifier lookup, but nothing matching it is stored locally.
        {confidence.data_gap_warning ? ` ${confidence.data_gap_warning}.` : ""} Oyster does not fabricate
        vulnerability data — double-check the identifier, or install more Knowledge Packs.
      </p>
    </div>
  );
}

// -----------------------------------------------------------------------
// Expandable source (detection / mitigation / incident_response / cloud /
// general routes) — lazily resolves the full passage via resolveCitation.
// -----------------------------------------------------------------------

function ExpandableSource({ source, index }: { source: SecurityIntelSource; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const [passage, setPassage] = useState<CitationSource | null>(null);
  const [loadingPassage, setLoadingPassage] = useState(false);
  const [fetchFailed, setFetchFailed] = useState(false);

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (next && !passage && !fetchFailed && source.chunk_id) {
      setLoadingPassage(true);
      const c = await resolveCitation(source.chunk_id);
      if (c) setPassage(c);
      else setFetchFailed(true);
      setLoadingPassage(false);
    }
  }

  return (
    <div className="border border-oyster-border rounded-lg overflow-hidden bg-oyster-bg/40">
      <button
        onClick={toggle}
        aria-expanded={expanded}
        aria-label={`Toggle details for source ${index}: ${source.title || source.source_url || "untitled"}`}
        className="w-full flex items-center gap-2.5 px-3 py-2 hover:bg-oyster-surface/40 transition-colors text-left"
      >
        <span className="text-[10px] font-bold text-oyster-muted bg-oyster-surface px-1.5 py-0.5 rounded shrink-0">
          [{index}]
        </span>
        <span className="flex-1 min-w-0 text-xs text-oyster-text truncate font-medium">
          {source.title || source.source_url || "Untitled source"}
        </span>
        {source.publisher && <span className="hidden sm:inline text-[10px] text-oyster-muted shrink-0">{source.publisher}</span>}
        {source.trust_level && (
          <span className="text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 text-oyster-muted bg-oyster-surface border border-oyster-border">
            {source.trust_level}
          </span>
        )}
        {expanded ? <ChevronUp size={12} className="text-oyster-muted shrink-0" /> : <ChevronDown size={12} className="text-oyster-muted shrink-0" />}
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-1 border-t border-oyster-border/60 space-y-2">
          {loadingPassage ? (
            <div className="flex items-center gap-2 text-xs text-oyster-muted py-2">
              <Loader2 size={12} className="animate-spin" /> Loading passage…
            </div>
          ) : passage?.passage ? (
            <p className="text-xs text-oyster-muted leading-relaxed whitespace-pre-wrap">{passage.passage}</p>
          ) : fetchFailed ? (
            <p className="text-xs text-oyster-muted py-1">Could not load the full passage for this source.</p>
          ) : !source.chunk_id ? (
            <p className="text-xs text-oyster-muted py-1">No expandable passage recorded for this source.</p>
          ) : null}

          {source.retrieved_at && (
            <p className="text-[10px] text-oyster-muted">Retrieved {formatDate(source.retrieved_at)}</p>
          )}
          {source.source_url && (
            <a
              href={source.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-oyster-accent hover:underline break-all"
            >
              <ExternalLink size={11} /> {source.source_url}
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------
// detection / mitigation / incident_response / cloud / general
// -----------------------------------------------------------------------

function GeneralAnswer({ result }: { result: SecurityIntelAnswer }) {
  const Icon = ROUTE_ICON[result.route] ?? HelpCircle;
  const guidanceList =
    result.route === "detection" ? result.detection_guidance : result.route === "mitigation" ? result.defensive_actions : null;
  const noSynthesis = result.llm_available === false;

  return (
    <div className="space-y-3">
      <div className={`rounded-xl border p-4 space-y-2 ${noSynthesis ? "bg-amber-500/5 border-amber-500/20" : "bg-oyster-surface border-oyster-border"}`}>
        <div className="flex flex-wrap items-center gap-2">
          <Icon size={15} className={noSynthesis ? "text-amber-400" : "text-oyster-accent"} />
          <h3 className="text-sm font-semibold text-oyster-text">{ROUTE_META[result.route]?.label ?? "Answer"}</h3>
          {noSynthesis && (
            <span className="ml-auto inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-amber-300 bg-amber-500/10 border border-amber-500/25 px-1.5 py-0.5 rounded">
              <AlertTriangle size={10} /> No synthesized answer — showing sources
            </span>
          )}
        </div>
        <p className="text-sm text-oyster-muted leading-relaxed whitespace-pre-wrap">
          {result.direct_answer || "No summary available."}
        </p>
        {result.platforms && result.platforms.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {result.platforms.map((p) => (
              <span
                key={p}
                className="text-[10px] uppercase tracking-wide text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded"
              >
                {p}
              </span>
            ))}
          </div>
        )}
      </div>

      {guidanceList && guidanceList.length > 0 && (
        <InfoCard icon={ListFilter} title={result.route === "detection" ? "Detection Guidance" : "Mitigation Guidance"}>
          <ul className="space-y-1">
            {guidanceList.map((g, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="text-oyster-accent/70 shrink-0">•</span>
                <span>{g}</span>
              </li>
            ))}
          </ul>
        </InfoCard>
      )}

      {result.route === "version_check" && result.status && (
        <InfoCard icon={Package} title="Version verdict">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span
              className={`text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded ${VERSION_STATUS_CLS[result.status] ?? "text-oyster-muted bg-oyster-surface"}`}
            >
              {result.status.replace(/_/g, " ")}
            </span>
            {result.fixed_versions && result.fixed_versions.length > 0 && (
              <span className="text-xs text-oyster-muted">Fixed in: {result.fixed_versions.join(", ")}</span>
            )}
          </div>
          {result.matches && result.matches.length > 0 && (
            <ul className="space-y-1">
              {result.matches.map((m, i) => (
                <li key={i} className="flex flex-wrap gap-1.5 items-center">
                  <span className="text-oyster-accent/70 shrink-0">•</span>
                  <span className="font-mono text-xs">{m.advisory_id}</span>
                  <span className="text-[10px] uppercase text-oyster-muted">{m.verdict}</span>
                  {m.withdrawn && <span className="text-[10px] text-red-300">withdrawn</span>}
                </li>
              ))}
            </ul>
          )}
        </InfoCard>
      )}

      {result.route === "prioritization" && result.ranked && result.ranked.length > 0 && (
        <InfoCard icon={ArrowUpDown} title="Ranked by installed KEV/EPSS/CVSS data">
          <ul className="space-y-2">
            {result.ranked.map((r) => (
              <li key={r.cve_id} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs">{r.cve_id}</span>
                {r.found && r.band ? (
                  <>
                    <span className={`text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded ${BAND_CLS[r.band] ?? ""}`}>
                      {r.band}
                    </span>
                    <span className="text-xs text-oyster-muted">score {r.score?.toFixed(2)} · confidence {((r.confidence ?? 0) * 100).toFixed(0)}%</span>
                  </>
                ) : (
                  <span className="text-[10px] uppercase text-oyster-muted">not found locally</span>
                )}
              </li>
            ))}
          </ul>
          {result.note && <p className="text-[11px] text-oyster-muted mt-2 italic">{result.note}</p>}
        </InfoCard>
      )}

      <div className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-2">
        <div className="flex items-center gap-2">
          <BookOpenCheck size={14} className="text-oyster-accent" />
          <h3 className="text-xs font-semibold text-oyster-text uppercase tracking-wide">
            Sources{result.sources ? ` (${result.sources.length})` : ""}
          </h3>
        </div>
        {result.sources && result.sources.length > 0 ? (
          <div className="space-y-1.5">
            {result.sources.map((s, i) => (
              <ExpandableSource key={s.chunk_id ?? i} source={s} index={i + 1} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-oyster-muted">No sources found for this question.</p>
        )}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// vulnerability_filter listing table — client-side filter + sort
// -----------------------------------------------------------------------

type SortKey = "cve_id" | "cvss_v3_score" | "epss_score" | "kev_listed" | "kev_due_date";

function SortHeader({
  label,
  active,
  dir,
  onClick,
}: {
  label: string;
  active: boolean;
  dir: "asc" | "desc";
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1 uppercase tracking-wider text-[10px] font-semibold transition-colors ${
        active ? "text-oyster-text" : "text-oyster-muted hover:text-oyster-text"
      }`}
    >
      {label}
      {active ? dir === "asc" ? <ArrowUp size={11} /> : <ArrowDown size={11} /> : <ArrowUpDown size={11} className="opacity-40" />}
    </button>
  );
}

function VulnListingTable({ rows }: { rows: SecurityIntelListingRow[] }) {
  const [severityFilter, setSeverityFilter] = useState("all");
  const [kevOnly, setKevOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("epss_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const severities = useMemo(() => {
    const set = new Set<string>();
    rows.forEach((r) => {
      if (r.cvss_v3_severity) set.add(r.cvss_v3_severity.toUpperCase());
    });
    return Array.from(set).sort();
  }, [rows]);

  const filtered = useMemo(() => {
    let out = rows;
    if (severityFilter !== "all") {
      out = out.filter((r) => (r.cvss_v3_severity ?? "").toUpperCase() === severityFilter);
    }
    if (kevOnly) out = out.filter((r) => r.kev_listed === 1);
    const q = search.trim().toLowerCase();
    if (q) {
      out = out.filter(
        (r) => r.cve_id.toLowerCase().includes(q) || (r.description ?? "").toLowerCase().includes(q)
      );
    }
    return [...out].sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av == null && bv == null) return 0;
      if (av == null) return 1; // nulls sort last regardless of direction
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }, [rows, severityFilter, kevOnly, search, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[140px]">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-oyster-muted" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by CVE id or description…"
            aria-label="Filter listing by CVE id or description"
            className="w-full bg-oyster-bg border border-oyster-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors"
          />
        </div>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          aria-label="Filter by CVSS severity"
          className="bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-1.5 text-xs text-oyster-text outline-none focus:border-oyster-accent/50 transition-colors"
        >
          <option value="all">All severities</option>
          {severities.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-oyster-muted cursor-pointer select-none px-1">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => setKevOnly(e.target.checked)}
            className="accent-oyster-accent"
          />
          KEV listed only
        </label>
        <span className="text-[11px] text-oyster-muted ml-auto shrink-0">
          {filtered.length} of {rows.length}
        </span>
      </div>

      <div className="overflow-x-auto border border-oyster-border rounded-xl">
        <table className="w-full min-w-[640px] text-left text-xs">
          <thead className="bg-oyster-surface/60 border-b border-oyster-border">
            <tr>
              <th className="px-3 py-2 font-normal">
                <SortHeader label="CVE" active={sortKey === "cve_id"} dir={sortDir} onClick={() => toggleSort("cve_id")} />
              </th>
              <th className="px-3 py-2 font-normal text-[10px] uppercase tracking-wider text-oyster-muted">Description</th>
              <th className="px-3 py-2 font-normal">
                <SortHeader label="CVSS" active={sortKey === "cvss_v3_score"} dir={sortDir} onClick={() => toggleSort("cvss_v3_score")} />
              </th>
              <th className="px-3 py-2 font-normal">
                <SortHeader label="EPSS" active={sortKey === "epss_score"} dir={sortDir} onClick={() => toggleSort("epss_score")} />
              </th>
              <th className="px-3 py-2 font-normal">
                <SortHeader label="KEV" active={sortKey === "kev_listed"} dir={sortDir} onClick={() => toggleSort("kev_listed")} />
              </th>
              <th className="px-3 py-2 font-normal">
                <SortHeader label="KEV due" active={sortKey === "kev_due_date"} dir={sortDir} onClick={() => toggleSort("kev_due_date")} />
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-oyster-muted">
                  No rows match these filters.
                </td>
              </tr>
            ) : (
              filtered.map((r) => (
                <tr key={r.cve_id} className="border-b border-oyster-border/60 last:border-0 hover:bg-oyster-surface/30 transition-colors">
                  <td className="px-3 py-2 font-mono text-oyster-text whitespace-nowrap">{r.cve_id}</td>
                  <td className="px-3 py-2 text-oyster-muted max-w-[320px]">
                    <span className="line-clamp-2">{r.description || "—"}</span>
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    {r.cvss_v3_score != null ? (
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${severityCls(r.cvss_v3_severity)}`}>
                        {r.cvss_v3_score.toFixed(1)}
                        {r.cvss_v3_severity ? ` ${r.cvss_v3_severity.toUpperCase()}` : ""}
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-3 py-2 text-oyster-text whitespace-nowrap">
                    {r.epss_score != null ? `${(r.epss_score * 100).toFixed(1)}%` : "—"}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    {r.kev_listed === 1 ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30">
                        <AlertTriangle size={10} /> KEV
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-3 py-2 text-oyster-muted whitespace-nowrap">
                    {r.kev_due_date ? formatDate(r.kev_due_date) : "—"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------
// Empty / loading states
// -----------------------------------------------------------------------

function EmptyState({ onExample }: { onExample: (q: string) => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 text-center py-16 px-4">
      <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
        <ShieldQuestion size={20} className="text-oyster-muted" />
      </div>
      <div className="space-y-1 max-w-md">
        <p className="text-sm font-medium text-oyster-text">Ask anything security</p>
        <p className="text-xs text-oyster-muted leading-relaxed">
          Look up an exact CVE, CWE, CAPEC, ATT&amp;CK technique, or D3FEND countermeasure; list known exploited
          vulnerabilities; or ask a detection, mitigation, incident-response, or cloud question. Every answer is
          grounded in the local knowledge base with sources — nothing is fabricated.
        </p>
      </div>
      <div className="flex flex-wrap justify-center gap-1.5 max-w-lg">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            onClick={() => onExample(ex)}
            className="text-xs text-oyster-muted hover:text-oyster-accent bg-oyster-surface hover:bg-oyster-surface/80 border border-oyster-border hover:border-oyster-accent/40 rounded-full px-3 py-1.5 transition-colors"
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  );
}

function LoadingSkeleton() {
  return (
    <div className="space-y-3" aria-live="polite" aria-busy="true">
      <div className="flex items-center justify-center gap-2 text-sm text-oyster-muted py-4">
        <Loader2 size={16} className="animate-spin" /> Consulting the local knowledge base…
      </div>
      {[0, 1, 2].map((i) => (
        <div key={i} className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-2 animate-pulse">
          <div className="h-3 w-1/3 bg-oyster-border rounded" />
          <div className="h-2.5 w-full bg-oyster-border/70 rounded" />
          <div className="h-2.5 w-5/6 bg-oyster-border/70 rounded" />
        </div>
      ))}
    </div>
  );
}

// -----------------------------------------------------------------------
// Panel
// -----------------------------------------------------------------------

export function SecurityIntelligencePanel({ onToggleSidebar, sidebarOpen, selectedModel }: SecurityIntelligencePanelProps) {
  const [query, setQuery] = useState("");
  const [hint, setHint] = useState<SecurityIntelClassification | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SecurityIntelAnswer | null>(null);
  const requestIdRef = useRef(0);

  // Debounced classify-as-you-type hint. Guarded against out-of-order
  // responses with a monotonic request id — a slow earlier call must never
  // overwrite the hint for what the user has since typed.
  useEffect(() => {
    const q = query.trim();
    if (q.length < 3) {
      setHint(null);
      return;
    }
    const id = ++requestIdRef.current;
    const t = setTimeout(() => {
      void classifySecurityQuestion(q).then((c) => {
        if (requestIdRef.current === id) setHint(c);
      });
    }, 350);
    return () => clearTimeout(t);
  }, [query]);

  const runSearch = useCallback(
    async (raw: string) => {
      const question = raw.trim();
      if (!question || loading) return;
      setLoading(true);
      setError(null);
      try {
        const data = await askSecurityIntelligence(question, selectedModel, 8);
        setResult(data);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Security intelligence lookup failed.");
        setResult(null);
      } finally {
        setLoading(false);
      }
    },
    [loading, selectedModel]
  );

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    void runSearch(query);
  }

  function handleExample(q: string) {
    setQuery(q);
    void runSearch(q);
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button
            onClick={onToggleSidebar}
            aria-label="Open sidebar"
            className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface"
          >
            <PanelLeftOpen size={18} />
          </button>
        )}
        <ShieldQuestion size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Security Intelligence</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1 hidden sm:inline-block">
          CVE · CWE · CAPEC · ATT&amp;CK · D3FEND
        </span>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-5">
          <form onSubmit={handleSubmit} className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-3">
            <label htmlFor="intel-query" className="text-xs font-semibold text-oyster-muted uppercase tracking-wider">
              Ask a security question
            </label>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
              <div className="relative flex-1 min-w-0">
                <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-oyster-muted" />
                <input
                  id="intel-query"
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="e.g. Tell me about CVE-2021-44228, or how do I detect T1055?"
                  className="w-full bg-oyster-bg border border-oyster-border rounded-lg pl-9 pr-3 py-2.5 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors"
                />
              </div>
              <button
                type="submit"
                disabled={!query.trim() || loading}
                className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all shrink-0 ${
                  !query.trim() || loading
                    ? "bg-oyster-border text-oyster-muted cursor-not-allowed"
                    : "bg-oyster-accent hover:bg-oyster-accent-hover text-white"
                }`}
              >
                {loading ? <Loader2 size={15} className="animate-spin" /> : <ShieldQuestion size={15} />}
                {loading ? "Looking up…" : "Ask"}
              </button>
            </div>
            {hint && (
              <div
                className={`inline-flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-1 rounded-full border ${
                  ROUTE_META[hint.route]?.cls ?? "text-oyster-muted bg-oyster-surface border-oyster-border"
                }`}
              >
                <Sparkles size={11} /> {classifyHintText(hint)}
              </div>
            )}
          </form>

          {error && (
            <div className="flex items-start gap-3 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
              <AlertCircle size={15} className="text-red-400 shrink-0 mt-0.5" />
              <div className="text-sm text-red-400">
                <p className="font-medium">Couldn&rsquo;t reach Security Intelligence.</p>
                <p className="text-xs mt-0.5 text-red-400/80">{error}</p>
              </div>
            </div>
          )}

          {loading && <LoadingSkeleton />}

          {!loading && result && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`inline-flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-1 rounded-full border ${
                    ROUTE_META[result.route]?.cls ?? "text-oyster-muted bg-oyster-surface border-oyster-border"
                  }`}
                >
                  {ROUTE_META[result.route]?.label ?? result.route}
                </span>
                <ConfidenceBadge confidence={result.confidence} />
              </div>

              {result.confidence.level !== "grounded" && result.confidence.data_gap_warning && (
                <div className="flex items-start gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
                  <AlertTriangle size={13} className="shrink-0 mt-0.5" />
                  {result.confidence.data_gap_warning}
                </div>
              )}

              {result.route === "exact_lookup" ? (
                result.items && result.items.length > 0 ? (
                  <div className="space-y-6">
                    {result.items.map((item) => (
                      <ExactItemCard key={item.identifier} item={item} />
                    ))}
                  </div>
                ) : (
                  <NotFoundState question={result.question} confidence={result.confidence} />
                )
              ) : result.route === "vulnerability_filter" ? (
                <div className="space-y-6">
                  {result.items && result.items.length > 0 && (
                    <div className="space-y-6">
                      {result.items.map((item) => (
                        <ExactItemCard key={item.identifier} item={item} />
                      ))}
                    </div>
                  )}
                  {result.listing && result.listing.length > 0 ? (
                    <VulnListingTable rows={result.listing} />
                  ) : (
                    <p className="text-sm text-oyster-muted text-center py-6">
                      No matching vulnerabilities in the local listing.
                    </p>
                  )}
                </div>
              ) : (
                <GeneralAnswer result={result} />
              )}
            </div>
          )}

          {!loading && !error && !result && <EmptyState onExample={handleExample} />}
        </div>
      </div>
    </div>
  );
}
