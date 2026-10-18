"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  Bug,
  PanelLeftOpen,
  Loader2,
  Trash2,
  ChevronDown,
  ChevronRight,
  MessageSquare,
  Share2,
  Link2,
  Check,
  Pencil,
  ClipboardCheck,
  Plus,
  AlertCircle,
  Globe,
  Lock,
  UserCircle2,
  MessageSquarePlus,
  Download,
} from "lucide-react";
import { type Severity, type UserFinding } from "@/types/chat";
import {
  listFindings,
  createUserFinding,
  updateFinding,
  deleteFinding,
  shareFinding,
  revokeFinding,
  listPublicFindings,
  exportFindingsReport,
  type PublicFinding,
} from "@/lib/api";

interface FindingsPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
  /** The active project — findings are scoped to it, exactly like artifacts. */
  projectId: string;
  /** Jump into the source chat (chat-captured findings only). */
  onOpenChat: (finding: UserFinding) => void;
  /** Start a new chat in the viewer's own workspace, seeded with a published
   *  finding plus the question the viewer actually wants to ask about it. */
  onReuseFinding: (finding: PublicFinding, question: string) => void;
  /** Bumped by the parent when a finding is created from the message toolbar. */
  refreshKey?: number;
}

/** "mine" and "report" are your own findings; "public" is the community feed —
 *  everything anyone chose to publish, yours included. */
type Filter = "all" | "report" | "public";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info: "bg-oyster-surface text-oyster-muted border-oyster-border",
};

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "N/A"];

/** The public URL for a shared finding, built client-side so it is right for
 *  whatever host/basePath this deploy uses (the backend returns only a token). */
function shareUrl(token: string): string {
  const base = process.env.NEXT_PUBLIC_BASE_PATH || "";
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return `${origin}${base}/shared/${token}`;
}

export function FindingsPanel({
  onToggleSidebar,
  sidebarOpen,
  projectId,
  onOpenChat,
  onReuseFinding,
  refreshKey,
}: FindingsPanelProps) {
  const [findings, setFindings] = useState<UserFinding[]>([]);
  const [publicFeed, setPublicFeed] = useState<PublicFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [showForm, setShowForm] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const data = await listFindings(projectId || undefined);
    setFindings(data);
    setLoading(false);
  }, [projectId]);

  const loadFeed = useCallback(async () => {
    setLoading(true);
    setPublicFeed(await listPublicFindings());
    setLoading(false);
  }, []);

  useEffect(() => {
    if (filter === "public") loadFeed();
    else load();
  }, [filter, load, loadFeed, refreshKey]);

  const reportCount = findings.filter((f) => f.in_report).length;
  const visible = filter === "report" ? findings.filter((f) => f.in_report) : findings;

  const patchLocal = (updated: UserFinding) =>
    setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));

  async function handlePatch(id: string, patch: Parameters<typeof updateFinding>[1]) {
    const updated = await updateFinding(id, patch);
    if (updated) patchLocal(updated);
  }

  async function handleDelete(id: string) {
    if (await deleteFinding(id)) setFindings((prev) => prev.filter((f) => f.id !== id));
  }

  async function handleShare(id: string) {
    const token = await shareFinding(id);
    const cur = findings.find((f) => f.id === id);
    if (token && cur) patchLocal({ ...cur, shared: true, share_token: token });
  }

  async function handleUnshare(id: string) {
    const cur = findings.find((f) => f.id === id);
    if ((await revokeFinding(id)) && cur) patchLocal({ ...cur, shared: false, share_token: null });
  }

  /** Un-publish one of your own straight from the feed — it disappears from
   *  everyone's feed immediately, and stays in your own list. */
  async function handleUnshareFromFeed(id: string) {
    if (await revokeFinding(id)) {
      setPublicFeed((prev) => prev.filter((f) => f.id !== id));
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? { ...f, shared: false, share_token: null } : f))
      );
    }
  }

  async function handleExport() {
    const blob = await exportFindingsReport();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "oyster-investigation-report.md";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="flex flex-col flex-1 min-w-0 h-app">
      <header className="flex items-center gap-3 px-4 py-3 border-b border-oyster-border bg-oyster-bg/80 backdrop-blur-sm shrink-0">
        {!sidebarOpen && (
          <button
            onClick={onToggleSidebar}
            className="text-oyster-muted hover:text-oyster-text transition-colors p-1.5 rounded-md hover:bg-oyster-surface"
          >
            <PanelLeftOpen size={18} />
          </button>
        )}
        <Bug size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Findings</span>
        {filter !== "public" && findings.length > 0 && (
          <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border">
            {findings.length}
          </span>
        )}

        <div className="ml-auto flex items-center gap-1 text-xs">
          {(["all", "report", "public"] as Filter[]).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`cursor-pointer flex items-center gap-1.5 px-2.5 py-1 rounded-md font-medium transition-colors ${
                filter === f
                  ? "bg-oyster-accent/15 text-oyster-accent"
                  : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface"
              }`}
            >
              {f === "public" && <Globe size={12} />}
              {f === "all" ? "Mine" : f === "report" ? `In report${reportCount ? ` (${reportCount})` : ""}` : "Public"}
            </button>
          ))}
          {filter !== "public" && (
            <button
              onClick={() => void handleExport()}
              disabled={reportCount === 0}
              title={reportCount === 0 ? "Add findings to the report first" : "Download Markdown report"}
              className="cursor-pointer ml-1 flex items-center gap-1.5 text-oyster-muted hover:text-oyster-text disabled:opacity-40 disabled:cursor-not-allowed px-2 py-1.5 rounded-lg transition-colors"
            >
              <Download size={13} />
              Export
            </button>
          )}
          {filter !== "public" && (
            <button
              onClick={() => setShowForm((v) => !v)}
              className="cursor-pointer ml-1 flex items-center gap-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 px-3 py-1.5 rounded-lg transition-colors"
            >
              <Plus size={13} />
              Log finding
            </button>
          )}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-3">
          {showForm && (
            <LogFindingForm
              onCancel={() => setShowForm(false)}
              onSaved={(f) => {
                setFindings((prev) => [f, ...prev]);
                setShowForm(false);
              }}
            />
          )}

          {loading ? (
            <div className="flex justify-center py-10">
              <Loader2 size={20} className="text-oyster-muted animate-spin" />
            </div>
          ) : filter === "public" ? (
            publicFeed.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
                <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
                  <Globe size={20} className="text-oyster-muted" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-medium text-oyster-text">Nothing published yet</p>
                  <p className="text-xs text-oyster-muted max-w-sm">
                    Findings people publish show up here for everyone signed in. Open one of your
                    own and hit <span className="text-oyster-accent">Make public</span> to be first.
                  </p>
                </div>
              </div>
            ) : (
              <>
                <p className="text-xs text-oyster-muted pb-1">
                  {publicFeed.length} published finding{publicFeed.length !== 1 ? "s" : ""} from the
                  community. Yours are marked — you can make them private again at any time.
                </p>
                {publicFeed.map((f) => (
                  <PublicFindingCard
                    key={f.id}
                    finding={f}
                    expanded={expandedId === f.id}
                    onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
                    onMakePrivate={() => handleUnshareFromFeed(f.id)}
                    onReuse={(question) => onReuseFinding(f, question)}
                  />
                ))}
              </>
            )
          ) : visible.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
              <div className="w-12 h-12 rounded-xl bg-oyster-surface border border-oyster-border flex items-center justify-center">
                <Bug size={20} className="text-oyster-muted" />
              </div>
              <div className="space-y-1">
                {filter === "report" ? (
                  <>
                    <p className="text-sm font-medium text-oyster-text">Nothing in the report yet</p>
                    <p className="text-xs text-oyster-muted max-w-xs">
                      Hover a reply and click <span className="text-red-400">Add to Report</span>, or
                      flag an existing finding with its report toggle.
                    </p>
                  </>
                ) : (
                  <>
                    <p className="text-sm font-medium text-oyster-text">No findings yet</p>
                    <p className="text-xs text-oyster-muted max-w-xs">
                      Hover any reply and click <span className="text-red-400">Create Finding</span>,
                      or use <span className="text-red-400">Log finding</span> above to record a
                      vulnerability with severity, endpoint and a recommended fix.
                    </p>
                  </>
                )}
              </div>
            </div>
          ) : (
            visible.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                expanded={expandedId === f.id}
                onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
                onPatch={(patch) => handlePatch(f.id, patch)}
                onDelete={() => handleDelete(f.id)}
                onShare={() => handleShare(f.id)}
                onUnshare={() => handleUnshare(f.id)}
                onOpenChat={() => onOpenChat(f)}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}

/** Manual finding entry — the old Red-Team Evidence form, now writing to the
 *  same per-user, project-scoped store as chat-captured findings. */
function LogFindingForm({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: (f: UserFinding) => void;
}) {
  const [severity, setSeverity] = useState<Severity>("high");
  const [title, setTitle] = useState("");
  const [asset, setAsset] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [method, setMethod] = useState("POST");
  const [steps, setSteps] = useState("");
  const [notes, setNotes] = useState("");
  const [fix, setFix] = useState("");
  const [unresolved, setUnresolved] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSave = title.trim().length > 0 && !saving;

  async function save() {
    if (!canSave) return;
    setSaving(true);
    setError(null);
    const created = await createUserFinding({
      title: title.trim(),
      // `content` is the body for every finding — for a manual one that is the
      // reproduction steps, so there is a single field rather than two.
      content: steps.trim() || title.trim(),
      severity,
      affected_asset: asset.trim(),
      endpoint: endpoint.trim(),
      method,
      notes: notes.trim(),
      recommended_fix: fix.trim(),
      unresolved_questions: unresolved.trim(),
    });
    setSaving(false);
    if (created) onSaved(created);
    else setError("Couldn’t save that finding. Check you’re still signed in.");
  }

  const field =
    "w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50 transition-colors";
  const label = "text-xs font-semibold text-oyster-muted uppercase tracking-wider";

  return (
    <div className="bg-oyster-surface border border-red-500/20 rounded-xl p-5 space-y-4">
      <p className="text-xs font-semibold text-red-400 uppercase tracking-wider">New finding</p>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <label className={label} htmlFor="f-sev">Severity</label>
          <select id="f-sev" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)} className={`${field} cursor-pointer`}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1.5">
          <label className={label} htmlFor="f-method">Method</label>
          <select id="f-method" value={method} onChange={(e) => setMethod(e.target.value)} className={`${field} cursor-pointer`}>
            {METHODS.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-title">Title</label>
        <input id="f-title" value={title} onChange={(e) => setTitle(e.target.value)}
          placeholder="e.g. Unrestricted file upload allows executable upload" className={field} />
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-asset">Affected asset <span className="normal-case font-normal">(optional)</span></label>
        <input id="f-asset" value={asset} onChange={(e) => setAsset(e.target.value)}
          placeholder="e.g. web-app-03.acme.internal (10.50.2.17)" className={`${field} font-mono`} />
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-endpoint">Affected endpoint <span className="normal-case font-normal">(optional)</span></label>
        <input id="f-endpoint" value={endpoint} onChange={(e) => setEndpoint(e.target.value)}
          placeholder="e.g. /api/documents/upload" className={`${field} font-mono`} />
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-steps">Steps to reproduce</label>
        <textarea id="f-steps" value={steps} onChange={(e) => setSteps(e.target.value)} rows={3}
          placeholder={"1. Upload a file with .php extension\n2. Observe the server accepts it"}
          className={`${field} resize-none`} />
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-notes">Notes / evidence <span className="normal-case font-normal">(optional)</span></label>
        <textarea id="f-notes" value={notes} onChange={(e) => setNotes(e.target.value)} rows={2}
          placeholder="What was observed, or paste the response body…" className={`${field} resize-none`} />
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-fix">Recommended fix <span className="normal-case font-normal">(optional)</span></label>
        <textarea id="f-fix" value={fix} onChange={(e) => setFix(e.target.value)} rows={2}
          placeholder="e.g. Validate MIME type server-side; allow only .pdf and .txt"
          className={`${field} resize-none`} />
      </div>

      <div className="space-y-1.5">
        <label className={label} htmlFor="f-unresolved">
          Unresolved questions <span className="normal-case font-normal">(optional)</span>
        </label>
        <textarea id="f-unresolved" value={unresolved} onChange={(e) => setUnresolved(e.target.value)} rows={2}
          placeholder="e.g. Whether the same flaw exists in the legacy endpoint was not checked"
          className={`${field} resize-none`} />
      </div>

      {error && (
        <div className="flex items-center gap-2 text-sm text-red-400">
          <AlertCircle size={14} />
          {error}
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={save}
          disabled={!canSave}
          className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium transition-colors ${
            canSave
              ? "bg-oyster-accent hover:bg-oyster-accent-hover text-white cursor-pointer"
              : "bg-oyster-border text-oyster-muted cursor-not-allowed"
          }`}
        >
          {saving ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          {saving ? "Saving…" : "Save finding"}
        </button>
        <button
          onClick={onCancel}
          className="cursor-pointer px-4 py-2 text-sm text-oyster-muted hover:text-oyster-text border border-oyster-border rounded-lg transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

function FindingCard({
  finding,
  expanded,
  onToggle,
  onPatch,
  onDelete,
  onShare,
  onUnshare,
  onOpenChat,
}: {
  finding: UserFinding;
  expanded: boolean;
  onToggle: () => void;
  onPatch: (patch: Parameters<typeof updateFinding>[1]) => void;
  onDelete: () => void;
  onShare: () => void;
  onUnshare: () => void;
  onOpenChat: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(finding.title);
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => setTitle(finding.title), [finding.title]);

  const commit = () => {
    setEditing(false);
    const next = title.trim();
    if (next && next !== finding.title) onPatch({ title: next });
    else setTitle(finding.title);
  };

  const copyLink = async () => {
    if (!finding.share_token) return;
    try {
      await navigator.clipboard.writeText(shareUrl(finding.share_token));
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable */
    }
  };

  const date = new Date(finding.created_at).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  return (
    <div className="bg-oyster-surface border border-oyster-border rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3">
        <button onClick={onToggle} className="cursor-pointer text-oyster-muted hover:text-oyster-text shrink-0" aria-label="Toggle">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>

        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider shrink-0 ${SEVERITY_COLORS[finding.severity] ?? SEVERITY_COLORS.info}`}>
          {finding.severity}
        </span>

        {editing ? (
          <input
            ref={inputRef}
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
              if (e.key === "Enter") { e.preventDefault(); commit(); }
              if (e.key === "Escape") { e.preventDefault(); setTitle(finding.title); setEditing(false); }
            }}
            aria-label="Finding title"
            className="flex-1 bg-oyster-bg border border-oyster-accent/50 rounded-md px-2 py-1 text-sm text-oyster-text outline-none"
          />
        ) : (
          <button onClick={() => setEditing(true)} title="Click to rename"
            className="cursor-pointer flex-1 min-w-0 flex items-center gap-1.5 text-left group/title">
            <span className="text-sm font-medium text-oyster-text truncate">{finding.title}</span>
            <Pencil size={11} className="text-oyster-muted opacity-0 group-hover/title:opacity-100 shrink-0" />
          </button>
        )}

        {finding.endpoint && (
          <span className="hidden lg:inline text-[11px] text-oyster-muted font-mono truncate max-w-[220px] shrink-0">
            {finding.method} {finding.endpoint}
          </span>
        )}
        {finding.in_report && (
          <span className="hidden sm:inline text-[10px] text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded shrink-0">
            In report
          </span>
        )}
        {finding.shared && (
          <span className="hidden sm:inline text-[10px] text-oyster-accent bg-oyster-accent/10 border border-oyster-accent/20 px-1.5 py-0.5 rounded shrink-0">
            Public
          </span>
        )}
        <span className="hidden md:inline text-[10px] text-oyster-muted shrink-0">{date}</span>

        <button
          onClick={() => onPatch({ in_report: !finding.in_report })}
          title={finding.in_report ? "Remove from report" : "Add to report"}
          className={`cursor-pointer p-1.5 rounded-md transition-colors shrink-0 ${
            finding.in_report
              ? "text-red-400 hover:text-red-300 hover:bg-red-500/10"
              : "text-oyster-muted hover:text-red-400 hover:bg-red-500/10"
          }`}
        >
          <ClipboardCheck size={13} />
        </button>
        {finding.conversation_id && (
          <button onClick={onOpenChat} title="Open the source chat"
            className="cursor-pointer p-1.5 rounded-md text-oyster-muted hover:text-oyster-accent hover:bg-oyster-bg/60 transition-colors shrink-0">
            <MessageSquare size={13} />
          </button>
        )}
        <button onClick={onDelete} title="Delete finding"
          className="cursor-pointer p-1.5 rounded-md text-oyster-muted hover:text-red-400 hover:bg-red-500/10 transition-colors shrink-0">
          <Trash2 size={13} />
        </button>
      </div>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-oyster-border/60 pt-3">
          {/* Severity is editable after the fact — triage usually happens later. */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-semibold text-oyster-muted uppercase tracking-wider">Severity</span>
            <select
              value={finding.severity}
              onChange={(e) => onPatch({ severity: e.target.value as Severity })}
              aria-label="Severity"
              className="cursor-pointer bg-oyster-bg border border-oyster-border rounded-md px-2 py-1 text-xs text-oyster-text outline-none focus:border-oyster-accent/50"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            {finding.endpoint && (
              <span className="text-[11px] text-oyster-muted font-mono">
                {finding.method} {finding.endpoint}
              </span>
            )}
          </div>

          <div className="prose prose-sm max-w-none max-h-80 overflow-y-auto rounded-lg bg-oyster-bg/50 border border-oyster-border px-3 py-2">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.content}</ReactMarkdown>
          </div>

          {finding.affected_asset && <Detail label="Affected asset" value={finding.affected_asset} />}
          {finding.notes && <Detail label="Notes / evidence" value={finding.notes} />}
          {finding.recommended_fix && <Detail label="Recommended fix" value={finding.recommended_fix} />}
          {finding.unresolved_questions && (
            <Detail label="Unresolved questions" value={finding.unresolved_questions} />
          )}

          <div className="flex flex-wrap items-center gap-2">
            {!finding.shared ? (
              <button onClick={onShare}
                className="cursor-pointer flex items-center gap-1.5 text-xs text-oyster-accent bg-oyster-accent/10 hover:bg-oyster-accent/20 border border-oyster-accent/20 px-2.5 py-1.5 rounded-lg transition-colors">
                <Share2 size={12} />
                Make public
              </button>
            ) : (
              <>
                <button onClick={copyLink}
                  className="cursor-pointer flex items-center gap-1.5 text-xs text-oyster-text bg-oyster-bg hover:bg-oyster-surface border border-oyster-border px-2.5 py-1.5 rounded-lg transition-colors">
                  {copied ? <Check size={12} className="text-oyster-accent" /> : <Link2 size={12} />}
                  {copied ? "Copied" : "Copy link"}
                </button>
                <button onClick={onUnshare}
                  className="cursor-pointer text-xs text-oyster-muted hover:text-red-400 px-2 py-1.5 rounded-lg transition-colors">
                  Make private
                </button>
                {finding.share_token && (
                  <span className="text-[11px] text-oyster-muted font-mono truncate max-w-full">
                    {shareUrl(finding.share_token)}
                  </span>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** A finding on the community feed — read-only, except that you can un-publish
 *  your own. Shows the author's handle (a nickname or "User 7"), never an email. */
function PublicFindingCard({
  finding,
  expanded,
  onToggle,
  onMakePrivate,
  onReuse,
}: {
  finding: PublicFinding;
  expanded: boolean;
  onToggle: () => void;
  onMakePrivate: () => void;
  onReuse: (question: string) => void;
}) {
  // Reuse asks WHAT you want before starting the chat: two ready-made questions
  // and an "Ask something else" box, so the opening message is the one the
  // person actually meant rather than a canned sentence chosen for them.
  const [asking, setAsking] = useState(false);
  const [writingOwn, setWritingOwn] = useState(false);
  const [custom, setCustom] = useState("");

  // A finding is not always a vulnerability, so the second preset follows what
  // this one actually is: anything with a severity or an affected endpoint
  // reads as a security issue, everything else as a technique or write-up.
  const looksLikeVuln =
    (finding.severity && finding.severity !== "info") || !!finding.endpoint?.trim();
  const presets = [
    "Explain this in depth — how it works and why it happens.",
    looksLikeVuln
      ? "How would I verify this safely within my own authorised scope?"
      : "How could I apply this in my own work? Walk me through it.",
  ];

  const start = (question: string) => {
    const q = question.trim();
    if (!q) return;
    onReuse(q);
    setAsking(false);
    setWritingOwn(false);
    setCustom("");
  };

  const when = new Date(finding.shared_at || finding.created_at).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

  return (
    <div
      className={`bg-oyster-surface border rounded-xl overflow-hidden ${
        finding.is_mine ? "border-oyster-accent/30" : "border-oyster-border"
      }`}
    >
      <div className="flex items-center gap-2 px-4 py-3">
        <button onClick={onToggle} className="cursor-pointer text-oyster-muted hover:text-oyster-text shrink-0" aria-label="Toggle">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>

        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wider shrink-0 ${SEVERITY_COLORS[finding.severity] ?? SEVERITY_COLORS.info}`}>
          {finding.severity}
        </span>

        <button onClick={onToggle} className="cursor-pointer flex-1 min-w-0 text-left">
          <span className="text-sm font-medium text-oyster-text truncate block">{finding.title}</span>
        </button>

        <span className="hidden sm:flex items-center gap-1.5 text-[11px] text-oyster-muted shrink-0">
          <UserCircle2 size={12} />
          {finding.author}
          {finding.is_mine && <span className="text-oyster-accent">(you)</span>}
        </span>
        <span className="hidden md:inline text-[10px] text-oyster-muted shrink-0">{when}</span>

        {/* Reuse — the point of a shared feed. Starts a fresh chat in YOUR
            workspace seeded with this finding; the original is untouched. */}
        <button
          onClick={() => setAsking((v) => !v)}
          title="Start a new chat from this finding"
          aria-expanded={asking}
          className={`cursor-pointer flex items-center gap-1.5 border px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-colors shrink-0 ${
            asking
              ? "bg-green-500/20 text-green-300 border-green-500/40"
              : "bg-green-500/10 hover:bg-green-500/20 text-green-400 border-green-500/20"
          }`}
        >
          <MessageSquarePlus size={12} />
          <span className="hidden sm:inline">Use this</span>
        </button>

        {finding.is_mine && (
          <button
            onClick={onMakePrivate}
            title="Make private — removes it from everyone's feed"
            className="cursor-pointer flex items-center gap-1 text-[11px] text-oyster-muted hover:text-red-400 hover:bg-red-500/10 px-2 py-1 rounded-md transition-colors shrink-0"
          >
            <Lock size={11} />
            <span className="hidden sm:inline">Make private</span>
          </button>
        )}
      </div>

      {/* What do you want to ask? Two ready-made questions, or write your own. */}
      {asking && (
        <div className="px-4 pb-4 pt-1 space-y-2 border-t border-green-500/20 bg-green-500/[0.03]">
          <p className="text-[11px] text-oyster-muted pt-2">
            Start a chat about <span className="text-oyster-text">{finding.title}</span> — what do
            you want to ask?
          </p>

          {presets.map((p) => (
            <button
              key={p}
              onClick={() => start(p)}
              className="cursor-pointer w-full text-left text-xs text-oyster-text bg-oyster-bg/60 hover:bg-green-500/10 border border-oyster-border hover:border-green-500/30 rounded-lg px-3 py-2 transition-colors"
            >
              {p}
            </button>
          ))}

          {!writingOwn ? (
            <button
              onClick={() => setWritingOwn(true)}
              className="cursor-pointer w-full text-left text-xs text-oyster-muted hover:text-oyster-text bg-oyster-bg/40 hover:bg-oyster-surface border border-dashed border-oyster-border rounded-lg px-3 py-2 transition-colors"
            >
              Ask something else…
            </button>
          ) : (
            <div className="space-y-2">
              <textarea
                autoFocus
                value={custom}
                onChange={(e) => setCustom(e.target.value)}
                onKeyDown={(e) => {
                  // Enter sends, Shift+Enter makes a new line — same as the composer.
                  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); start(custom); }
                  if (e.key === "Escape") { e.preventDefault(); setWritingOwn(false); }
                }}
                rows={2}
                placeholder="e.g. Does this apply to a GraphQL endpoint too?"
                aria-label="Your question about this finding"
                className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2 text-xs text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-green-500/40 transition-colors"
              />
              <div className="flex items-center gap-2">
                <button
                  onClick={() => start(custom)}
                  disabled={!custom.trim()}
                  className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors ${
                    custom.trim()
                      ? "cursor-pointer bg-green-500/15 hover:bg-green-500/25 text-green-400 border border-green-500/30"
                      : "cursor-not-allowed bg-oyster-border/50 text-oyster-muted border border-transparent"
                  }`}
                >
                  <MessageSquarePlus size={12} />
                  Start chat
                </button>
                <button
                  onClick={() => { setWritingOwn(false); setCustom(""); }}
                  className="cursor-pointer text-xs text-oyster-muted hover:text-oyster-text px-2 py-1.5 transition-colors"
                >
                  Back
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-oyster-border/60 pt-3">
          {finding.endpoint && (
            <p className="text-[11px] text-oyster-muted font-mono">
              {finding.method} {finding.endpoint}
            </p>
          )}
          {/* This renders PublicFinding (the published/shared projection), which
             deliberately omits affected_asset/unresolved_questions for now —
             see services/user_findings_service.list_public / get_by_token. */}
          <div className="prose prose-sm max-w-none max-h-96 overflow-y-auto rounded-lg bg-oyster-bg/50 border border-oyster-border px-3 py-2">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.content}</ReactMarkdown>
          </div>
          {finding.recommended_fix && <Detail label="Recommended fix" value={finding.recommended_fix} />}
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              onClick={() => setAsking(true)}
              className="cursor-pointer flex items-center gap-1.5 bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/20 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors"
            >
              <MessageSquarePlus size={12} />
              Start a chat from this
            </button>
            <span className="text-[10px] text-oyster-muted">
              Shared by {finding.author} · {when}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-1">
      <p className="text-[10px] font-semibold text-oyster-muted uppercase tracking-wider">{label}</p>
      <p className="text-xs text-oyster-text leading-relaxed whitespace-pre-wrap">{value}</p>
    </div>
  );
}
