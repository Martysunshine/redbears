"use client";

import { useState, useEffect, useCallback } from "react";
import { X, Trash2, Pencil, Check, XCircle, Plus, Download, AlertTriangle, Loader2 } from "lucide-react";
import {
  listMemories,
  listPendingMemories,
  listMemoryConflicts,
  approveMemory,
  rejectMemory,
  deleteMemory,
  updateMemory,
  addMemory,
  exportMemory,
  resolveMemoryConflict,
  type MemoryItem,
  type ConflictGroup,
} from "@/lib/api";

interface MemoryPanelProps {
  projectId: string;
  onClose: () => void;
}

type Tab = "active" | "pending" | "conflicts";

const TYPE_LABEL: Record<string, string> = {
  fact: "Fact",
  preference: "Preference",
  decision: "Decision",
  instruction: "Instruction",
  project_detail: "Project detail",
};

export function MemoryPanel({ projectId, onClose }: MemoryPanelProps) {
  const [tab, setTab] = useState<Tab>("active");
  const [active, setActive] = useState<MemoryItem[]>([]);
  const [pending, setPending] = useState<MemoryItem[]>([]);
  const [conflicts, setConflicts] = useState<ConflictGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [a, p, c] = await Promise.all([
        listMemories(projectId, "active"),
        listPendingMemories(projectId),
        listMemoryConflicts(projectId),
      ]);
      setActive(a.memories);
      setPending(p.pending);
      setConflicts(c.conflicts);
    } catch {
      // backend offline — leave lists as-is
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleDelete(id: string) {
    setActive((prev) => prev.filter((m) => m.id !== id));
    await deleteMemory(projectId, id);
  }

  async function handleApprove(id: string) {
    setPending((prev) => prev.filter((m) => m.id !== id));
    await approveMemory(projectId, id);
    refresh();
  }

  async function handleReject(id: string) {
    setPending((prev) => prev.filter((m) => m.id !== id));
    await rejectMemory(projectId, id);
  }

  async function handleKeep(group: string, id: string) {
    setConflicts((prev) => prev.filter((g) => g.conflict_group !== group));
    await resolveMemoryConflict(projectId, group, id);
    refresh();
  }

  async function handleExport() {
    const data = await exportMemory(projectId);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `oyster-memory-${projectId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl max-h-[85vh] flex flex-col bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-oyster-border shrink-0">
          <h2 className="text-[15px] font-semibold text-oyster-text">Manage Memories</h2>
          <button onClick={onClose} className="cursor-pointer text-oyster-muted hover:text-oyster-text p-1 rounded">
            <X size={16} />
          </button>
        </div>

        <div className="flex items-center gap-1 px-5 pt-3 shrink-0">
          {([
            ["active", `Active (${active.length})`],
            ["pending", `Review${pending.length ? ` (${pending.length})` : ""}`],
            ["conflicts", `Conflicts${conflicts.length ? ` (${conflicts.length})` : ""}`],
          ] as [Tab, string][]).map(([t, label]) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`cursor-pointer px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${
                tab === t
                  ? "bg-oyster-accent/15 text-oyster-accent"
                  : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface"
              }`}
            >
              {label}
            </button>
          ))}
          <button
            onClick={() => setShowAdd((v) => !v)}
            className="cursor-pointer ml-auto flex items-center gap-1 text-xs text-oyster-accent hover:text-oyster-accent-hover px-2 py-1"
          >
            <Plus size={13} /> Add
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-2">
          {showAdd && <AddMemoryForm projectId={projectId} onDone={() => { setShowAdd(false); refresh(); }} />}

          {loading ? (
            <div className="flex justify-center py-10">
              <Loader2 size={18} className="text-oyster-muted animate-spin" />
            </div>
          ) : tab === "active" ? (
            active.length === 0 ? (
              <EmptyState text="No long-term memories yet. Oyster will pick up useful facts as you chat, or add one manually above." />
            ) : (
              active.map((m) => (
                <MemoryRow key={m.id} memory={m} projectId={projectId} onDelete={() => handleDelete(m.id)} onSaved={refresh} />
              ))
            )
          ) : tab === "pending" ? (
            pending.length === 0 ? (
              <EmptyState text="Nothing waiting for review." />
            ) : (
              pending.map((m) => (
                <div key={m.id} className="bg-oyster-surface border border-oyster-border rounded-xl p-3.5 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-semibold text-oyster-muted uppercase tracking-wider bg-oyster-bg px-1.5 py-0.5 rounded border border-oyster-border">
                      {TYPE_LABEL[m.type] ?? m.type}
                    </span>
                    <span className="text-xs text-oyster-muted truncate">{m.subject}</span>
                  </div>
                  <p className="text-sm text-oyster-text">{m.content}</p>
                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={() => handleApprove(m.id)}
                      className="cursor-pointer flex items-center gap-1 text-xs bg-green-500/10 text-green-400 border border-green-500/20 px-2.5 py-1 rounded-lg hover:bg-green-500/20"
                    >
                      <Check size={12} /> Save
                    </button>
                    <button
                      onClick={() => handleReject(m.id)}
                      className="cursor-pointer flex items-center gap-1 text-xs bg-oyster-bg text-oyster-muted border border-oyster-border px-2.5 py-1 rounded-lg hover:text-oyster-text"
                    >
                      <XCircle size={12} /> Discard
                    </button>
                  </div>
                </div>
              ))
            )
          ) : conflicts.length === 0 ? (
            <EmptyState text="No conflicting memories to resolve." />
          ) : (
            conflicts.map((g) => (
              <div key={g.conflict_group} className="bg-oyster-surface border border-yellow-500/20 rounded-xl p-3.5 space-y-2">
                <div className="flex items-center gap-1.5 text-yellow-400 text-xs font-medium">
                  <AlertTriangle size={13} /> Conflicting information
                </div>
                {g.members.map((m) => (
                  <div key={m.id} className="flex items-center gap-2 bg-oyster-bg border border-oyster-border rounded-lg p-2.5">
                    <p className="text-sm text-oyster-text flex-1">{m.content}</p>
                    <button
                      onClick={() => handleKeep(g.conflict_group, m.id)}
                      className="cursor-pointer shrink-0 text-xs bg-oyster-accent/10 text-oyster-accent border border-oyster-accent/20 px-2.5 py-1 rounded-lg hover:bg-oyster-accent/20"
                    >
                      Keep this
                    </button>
                  </div>
                ))}
              </div>
            ))
          )}
        </div>

        <div className="flex items-center justify-between px-5 py-3 border-t border-oyster-border shrink-0">
          <p className="text-[11px] text-oyster-muted">Stored locally, encrypted at rest. Never used for training.</p>
          <button
            onClick={handleExport}
            className="cursor-pointer flex items-center gap-1.5 text-xs text-oyster-muted hover:text-oyster-text"
          >
            <Download size={12} /> Export JSON
          </button>
        </div>
      </div>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="text-xs text-oyster-muted text-center py-10 px-6 leading-relaxed">{text}</p>;
}

function MemoryRow({
  memory,
  projectId,
  onDelete,
  onSaved,
}: {
  memory: MemoryItem;
  projectId: string;
  onDelete: () => void;
  onSaved: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [content, setContent] = useState(memory.content);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    setSaving(true);
    setError(null);
    const result = await updateMemory(projectId, memory.id, { content });
    setSaving(false);
    if (!result.ok) {
      setError(result.error ?? "Could not save");
      return;
    }
    setEditing(false);
    onSaved();
  }

  return (
    <div className="bg-oyster-surface border border-oyster-border rounded-xl p-3.5 space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-semibold text-oyster-muted uppercase tracking-wider bg-oyster-bg px-1.5 py-0.5 rounded border border-oyster-border">
          {TYPE_LABEL[memory.type] ?? memory.type}
        </span>
        <span className="text-xs text-oyster-muted truncate flex-1">{memory.subject}</span>
        <button onClick={() => setEditing((v) => !v)} className="cursor-pointer text-oyster-muted hover:text-oyster-text p-0.5">
          <Pencil size={12} />
        </button>
        <button onClick={onDelete} className="cursor-pointer text-oyster-muted hover:text-red-400 p-0.5">
          <Trash2 size={12} />
        </button>
      </div>

      {editing ? (
        <div className="space-y-2">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={2}
            className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-sm text-oyster-text resize-none outline-none focus:border-oyster-accent/50"
          />
          {error && <p className="text-[11px] text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="cursor-pointer text-xs bg-oyster-accent text-white px-2.5 py-1 rounded-lg disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save"}
            </button>
            <button
              onClick={() => { setEditing(false); setContent(memory.content); setError(null); }}
              className="cursor-pointer text-xs text-oyster-muted hover:text-oyster-text px-2.5 py-1"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <p className="text-sm text-oyster-text">{memory.content}</p>
      )}
    </div>
  );
}

function AddMemoryForm({ projectId, onDone }: { projectId: string; onDone: () => void }) {
  const [type, setType] = useState("fact");
  const [subject, setSubject] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    if (!subject.trim() || !content.trim()) return;
    setSaving(true);
    setError(null);
    const result = await addMemory(projectId, { type, subject: subject.trim(), content: content.trim() });
    setSaving(false);
    if (!result.ok) {
      setError(result.error ?? "Could not save memory");
      return;
    }
    setSubject("");
    setContent("");
    onDone();
  }

  return (
    <div className="bg-oyster-surface border border-oyster-accent/20 rounded-xl p-3.5 space-y-2.5">
      <div className="flex gap-2">
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="cursor-pointer bg-oyster-bg border border-oyster-border rounded-lg px-2 py-1.5 text-xs text-oyster-text outline-none"
        >
          {Object.entries(TYPE_LABEL).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <input
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="Short label, e.g. 'report format'"
          className="flex-1 bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-1.5 text-xs text-oyster-text placeholder:text-oyster-muted outline-none focus:border-oyster-accent/50"
        />
      </div>
      <textarea
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="What should Oyster remember?"
        rows={2}
        className="w-full bg-oyster-bg border border-oyster-border rounded-lg px-2.5 py-2 text-sm text-oyster-text placeholder:text-oyster-muted resize-none outline-none focus:border-oyster-accent/50"
      />
      {error && <p className="text-[11px] text-red-400">{error}</p>}
      <button
        onClick={handleSave}
        disabled={!subject.trim() || !content.trim() || saving}
        className="cursor-pointer text-xs bg-oyster-accent hover:bg-oyster-accent-hover text-white px-3 py-1.5 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {saving ? "Saving…" : "Save memory"}
      </button>
    </div>
  );
}
