"use client";

import { useEffect, useMemo, useState } from "react";
import { Search, X, MessageSquare, FileText, Bug, Brain, Loader2 } from "lucide-react";
import { type Message } from "@/types/chat";
import { searchDocuments, listFindings } from "@/lib/api";

type Scope = "conversation" | "files" | "findings" | "memory";

const SCOPES: { id: Scope; label: string; icon: React.ElementType }[] = [
  { id: "conversation", label: "Conversation", icon: MessageSquare },
  { id: "files", label: "Files", icon: FileText },
  { id: "findings", label: "Findings", icon: Bug },
  { id: "memory", label: "Memory", icon: Brain },
];

interface ChatSearchProps {
  messages: Message[];
  onClose: () => void;
}

export function ChatSearch({ messages, onClose }: ChatSearchProps) {
  const [scope, setScope] = useState<Scope>("conversation");
  const [query, setQuery] = useState("");
  const [remote, setRemote] = useState<{ title: string; body: string }[]>([]);
  const [loading, setLoading] = useState(false);

  // Client-side conversation search
  const convHits = useMemo(() => {
    if (scope !== "conversation" || !query.trim()) return [];
    const q = query.toLowerCase();
    return messages
      .filter((m) => m.content.toLowerCase().includes(q))
      .map((m) => ({ title: m.role === "user" ? "You" : "Oyster", body: m.content }));
  }, [scope, query, messages]);

  // Remote search for files / findings
  useEffect(() => {
    if ((scope !== "files" && scope !== "findings") || !query.trim()) {
      setRemote([]);
      return;
    }
    let cancelled = false;
    setLoading(true);
    (async () => {
      try {
        if (scope === "files") {
          const data = await searchDocuments(query, 6);
          if (!cancelled)
            setRemote(data.results.map((r) => ({ title: r.document, body: r.chunk })));
        } else {
          // The user's own saved findings (per-account), not the admin evidence
          // store. Filter client-side by title/content.
          const data = await listFindings();
          const q = query.toLowerCase();
          if (!cancelled)
            setRemote(
              data
                .filter(
                  (f) =>
                    f.title.toLowerCase().includes(q) ||
                    f.content.toLowerCase().includes(q)
                )
                .map((f) => ({ title: f.title, body: f.content }))
            );
        }
      } catch {
        if (!cancelled) setRemote([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scope, query]);

  const results = scope === "conversation" ? convHits : remote;

  return (
    <div className="border-b border-oyster-border bg-oyster-bg/95 backdrop-blur-sm">
      <div className="max-w-3xl mx-auto px-4 py-3">
        <div className="flex items-center gap-2 bg-oyster-surface border border-oyster-border rounded-xl px-3 py-2 focus-within:border-oyster-accent/50 transition-colors">
          <Search size={15} className="text-oyster-muted shrink-0" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Escape" && onClose()}
            placeholder={`Search ${scope}…`}
            className="flex-1 bg-transparent outline-none text-sm text-oyster-text placeholder:text-oyster-muted"
          />
          <button onClick={onClose} className="cursor-pointer text-oyster-muted hover:text-oyster-text shrink-0">
            <X size={15} />
          </button>
        </div>

        {/* Scope tabs */}
        <div className="flex items-center gap-1 mt-2">
          {SCOPES.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setScope(id)}
              className={`cursor-pointer flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                scope === id
                  ? "bg-oyster-accent/15 text-oyster-accent"
                  : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface"
              }`}
            >
              <Icon size={12} />
              {label}
            </button>
          ))}
        </div>

        {/* Results */}
        {query.trim() && (
          <div className="mt-2 max-h-64 overflow-y-auto space-y-1">
            {scope === "memory" ? (
              <p className="text-xs text-oyster-muted px-2 py-4 text-center">
                Memory search arrives with the Memory workspace panel.
              </p>
            ) : loading ? (
              <div className="flex items-center gap-2 px-2 py-4 text-xs text-oyster-muted">
                <Loader2 size={13} className="animate-spin" /> Searching…
              </div>
            ) : results.length === 0 ? (
              <p className="text-xs text-oyster-muted px-2 py-4 text-center">No matches.</p>
            ) : (
              results.map((r, i) => (
                <div key={i} className="px-3 py-2 rounded-lg bg-oyster-surface/50 border border-oyster-border/50">
                  <p className="text-xs font-medium text-oyster-text truncate">{r.title}</p>
                  <p className="text-[11px] text-oyster-muted line-clamp-2 mt-0.5">{r.body}</p>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
