"use client";

import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Loader2, Bookmark } from "lucide-react";
import { getSharedFinding, type SharedFinding } from "@/lib/api";

/**
 * Public, read-only view of a finding someone chose to share. No auth: this
 * route is reachable at /oyster/shared/<token> without signing in. It fetches
 * the minimal public projection (title, content, citations, created_at) — the
 * backend never exposes the owner, project or conversation. An unknown or
 * revoked token renders a plain "not available" state.
 */
export default function SharedFindingPage({
  params,
}: {
  params: { token: string };
}) {
  const { token } = params;
  const [finding, setFinding] = useState<SharedFinding | null>(null);
  const [state, setState] = useState<"loading" | "ok" | "missing">("loading");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const f = await getSharedFinding(token);
      if (cancelled) return;
      if (f) { setFinding(f); setState("ok"); }
      else setState("missing");
    })();
    return () => { cancelled = true; };
  }, [token]);

  return (
    <main className="min-h-app bg-oyster-bg text-oyster-text flex flex-col items-center px-4 py-10 sm:py-16">
      <div className="w-full max-w-3xl">
        <div className="flex items-center gap-2 mb-6 text-oyster-muted">
          <Bookmark size={16} className="text-oyster-accent" />
          <span className="text-sm font-medium">Shared from Oyster</span>
        </div>

        {state === "loading" ? (
          <div className="flex justify-center py-20">
            <Loader2 size={22} className="text-oyster-muted animate-spin" />
          </div>
        ) : state === "missing" ? (
          <div className="rounded-2xl border border-oyster-border bg-oyster-surface/40 px-6 py-16 text-center">
            <p className="text-lg font-semibold text-oyster-text mb-1">This finding isn’t available</p>
            <p className="text-sm text-oyster-muted">
              The link may have been revoked, or it never existed.
            </p>
          </div>
        ) : finding ? (
          <article className="rounded-2xl border border-oyster-border bg-oyster-surface/40 p-6 sm:p-8">
            <h1 className="text-xl sm:text-2xl font-semibold text-oyster-text mb-2">{finding.title}</h1>
            <p className="text-xs text-oyster-muted mb-6">
              {finding.author ? `Shared by ${finding.author} · ` : ""}
              {new Date(finding.created_at).toLocaleDateString(undefined, {
                year: "numeric",
                month: "long",
                day: "numeric",
              })}
            </p>
            {finding.endpoint && (
              <p className="text-[11px] text-oyster-muted font-mono mb-4">
                {finding.method} {finding.endpoint}
              </p>
            )}
            <div className="prose prose-sm max-w-none overflow-x-auto">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{finding.content}</ReactMarkdown>
            </div>
          </article>
        ) : null}

        <p className="mt-8 text-center text-[11px] text-oyster-muted">
          Read-only. Shared content is visible to anyone with this link.
        </p>
      </div>
    </main>
  );
}
