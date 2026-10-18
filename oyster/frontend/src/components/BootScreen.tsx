"use client";

import { Loader2, RefreshCw } from "lucide-react";

/**
 * What the chat pane shows before the workspace is ready.
 *
 * Used to be `<div className="flex-1" />` — a blank pane — while the session
 * and tier resolved, and the same blank pane forever if either never did.
 * Now it is a spinner while loading and a sentence with a Retry when the
 * boot failed, so "Oyster loads empty" is never the last thing on screen.
 */
export function BootScreen({
  error,
  onRetry,
}: {
  error?: string | null;
  onRetry?: () => void;
}) {
  return (
    <div className="flex-1 min-w-0 h-app flex items-center justify-center bg-oyster-bg px-6">
      <div className="text-center max-w-sm">
        {error ? (
          <>
            <p className="text-oyster-text text-[15px] mb-1">Oyster couldn&apos;t load your workspace.</p>
            <p className="text-oyster-muted text-sm mb-5">{error}</p>
            {onRetry && (
              <button
                onClick={onRetry}
                className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-oyster-accent text-white text-sm hover:bg-oyster-accent-hover transition-colors"
              >
                <RefreshCw size={14} />
                Try again
              </button>
            )}
          </>
        ) : (
          <>
            <Loader2 size={28} className="animate-spin text-oyster-accent mx-auto mb-3" />
            <p className="text-oyster-muted text-sm">Loading Oyster…</p>
          </>
        )}
      </div>
    </div>
  );
}
