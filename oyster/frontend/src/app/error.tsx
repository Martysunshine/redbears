"use client";

import { useEffect } from "react";
import { RefreshCw } from "lucide-react";

/**
 * Next.js route-level error boundary. Anything that escapes the component
 * boundaries lands here instead of on a blank page. The message is fixed on
 * purpose: `error.message` may name a file, a host or a token.
 */
export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("Oyster: page error", error);
  }, [error]);

  return (
    <div className="h-app flex items-center justify-center bg-oyster-bg text-oyster-text px-6">
      <div className="text-center max-w-sm">
        <p className="text-[15px] mb-1">Oyster hit a problem loading this page.</p>
        <p className="text-oyster-muted text-sm mb-5">Nothing was lost. Try again, or reload.</p>
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={reset}
            className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-oyster-accent text-white text-sm hover:bg-oyster-accent-hover transition-colors"
          >
            <RefreshCw size={14} />
            Try again
          </button>
          <button
            onClick={() => window.location.reload()}
            className="cursor-pointer px-4 py-2 rounded-lg border border-oyster-border text-sm hover:bg-oyster-surface transition-colors"
          >
            Reload
          </button>
        </div>
      </div>
    </div>
  );
}
