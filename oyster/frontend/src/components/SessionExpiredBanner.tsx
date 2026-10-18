"use client";

import { LogIn, X } from "lucide-react";

/**
 * Shown when a request that carried a bearer token came back 401 — the
 * session expired or was revoked. Non-blocking: the anonymous chat still
 * works underneath, but anything that needs the account (history, projects,
 * unlimited chat) will fail until they sign in again, and this says so
 * instead of leaving `Error: Backend error 401` in a chat bubble.
 */
export function SessionExpiredBanner({
  onSignIn,
  onDismiss,
}: {
  onSignIn: () => void;
  onDismiss: () => void;
}) {
  return (
    <div
      role="status"
      className="fixed top-0 inset-x-0 z-[90] flex items-center justify-center gap-3 px-4 py-2 bg-oyster-sidebar border-b border-oyster-border text-sm text-oyster-text shadow-lg"
    >
      <span>Your session has expired.</span>
      <button
        onClick={onSignIn}
        className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-oyster-accent text-white hover:bg-oyster-accent-hover transition-colors"
      >
        <LogIn size={14} />
        Sign in again
      </button>
      <button
        onClick={onDismiss}
        aria-label="Dismiss"
        className="cursor-pointer text-oyster-muted hover:text-oyster-text p-1"
      >
        <X size={14} />
      </button>
    </div>
  );
}
