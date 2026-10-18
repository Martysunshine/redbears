"use client";

// The door existing accounts meet after a terms change.
//
// Deliberately NOT dismissible — no close button, no Escape, no backdrop
// click. Accepting is a condition of using the chat, so a modal you could
// click past would misrepresent the choice: it would look optional while the
// backend still refuses every message. The only two ways out are the two real
// options — accept, or leave.
//
// This renders for tier "user" only; operators are exempt (the backend sets
// agreement.required = false for them), so a mistake here can never lock the
// people who would have to fix it out of their own app.

import { useState } from "react";
import { LogOut } from "lucide-react";
import { useAuth } from "./AuthGate";
import { AgreementText } from "./AgreementText";
import { OysterMascot } from "./OysterMascot";

export function AgreementGate() {
  const { email, agreement, setAgreementAccepted, signOut } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Someone who accepted an earlier version is being asked again because the
  // terms changed — say so, rather than implying they never answered.
  const isUpdate = Boolean(agreement?.accepted_version);

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      await setAgreementAccepted(true);
    } catch {
      setError("Could not save that — check your connection and try again.");
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-[95] flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="agreement-gate-title"
    >
      <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" />
      <div className="relative flex max-h-[88vh] w-full max-w-lg flex-col rounded-2xl border border-oyster-border bg-oyster-sidebar shadow-2xl">
        <div className="shrink-0 border-b border-oyster-border p-5 pb-4">
          <div className="mb-2 flex items-center gap-2.5">
            <OysterMascot size={32} variant="sidebar" />
            <h2 id="agreement-gate-title" className="text-base font-semibold text-oyster-text">
              {isUpdate ? "We've updated the agreement" : "Before you continue"}
            </h2>
          </div>
          <p className="text-xs leading-relaxed text-oyster-muted">
            {isUpdate
              ? "Oyster's user agreement has changed. Please read it and accept to keep using the chat."
              : "Using Oyster with an account requires accepting this agreement. It includes your conversations being stored and used to improve Oyster's AI."}
          </p>
          {email && <p className="mt-1.5 truncate text-[11px] text-oyster-muted">{email}</p>}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <AgreementText />
        </div>

        <div className="shrink-0 border-t border-oyster-border p-4">
          {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
          <button
            onClick={accept}
            disabled={busy}
            className="w-full cursor-pointer rounded-md bg-oyster-accent px-3 py-2.5 text-sm font-medium text-white transition hover:bg-oyster-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? "Saving…" : "I agree — continue"}
          </button>
          <button
            onClick={signOut}
            className="mt-2 flex w-full cursor-pointer items-center justify-center gap-1.5 rounded-md px-3 py-2 text-xs text-oyster-muted transition-colors hover:bg-oyster-surface hover:text-oyster-text"
          >
            <LogOut size={13} /> Sign out instead
          </button>
          <p className="mt-2.5 text-center text-[10px] leading-relaxed text-oyster-muted">
            Don&apos;t want to accept? You can still use Oyster without an account —
            sign out and keep chatting anonymously. Anonymous chats are never stored
            or used for training.
          </p>
        </div>
      </div>
    </div>
  );
}
