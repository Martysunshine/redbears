"use client";

// The lock upsell: shown when an anonymous visitor has spent the daily free
// message. Pure UX — the backend independently enforces the allowance (429
// "anon_daily_limit" from /chat).

import { Lock } from "lucide-react";
import { OysterMascot } from "./OysterMascot";
import { useAuth } from "./AuthGate";

export function UpsellModal({ onClose }: { onClose: () => void }) {
  const { openAuth } = useAuth();

  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      onKeyDown={(e) => e.key === "Escape" && onClose()}
    >
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-sm bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl p-6 text-center">
        <div className="flex justify-center mb-3">
          <OysterMascot size={96} variant="welcome" />
        </div>
        <div className="mb-1 flex items-center justify-center gap-2">
          <Lock size={14} className="text-oyster-accent" />
          <h2 className="text-base font-semibold text-oyster-text">
            Free message used for today
          </h2>
        </div>
        <p className="mb-5 text-sm text-oyster-muted leading-relaxed">
          Anonymous visitors get one message per day. Create a free account and
          chat with Oyster without limits.
        </p>
        <button
          onClick={() => { onClose(); openAuth("signup"); }}
          className="cursor-pointer mb-2 w-full rounded-lg bg-oyster-accent px-3 py-2.5 text-sm font-medium text-white transition hover:bg-oyster-accent-hover"
        >
          Create free account
        </button>
        <button
          onClick={() => { onClose(); openAuth("signin"); }}
          className="cursor-pointer w-full rounded-lg border border-oyster-border px-3 py-2 text-xs font-medium text-oyster-muted transition hover:text-oyster-text hover:bg-oyster-surface"
        >
          I already have an account
        </button>
      </div>
    </div>
  );
}
