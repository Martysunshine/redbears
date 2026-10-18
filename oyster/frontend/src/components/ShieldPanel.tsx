"use client";

import { useState } from "react";
import { PanelLeftOpen, ShieldAlert, Copy, Check, ExternalLink, Lock } from "lucide-react";
import {
  SHIELD_REPO,
  SHIELD_TAGLINE,
  SHIELD_LAYERS,
  SHIELD_SECTIONS,
} from "@/data/shield";

interface ShieldPanelProps {
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
}

// Read-only, copy-and-run reference for the CyberMat Shield scanner. Nothing
// here executes inside Oyster — the operator copies a command and runs the
// scanner on their own machine. There is intentionally no run/scan action and
// no ToolProfile registration for this surface.
export function ShieldPanel({ onToggleSidebar, sidebarOpen }: ShieldPanelProps) {
  const [copied, setCopied] = useState<string | null>(null);

  async function copy(key: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500);
    } catch {
      /* clipboard unavailable — no-op */
    }
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
        <ShieldAlert size={15} className="text-oyster-muted shrink-0" />
        <span className="text-sm font-medium text-oyster-text">Shield</span>
        <span className="text-xs text-oyster-muted bg-oyster-surface px-2 py-0.5 rounded-md border border-oyster-border ml-1">
          copy &amp; run — nothing executes here
        </span>
        <a
          href={SHIELD_REPO}
          target="_blank"
          rel="noreferrer"
          className="ml-auto flex items-center gap-1.5 text-xs text-oyster-muted hover:text-oyster-text bg-oyster-surface px-2 py-1 rounded-md border border-oyster-border transition-colors"
        >
          <ExternalLink size={12} /> Repository
        </a>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-6">
        <div className="max-w-3xl mx-auto space-y-6">
          {/* Intro + safety note */}
          <div className="bg-oyster-surface border border-oyster-border rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2">
              <ShieldAlert size={18} className="text-oyster-accent" />
              <h1 className="text-base font-semibold text-oyster-text">CyberMat Shield</h1>
              <span className="text-[10px] font-semibold text-oyster-muted uppercase tracking-wider bg-oyster-bg px-1.5 py-0.5 rounded border border-oyster-border">
                MIT · OWASP Top 10:2025
              </span>
            </div>
            <p className="text-sm text-oyster-muted leading-relaxed">{SHIELD_TAGLINE}</p>
            <div className="flex items-start gap-2 text-xs text-oyster-muted bg-oyster-bg border border-oyster-border rounded-lg px-3 py-2">
              <Lock size={13} className="text-oyster-accent shrink-0 mt-0.5" />
              <span>
                This is reference only. Oyster does not run the scanner — copy a command below and
                run it in your own terminal, on your own machine.
              </span>
            </div>
          </div>

          {/* Scanner layers */}
          <div className="space-y-3">
            <h2 className="text-xs font-semibold text-oyster-muted uppercase tracking-widest px-1">
              What it scans
            </h2>
            <div className="grid gap-3 sm:grid-cols-3">
              {SHIELD_LAYERS.map((layer) => (
                <div
                  key={layer.name}
                  className="bg-oyster-surface border border-oyster-border rounded-xl p-4 space-y-2"
                >
                  <p className="text-sm font-medium text-oyster-text leading-snug">{layer.name}</p>
                  <p className="text-xs text-oyster-muted leading-relaxed">{layer.summary}</p>
                  <ul className="space-y-1 pt-1">
                    {layer.detects.map((d, i) => (
                      <li key={i} className="text-[11px] text-oyster-muted/90 leading-relaxed flex gap-1.5">
                        <span className="text-oyster-accent shrink-0">•</span>
                        <span>{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          {/* Command sections */}
          {SHIELD_SECTIONS.map((section) => (
            <div key={section.id} className="space-y-2.5">
              <div className="px-1">
                <h2 className="text-sm font-semibold text-oyster-text">{section.title}</h2>
                <p className="text-xs text-oyster-muted mt-0.5">{section.description}</p>
              </div>
              <div className="space-y-2">
                {section.snippets.map((snip, i) => {
                  const key = `${section.id}-${i}`;
                  return (
                    <div
                      key={key}
                      className="bg-oyster-surface border border-oyster-border rounded-xl overflow-hidden"
                    >
                      <div className="flex items-center justify-between px-3 py-1.5 border-b border-oyster-border">
                        <span className="text-[11px] font-medium text-oyster-muted">{snip.label}</span>
                        <button
                          onClick={() => copy(key, snip.code)}
                          className="cursor-pointer flex items-center gap-1 text-[11px] text-oyster-muted hover:text-oyster-text px-1.5 py-0.5 rounded transition-colors"
                          aria-label={`Copy ${snip.label}`}
                        >
                          {copied === key ? (
                            <><Check size={12} className="text-green-500" /> Copied</>
                          ) : (
                            <><Copy size={12} /> Copy</>
                          )}
                        </button>
                      </div>
                      <pre className="px-3 py-2.5 text-[12px] text-oyster-text font-mono overflow-x-auto leading-relaxed whitespace-pre">
                        {snip.code}
                      </pre>
                      {snip.note && (
                        <p className="px-3 pb-2 text-[11px] text-oyster-muted/80">{snip.note}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
