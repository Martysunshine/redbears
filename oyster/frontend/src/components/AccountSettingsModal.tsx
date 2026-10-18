"use client";

// Settings — the box behind the red wheel in the sidebar footer.
//
// THE settings box. There used to be two: this one (account, agreement,
// deletion) behind a red wheel in the chat header, and a separate grey-gear
// modal in the sidebar footer for Oyster configuration (model, runtime,
// long-term memory). Two buttons for one idea, and which one you got depended
// on whether you were an operator. They are merged here, behind the single
// wheel, and every section is available to every signed-in account.
//
// Section order runs from "who am I" through "how does Oyster behave for me"
// to "how do I leave", with the irreversible things last.

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  Database,
  ExternalLink,
  LogOut,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react";
import { useAuth } from "./AuthGate";
import { AgreementText } from "./AgreementText";
import { MemoryPanel } from "./MemoryPanel";
import { SettingsWheel, RedOrcaMark } from "./brand";
import {
  UI_MODELS,
  getSettings,
  updateSettings,
  deleteAllPersonalData,
  getProfile,
  updateProfile,
  type OysterSettings,
  type Profile,
} from "@/lib/api";
import { DASHBOARD_URL, PRIVACY_URL, TERMS_URL } from "@/lib/site";

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function Toggle({ checked, onChange, disabled }: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`cursor-pointer relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
        checked ? "bg-oyster-accent" : "bg-oyster-border"
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
          checked ? "translate-x-[18px]" : "translate-x-1"
        }`}
      />
    </button>
  );
}

function SettingRow({ label, hint, checked, onChange, disabled }: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-3 py-2">
      <div className="min-w-0">
        <p className="text-sm text-oyster-text">{label}</p>
        <p className="text-[11px] text-oyster-muted leading-snug mt-0.5">{hint}</p>
      </div>
      <div className="pt-0.5">
        <Toggle checked={checked} onChange={onChange} disabled={disabled} />
      </div>
    </div>
  );
}

interface AccountSettingsModalProps {
  onClose: () => void;
  selectedModel: string;
  onModelChange: (m: string) => void;
  backendOk: boolean | null;
  onReconnect: () => void;
  /** The caller's workspace. The backend redirects non-operators into their
   *  own regardless of what is sent, so this only has to be right for them. */
  projectId: string;
}

export function AccountSettingsModal({
  onClose,
  selectedModel,
  onModelChange,
  backendOk,
  onReconnect,
  projectId,
}: AccountSettingsModalProps) {
  const { email, tier, agreement, setAgreementAccepted, deleteAccount, signOut } = useAuth();
  const [settings, setSettings] = useState<OysterSettings | null>(null);
  const [memoryOpen, setMemoryOpen] = useState(false);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [wiping, setWiping] = useState(false);
  const [wipeMsg, setWipeMsg] = useState<string | null>(null);
  const [confirmWithdraw, setConfirmWithdraw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Deletion is irreversible, so it takes two deliberate steps and then typing
  // the account's own email — a single click is not consent to destroy data.
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [typedEmail, setTypedEmail] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [loginRemains, setLoginRemains] = useState(false);

  const emailMatches =
    !!email && typedEmail.trim().toLowerCase() === email.trim().toLowerCase();

  const loadSettings = useCallback(() => {
    getSettings(projectId).then(setSettings).catch(() => {});
  }, [projectId]);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  async function patch(fields: Partial<Omit<OysterSettings, "project_id">>) {
    if (!settings) return;
    setSettings({ ...settings, ...fields }); // optimistic
    try {
      setSettings(await updateSettings(projectId, fields));
    } catch {
      loadSettings(); // revert on failure
    }
  }

  async function handleWipe() {
    setWiping(true);
    try {
      const res = await deleteAllPersonalData(projectId);
      setWipeMsg(`Deleted ${res.memories_deleted} memor${res.memories_deleted === 1 ? "y" : "ies"}.`);
      setConfirmWipe(false);
    } catch {
      setWipeMsg("Failed to delete — is the backend running?");
    } finally {
      setWiping(false);
    }
  }

  async function runDelete() {
    setDeleting(true);
    setDeleteError(null);
    const outcome = await deleteAccount();
    if (!outcome.ok) {
      setDeleteError(outcome.error);
      setDeleting(false);
      return;
    }
    if ("loginRemains" in outcome && outcome.loginRemains) {
      // Do NOT close: they need to read this. Their data is gone, but the
      // empty login record survived and only we can remove it.
      setLoginRemains(true);
      setDeleting(false);
      return;
    }
    onClose();
  }

  const accepted = !!agreement?.accepted;
  const isOperator = tier === "admin";

  async function withdraw() {
    setBusy(true);
    setError(null);
    try {
      await setAgreementAccepted(false);
      onClose(); // the blocking gate takes over from here
    } catch {
      setError("Could not save that — check your connection and try again.");
      setBusy(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-[85] flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="settings-title"
      onKeyDown={(e) => e.key === "Escape" && onClose()}
    >
      <div className="absolute inset-0 bg-black/65 backdrop-blur-sm" onClick={onClose} />
      <div className="relative flex max-h-[88vh] w-full max-w-lg flex-col rounded-2xl border border-oyster-border bg-oyster-sidebar shadow-2xl">
        {/* Header */}
        <div className="flex shrink-0 items-center gap-2.5 border-b border-oyster-border p-5 pb-4">
          <span className="rw-btn flex items-center">
            <SettingsWheel size={18} />
          </span>
          <h2 id="settings-title" className="text-base font-semibold text-oyster-text">
            Settings
          </h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="ml-auto cursor-pointer rounded p-1 text-oyster-muted transition-colors hover:text-oyster-text"
          >
            <X size={16} />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-5">
          {/* Account */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              Account
            </h3>
            <div className="rounded-xl border border-oyster-border bg-oyster-bg/60 p-3.5">
              <p className="truncate text-sm text-oyster-text">{email ?? "Signed in"}</p>
              <p className="mt-0.5 text-[11px] text-oyster-muted">
                {isOperator ? "Operator account" : "Free account · unlimited chat"}
              </p>
            </div>
          </section>

          {/* Public name — what other people see when you publish a finding */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              Public name
            </h3>
            <DisplayNameSetting />
          </section>

          {/* How they opted */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              Your agreement
            </h3>
            <div className="rounded-xl border border-oyster-border bg-oyster-bg/60 p-3.5">
              {isOperator ? (
                <p className="text-[11px] leading-relaxed text-oyster-muted">
                  Operator accounts are not asked to accept the public user agreement —
                  training on operator conversations is governed by the project-level
                  switch instead.
                </p>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="flex items-center gap-1.5 text-sm font-medium text-oyster-text">
                        {accepted ? (
                          <>
                            <Check size={14} className="shrink-0 text-green-400" />
                            Accepted
                          </>
                        ) : (
                          "Not accepted"
                        )}
                      </p>
                      <p className="mt-1 text-[11px] leading-relaxed text-oyster-muted">
                        {accepted
                          ? "Your conversations are stored to your account and may be used to improve Oyster's AI."
                          : "Chat is unavailable until you accept."}
                      </p>
                    </div>
                  </div>
                  <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 border-t border-oyster-border pt-3 text-[11px]">
                    <dt className="text-oyster-muted">Accepted on</dt>
                    <dd className="text-oyster-text">{formatDate(agreement?.accepted_at ?? null)}</dd>
                    <dt className="text-oyster-muted">Version</dt>
                    <dd className="font-mono text-oyster-text">
                      {agreement?.accepted_version ?? "—"}
                    </dd>
                  </dl>
                </>
              )}
            </div>
          </section>

          {/* The agreement itself, in full */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              What you agreed to
            </h3>
            <div className="max-h-64 overflow-y-auto rounded-xl border border-oyster-border bg-oyster-bg/60 p-3.5">
              <AgreementText />
            </div>
            <div className="mt-2 flex flex-wrap gap-3">
              <a
                href={TERMS_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-[11px] text-oyster-accent hover:text-oyster-accent-hover"
              >
                Terms <ExternalLink size={11} />
              </a>
              <a
                href={PRIVACY_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-[11px] text-oyster-accent hover:text-oyster-accent-hover"
              >
                Privacy Policy <ExternalLink size={11} />
              </a>
            </div>
          </section>

          {/* ---- Oyster configuration (was the separate grey-gear modal) ---- */}

          {/* Model */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              Default Model
            </h3>
            <select
              value={selectedModel}
              onChange={(e) => onModelChange(e.target.value)}
              className="cursor-pointer w-full bg-oyster-surface border border-oyster-border rounded-lg px-3 py-2 text-sm text-oyster-text outline-none focus:border-oyster-accent/50"
            >
              {UI_MODELS.map((m) => (
                <option key={m.key} value={m.key}>
                  {m.label} — {m.description}
                </option>
              ))}
            </select>
            <p className="mt-1.5 text-[11px] leading-snug text-oyster-muted">
              Heavier models reason better but answer more slowly on shared
              hardware. You can change this at any time, mid-conversation.
            </p>
          </section>

          {/* Runtime */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              Runtime
            </h3>
            <div className="flex items-center gap-2 bg-oyster-surface border border-oyster-border rounded-lg px-3 py-2.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  backendOk === null ? "bg-yellow-500 animate-pulse" : backendOk ? "bg-green-500" : "bg-red-500"
                }`}
              />
              <span className="text-sm text-oyster-text flex-1">
                {backendOk === null ? "Connecting…" : backendOk ? "Ollama · local · connected" : "Backend offline"}
              </span>
              {backendOk === false && (
                <button
                  onClick={onReconnect}
                  className="cursor-pointer flex items-center gap-1 text-xs text-oyster-accent hover:text-oyster-accent-hover"
                >
                  <RefreshCw size={11} /> Retry
                </button>
              )}
            </div>
          </section>

          {/* Long-term memory */}
          <section>
            <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
              Long-term Memory
            </h3>
            <p className="mb-1 text-[11px] leading-snug text-oyster-muted">
              Oyster can remember useful facts and preferences across your
              conversations, stored encrypted and kept to your own workspace —
              never used to train or fine-tune a model.
            </p>
            <div className="divide-y divide-oyster-border/60">
              <SettingRow
                label="Use long-term memory"
                hint="Recall relevant memories when answering."
                checked={settings?.memory_enabled ?? true}
                onChange={(v) => patch({ memory_enabled: v })}
                disabled={!settings}
              />
              <SettingRow
                label="Automatically save useful memories"
                hint="Extract facts/preferences from chats without asking."
                checked={settings?.auto_save ?? true}
                onChange={(v) => patch({ auto_save: v })}
                disabled={!settings || !settings.memory_enabled}
              />
              <SettingRow
                label="Ask before saving"
                hint="Review each memory before it's stored."
                checked={settings?.ask_before_saving ?? false}
                onChange={(v) => patch({ ask_before_saving: v })}
                disabled={!settings || !settings.memory_enabled}
              />
            </div>
            <button
              onClick={() => setMemoryOpen(true)}
              className="cursor-pointer flex items-center gap-1.5 text-xs text-oyster-accent hover:text-oyster-accent-hover mt-2"
            >
              <Database size={12} /> Manage memories
            </button>
          </section>

          {/* Model improvement — OPERATORS ONLY, deliberately.
              For everyone else the user agreement above already answers this
              question, and it answers it as a condition of use. Showing a
              toggle that appears to switch off what the agreement says is
              happening would be a contradiction on a consent surface. */}
          {isOperator && (
            <section>
              <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
                Model Improvement
              </h3>
              <p className="mb-1 text-[11px] leading-snug text-oyster-muted">
                Off by default. When enabled, this project&apos;s conversations
                become eligible for a separate, manually-reviewed fine-tuning
                pipeline — redacted, deduplicated, and never applied
                automatically. This is not RAG/memory and does not affect what
                Oyster recalls above.
              </p>
              <SettingRow
                label="Allow my data for model improvement"
                hint="Opt this project's conversations into the training pipeline."
                checked={settings?.allow_training_data ?? false}
                onChange={(v) => patch({ allow_training_data: v })}
                disabled={!settings}
              />
            </section>
          )}

          {/* Withdraw — honest about what it costs */}
          {!isOperator && accepted && (
            <section>
              <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-oyster-muted">
                Withdraw
              </h3>
              {confirmWithdraw ? (
                <div className="rounded-xl border border-red-500/30 bg-red-500/[0.06] p-3.5">
                  <p className="text-[11px] leading-relaxed text-oyster-text">
                    Withdrawing does two things, both immediately:
                  </p>
                  <ul className="ml-4 mt-1.5 list-disc space-y-1 text-[11px] leading-relaxed text-oyster-muted">
                    <li>Your chats are excluded from every dataset built afterwards.</li>
                    <li>
                      <span className="text-oyster-text">Your chat access ends</span> —
                      acceptance is what grants it. You can accept again at any time.
                    </li>
                  </ul>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-oyster-muted">
                    A model that has already been trained cannot be untrained.
                  </p>
                  {error && <p className="mt-2 text-[11px] text-red-400">{error}</p>}
                  <div className="mt-3 flex gap-2">
                    <button
                      onClick={withdraw}
                      disabled={busy}
                      className="cursor-pointer rounded-md bg-red-500/90 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-red-500 disabled:opacity-50"
                    >
                      {busy ? "Withdrawing…" : "Withdraw and end access"}
                    </button>
                    <button
                      onClick={() => setConfirmWithdraw(false)}
                      className="cursor-pointer rounded-md px-3 py-1.5 text-xs text-oyster-muted transition-colors hover:bg-oyster-surface hover:text-oyster-text"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmWithdraw(true)}
                  className="w-full cursor-pointer rounded-xl border border-oyster-border bg-oyster-bg/60 p-3 text-left text-[11px] leading-relaxed text-oyster-muted transition-colors hover:border-red-500/30 hover:text-oyster-text"
                >
                  <span className="text-oyster-text">Withdraw my agreement</span> — removes
                  my chats from future training. This also ends chat access.
                </button>
              )}
            </section>
          )}

          {/* Danger zone. Two different deletions, and the difference matters:
              memories are one kind of stored data, the account is everything.
              Named so nobody reaches for the wrong one. */}
          <section>
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-red-400/80">
              Danger zone
            </h3>
            {!confirmWipe ? (
              <button
                onClick={() => { setConfirmWipe(true); setWipeMsg(null); }}
                className="w-full cursor-pointer rounded-xl border border-oyster-border bg-oyster-bg/60 p-3 text-left text-[11px] leading-relaxed text-oyster-muted transition-colors hover:border-red-500/30 hover:text-oyster-text"
              >
                <span className="text-oyster-text">Delete my memories</span> — erases
                everything Oyster has remembered about you. Your chats and uploads stay.
              </button>
            ) : (
              <div className="space-y-2 rounded-xl border border-red-500/30 bg-red-500/[0.06] p-3.5">
                <div className="flex items-start gap-2 text-[11px] leading-relaxed text-oyster-text">
                  <AlertTriangle size={14} className="mt-0.5 shrink-0 text-red-400" />
                  <span>
                    This permanently deletes every long-term memory in your
                    workspace. It cannot be undone. Conversation history and
                    uploaded files are not affected.
                  </span>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={handleWipe}
                    disabled={wiping}
                    className="cursor-pointer rounded-md bg-red-500/90 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-red-500 disabled:opacity-50"
                  >
                    {wiping ? "Deleting…" : "Delete my memories"}
                  </button>
                  <button
                    onClick={() => setConfirmWipe(false)}
                    className="cursor-pointer rounded-md px-3 py-1.5 text-xs text-oyster-muted transition-colors hover:bg-oyster-surface hover:text-oyster-text"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
            {wipeMsg && <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-oyster-muted">
              <Trash2 size={11} /> {wipeMsg}
            </p>}
          </section>

          {/* Delete account — the erasure right, self-service */}
          {!isOperator && (
            <section>
              {loginRemains ? (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/[0.06] p-3.5">
                  <p className="text-[11px] leading-relaxed text-oyster-text">
                    Your data has been deleted — conversations, uploads and your
                    agreement record are gone.
                  </p>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-oyster-muted">
                    One thing we couldn&apos;t finish: the empty sign-in record still
                    exists, so this email can still log in (to nothing). Email{" "}
                    <a
                      href="mailto:techredorca@gmail.com"
                      className="text-oyster-accent underline underline-offset-2"
                    >
                      techredorca@gmail.com
                    </a>{" "}
                    and we&apos;ll remove it.
                  </p>
                  <button
                    onClick={() => { signOut(); onClose(); }}
                    className="mt-3 cursor-pointer rounded-md bg-oyster-surface px-3 py-1.5 text-xs text-oyster-text transition hover:bg-oyster-border"
                  >
                    Close and sign out
                  </button>
                </div>
              ) : confirmDelete ? (
                <div className="rounded-xl border border-red-500/30 bg-red-500/[0.06] p-3.5">
                  <p className="text-[11px] leading-relaxed text-oyster-text">
                    This permanently deletes:
                  </p>
                  <ul className="ml-4 mt-1.5 list-disc space-y-1 text-[11px] leading-relaxed text-oyster-muted">
                    <li>Your account and sign-in</li>
                    <li>Every conversation and message</li>
                    <li>Every file, image, video and note you uploaded</li>
                    <li>Your agreement record — you are removed from all future training</li>
                  </ul>
                  <p className="mt-1.5 text-[11px] leading-relaxed text-oyster-muted">
                    <span className="text-oyster-text">This cannot be undone</span>, and a
                    model that has already been trained cannot be untrained.
                  </p>
                  <label className="mt-3 block text-[11px] text-oyster-muted">
                    Type <span className="font-mono text-oyster-text">{email}</span> to confirm
                  </label>
                  <input
                    type="email"
                    autoComplete="off"
                    value={typedEmail}
                    onChange={(e) => setTypedEmail(e.target.value)}
                    className="mt-1 w-full rounded-md border border-oyster-border bg-oyster-bg px-2.5 py-1.5 text-xs text-oyster-text outline-none focus:border-red-500/60"
                  />
                  {deleteError && <p className="mt-2 text-[11px] text-red-400">{deleteError}</p>}
                  <div className="mt-3 flex gap-2">
                    <button
                      onClick={runDelete}
                      disabled={!emailMatches || deleting}
                      className="cursor-pointer rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-red-500 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {deleting ? "Deleting…" : "Permanently delete my account"}
                    </button>
                    <button
                      onClick={() => { setConfirmDelete(false); setTypedEmail(""); setDeleteError(null); }}
                      disabled={deleting}
                      className="cursor-pointer rounded-md px-3 py-1.5 text-xs text-oyster-muted transition-colors hover:bg-oyster-surface hover:text-oyster-text"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="w-full cursor-pointer rounded-xl border border-oyster-border bg-oyster-bg/60 p-3 text-left text-[11px] leading-relaxed text-oyster-muted transition-colors hover:border-red-500/40 hover:text-oyster-text"
                >
                  <span className="text-oyster-text">Delete my account</span> — erases your
                  account, all conversations and everything you uploaded. Permanent.
                </button>
              )}
            </section>
          )}
        </div>

        {/* Footer actions */}
        <div className="flex shrink-0 items-center gap-2 border-t border-oyster-border p-4">
          <a
            href={DASHBOARD_URL}
            className="flex cursor-pointer items-center gap-2 rounded-md px-3 py-2 text-xs font-medium text-oyster-muted transition-colors hover:bg-oyster-surface hover:text-oyster-text"
          >
            <RedOrcaMark width={18} /> Dashboard
          </a>
          <button
            onClick={signOut}
            className="ml-auto flex cursor-pointer items-center gap-1.5 rounded-md px-3 py-2 text-xs text-oyster-muted transition-colors hover:bg-oyster-surface hover:text-oyster-text"
          >
            <LogOut size={13} /> Sign out
          </button>
        </div>
      </div>

      {memoryOpen && <MemoryPanel projectId={projectId} onClose={() => setMemoryOpen(false)} />}
    </div>
  );
}

/**
 * The nickname shown as the author when you publish a finding.
 *
 * Everyone starts as "User 7" — a number assigned in join order, which says
 * nothing about who they are. Your email is never shown to other people, and
 * clearing this box puts the generated name back.
 */
function DisplayNameSetting() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const p = await getProfile();
      if (cancelled) return;
      setProfile(p);
      setValue(p?.display_name ?? "");
    })();
    return () => { cancelled = true; };
  }, []);

  const dirty = (profile?.display_name ?? "") !== value.trim();

  async function save() {
    setSaving(true);
    setError(null);
    setSaved(false);
    const res = await updateProfile(value.trim());
    setSaving(false);
    if (res.profile) {
      setProfile(res.profile);
      setValue(res.profile.display_name ?? "");
      setSaved(true);
      setTimeout(() => setSaved(false), 1600);
    } else {
      setError(res.error ?? "Could not save that name.");
    }
  }

  return (
    <div className="rounded-xl border border-oyster-border bg-oyster-bg/60 p-3.5">
      <p className="text-sm text-oyster-text">
        You appear as{" "}
        <span className="font-medium text-oyster-accent">{profile?.handle ?? "…"}</span>
      </p>
      <p className="mt-0.5 text-[11px] text-oyster-muted">
        This is the only name other people see on findings you publish. Your email is never shown.
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input
          value={value}
          onChange={(e) => { setValue(e.target.value); setError(null); }}
          onKeyDown={(e) => { if (e.key === "Enter" && dirty && !saving) { e.preventDefault(); save(); } }}
          maxLength={32}
          placeholder={profile ? `User ${profile.member_no}` : "Pick a nickname"}
          aria-label="Public nickname"
          className="min-w-[180px] flex-1 rounded-lg border border-oyster-border bg-oyster-bg px-3 py-2 text-sm text-oyster-text placeholder:text-oyster-muted outline-none transition-colors focus:border-oyster-accent/50"
        />
        <button
          onClick={save}
          disabled={!dirty || saving}
          className={`rounded-lg px-3 py-2 text-xs font-medium transition-colors ${
            dirty && !saving
              ? "cursor-pointer bg-oyster-accent text-white hover:bg-oyster-accent-hover"
              : "cursor-not-allowed bg-oyster-border text-oyster-muted"
          }`}
        >
          {saving ? "Saving…" : saved ? "Saved" : "Save"}
        </button>
      </div>

      {value.trim() && (
        <button
          onClick={() => setValue("")}
          className="mt-2 cursor-pointer text-[11px] text-oyster-muted underline-offset-2 hover:text-oyster-text hover:underline"
        >
          Clear and go back to {profile ? `User ${profile.member_no}` : "the default name"}
        </button>
      )}
      {error && <p className="mt-2 text-[11px] text-red-400">{error}</p>}
    </div>
  );
}
