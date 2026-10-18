"use client";

import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  MessageSquare,
  BookOpen,
  Shield,
  ShieldCheck,
  Radar,
  ShieldAlert,
  BookMarked,
  StickyNote,
  Code2,
  Target,
  Map,
  ClipboardList,
  Bug,
  Wrench,
  Terminal,
  Plus,
  Search,
  Check,
  FolderPlus,
  ChevronRight,
  ChevronsUpDown,
  MoreHorizontal,
  Pencil,
  Trash2,
  Pin,
  PinOff,
  PanelLeftClose,
  ShieldQuestion,
  Layers,
} from "lucide-react";
import { type Conversation, type Mode } from "@/types/chat";
import { UI_MODELS, type ProjectSummary } from "@/lib/api";
import { OysterMascot } from "./OysterMascot";
import { ReportBugButton } from "./ReportBugButton";
import { useAuth } from "./AuthGate";
import { SettingsWheel } from "./brand";

interface SidebarProps {
  /** Any signed-in account gets the workspace toolset; "anon" sees chat only.
   *  "admin" additionally gets the project switcher. */
  tier: "anon" | "user" | "admin" | null;
  mode: Mode;
  onModeChange: (mode: Mode) => void;
  conversations: Conversation[];
  activeConvId: string;
  onSelectConv: (id: string) => void;
  onNewConv: () => void;
  onRenameConv: (id: string, title: string) => void;
  onDeleteConv: (id: string) => void;
  onPinConv: (id: string, pinned: boolean) => void;
  backendOk: boolean | null;
  /** null = not hydrated yet: CSS picks the layout (closed on phones, open on
   *  desktop) so the server markup and the first client paint agree. */
  isOpen: boolean | null;
  onToggle: () => void;
  selectedModel: string;
  onModelChange: (model: string) => void;
  activeProjectName: string;
  onOpenSettings: () => void;
  /** Open the in-app Company Handbook (context-aware to the current mode). */
  onOpenHandbook: () => void;
  /** Search moved here from the chat header; toggles the panel ChatWindow renders. */
  searchOpen: boolean;
  onToggleSearch: () => void;
  /** Operator project switcher. */
  projects: ProjectSummary[];
  activeProjectId: string;
  onSwitchProject: (id: string) => void;
  onCreateProject: (name: string) => void;
  onRenameProject: (id: string, name: string) => void;
  /** Resolves to null on success, or an error message to show (e.g. deleting the
   *  protected default project is refused by the backend). */
  onDeleteProject: (id: string) => Promise<string | null>;
}

// "Evidence" used to live here. It was the same thing as Findings — a logged
// finding — but kept in a separate global store, so the two drifted apart.
// Findings absorbed it (severity/endpoint/method/fix and all) and sits in the
// main nav below, where it is reachable from anywhere rather than buried.
const RED_TEAM: { id: Mode; label: string; icon: React.ElementType }[] = [
  { id: "scope", label: "Scope", icon: Target },
  { id: "recon", label: "Recon", icon: Map },
  { id: "testplan", label: "Planner", icon: ClipboardList },
  { id: "fix", label: "Fix Advisor", icon: Wrench },
  { id: "codelab", label: "Code Lab", icon: Code2 },
];

const RED_TEAM_IDS: Mode[] = RED_TEAM.map((r) => r.id);

// Blue Team — the defensive counterpart to Red Team. "SOC Copilot" is the
// functional analyst workbench (socmat, mounted at /socmat/api); "Shield" is a
// read-only copy-and-run reference for the local CyberMat Shield scanner — it
// never executes anything inside Oyster.
const BLUE_TEAM: { id: Mode; label: string; icon: React.ElementType }[] = [
  { id: "soccopilot", label: "SOC Copilot", icon: Radar },
  { id: "cookbook", label: "Cook Book", icon: BookMarked },
  { id: "notes", label: "Notes", icon: StickyNote },
  { id: "shield", label: "Shield", icon: ShieldAlert },
];

const BLUE_TEAM_IDS: Mode[] = BLUE_TEAM.map((b) => b.id);
const MENU_W = 160;

type MenuAnchor = { id: string; right: number; top: number; bottom: number; up: boolean };

export function Sidebar({
  tier,
  mode,
  onModeChange,
  conversations,
  activeConvId,
  onSelectConv,
  onNewConv,
  onRenameConv,
  onDeleteConv,
  onPinConv,
  backendOk,
  isOpen,
  onToggle,
  selectedModel,
  onModelChange,
  activeProjectName,
  onOpenSettings,
  onOpenHandbook,
  searchOpen,
  onToggleSearch,
  projects,
  activeProjectId,
  onSwitchProject,
  onCreateProject,
  onRenameProject,
  onDeleteProject,
}: SidebarProps) {
  const [redTeamOpen, setRedTeamOpen] = useState(RED_TEAM_IDS.includes(mode));
  const [blueTeamOpen, setBlueTeamOpen] = useState(BLUE_TEAM_IDS.includes(mode));
  const [menu, setMenu] = useState<MenuAnchor | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [deleting, setDeleting] = useState<Conversation | null>(null);
  const [mounted, setMounted] = useState(false);
  const renameRef = useRef<HTMLInputElement>(null);
  const deleteBtnRef = useRef<HTMLButtonElement>(null);
  // Only for prefilling the bug-report form. Null for an anonymous visitor,
  // who then types their own address — see ReportBugButton.
  const { email } = useAuth();

  useEffect(() => setMounted(true), []);

  // The workspace surfaces — red-team panels, RAG, model choice, settings —
  // belong to every signed-in account. The backend gives each account its own
  // project (services/project_context.py), so these act on their data, not a
  // shared one. Anonymous visitors still see plain chat only: none of it would
  // work for them (401) and the simple view is the point of the public tier.
  const isSignedIn = tier === "user" || tier === "admin";
  // Genuinely instance-wide, so still allow-list only: the project switcher
  // flips the ACTIVE project for everyone, and Execute runs real tools.
  const isOperator = tier === "admin";

  const sorted = [...conversations].sort((a, b) => Number(b.pinned) - Number(a.pinned));
  const menuConv = menu ? conversations.find((c) => c.id === menu.id) ?? null : null;

  // Close the menu on Escape.
  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(null);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [menu]);

  useEffect(() => {
    if (deleting) deleteBtnRef.current?.focus();
  }, [deleting]);

  function openMenu(e: React.MouseEvent<HTMLButtonElement>, id: string) {
    e.stopPropagation();
    if (menu?.id === id) return setMenu(null);
    const r = e.currentTarget.getBoundingClientRect();
    const up = window.innerHeight - r.bottom < 140;
    setMenu({ id, right: r.right, top: r.top, bottom: r.bottom, up });
  }

  function startRename(c: Conversation) {
    setMenu(null);
    setRenamingId(c.id);
    setRenameValue(c.title);
    setTimeout(() => renameRef.current?.select(), 0);
  }

  function commitRename() {
    if (renamingId) {
      const next = renameValue.trim();
      const current = conversations.find((c) => c.id === renamingId);
      if (next && next !== current?.title) onRenameConv(renamingId, next);
    }
    setRenamingId(null);
  }

  function confirmDelete() {
    if (deleting) onDeleteConv(deleting.id);
    setDeleting(null);
  }

  const navBtn = (active: boolean) =>
    `group cursor-pointer w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left text-sm transition-all duration-150 ${
      active
        ? "bg-oyster-accent/15 text-oyster-accent"
        : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface/60"
    }`;

  return (
    <>
      {isOpen === true && <div className="fixed inset-0 bg-black/50 z-10 md:hidden" onClick={onToggle} />}

      <aside
        className={`flex flex-col bg-oyster-sidebar border-r border-oyster-border transition-all duration-300 ease-in-out z-20 shrink-0 h-app ${
          isOpen === null
            ? "w-0 overflow-hidden md:w-64 md:overflow-visible"
            : isOpen
              ? "w-64"
              : "w-0 overflow-hidden"
        }`}
      >
        {/* Brand */}
        <div className="flex items-center justify-between px-4 pt-4 pb-3 shrink-0">
          <div className="flex items-center gap-2">
            <OysterMascot size={40} variant="sidebar" />
            <span className="font-semibold text-oyster-text text-[15px] tracking-tight">Oyster</span>
          </div>
          <button
            onClick={onToggle}
            className="cursor-pointer text-oyster-muted/70 hover:text-oyster-text transition-colors p-1 rounded"
            title="Collapse sidebar"
            aria-label="Collapse sidebar"
          >
            <PanelLeftClose size={16} />
          </button>
        </div>

        {/* Project switcher — every signed-in account has its own private
            projects now (the backend scopes list/create/switch by owner), so
            this is no longer operator-only. Anonymous visitors see plain chat. */}
        {isSignedIn && (
          <ProjectSwitcher
            activeProjectName={activeProjectName}
            activeProjectId={activeProjectId}
            projects={projects}
            onSwitch={onSwitchProject}
            onCreate={onCreateProject}
            onRename={onRenameProject}
            onDelete={onDeleteProject}
          />
        )}

        {/* Primary navigation — hackathon build: exactly three views. The old
            Chat/Dashboard, Red Team, Blue Team, RAG Analyst and Execute entries
            are gone from the UI (their backend services are untouched).
            Anonymous visitors have no other view, so they keep plain Chat. */}
        <nav className="px-3 space-y-0.5 shrink-0" aria-label="Primary">
          {!isSignedIn && (
            <button onClick={() => onModeChange("basic")} className={navBtn(mode === "basic")}>
              <MessageSquare size={16} className="shrink-0" />
              <span className="font-medium">Chat</span>
            </button>
          )}
          {isSignedIn && (<>
          <button onClick={() => onModeChange("intel")} className={navBtn(mode === "intel")}>
            <ShieldQuestion size={16} className="shrink-0" />
            <span className="font-medium">Security Intel</span>
          </button>

          <button onClick={() => onModeChange("redbears")} className={navBtn(mode === "redbears")}>
            <Layers size={16} className="shrink-0" />
            <span className="font-medium">Red Bears</span>
          </button>

          <button onClick={() => onModeChange("findings")} className={navBtn(mode === "findings")}>
            <Bug size={16} className="shrink-0" />
            <span className="font-medium">Findings</span>
          </button>
          </>)}
        </nav>


        {/* Conversation controls open the Chat tab from any main view. */}
        <>
        <div className="mx-3 my-3 border-t border-oyster-border shrink-0" />

        {/* Search + New chat */}
        <div className="px-3 shrink-0 space-y-2">
          {/* Search moved here from the chat header. It toggles the same
              multi-scope panel (conversation / files / findings / memory) that
              ChatWindow still renders — only the trigger relocated. */}
          <button
            onClick={onToggleSearch}
            aria-pressed={searchOpen}
            title="Search"
            className={`cursor-pointer w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
              searchOpen
                ? "text-oyster-accent bg-oyster-accent/10 border-oyster-accent/40"
                : "text-oyster-text bg-oyster-surface/70 border-oyster-border hover:border-oyster-accent/40 hover:bg-oyster-surface"
            }`}
          >
            <Search size={15} className="text-oyster-accent" />
            Search
          </button>
          <button
            onClick={onNewConv}
            className="cursor-pointer w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-oyster-text bg-oyster-surface/70 border border-oyster-border hover:border-oyster-accent/40 hover:bg-oyster-surface transition-colors"
          >
            <Plus size={15} className="text-oyster-accent" />
            New Chat
          </button>
        </div>

        {/* History — fills all remaining space, scrolls only when long */}
        <div className="flex-1 min-h-0 flex flex-col px-3 pt-3">
          <p className="text-[10px] font-semibold text-oyster-muted uppercase tracking-widest px-2 mb-1.5 shrink-0">
            History
          </p>
          <div className="flex-1 min-h-0 overflow-y-auto space-y-0.5 pr-0.5" onScroll={() => setMenu(null)}>
            {sorted.length === 0 ? (
              <p className="text-xs text-oyster-muted px-2 py-1">No conversations yet</p>
            ) : (
              sorted.map((conv) => (
                <div key={conv.id} className="relative group">
                  {renamingId === conv.id ? (
                    <input
                      ref={renameRef}
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onBlur={commitRename}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") { e.preventDefault(); commitRename(); }
                        if (e.key === "Escape") { e.preventDefault(); setRenamingId(null); }
                      }}
                      aria-label="Rename conversation"
                      className="w-full bg-oyster-surface border border-oyster-accent/50 rounded-lg px-2.5 py-2 text-xs text-oyster-text outline-none"
                    />
                  ) : (
                    <button
                      onClick={() => onSelectConv(conv.id)}
                      className={`cursor-pointer w-full flex items-center gap-2 pl-2.5 pr-7 py-2 rounded-lg text-left text-xs transition-all duration-150 ${
                        conv.id === activeConvId
                          ? "bg-oyster-surface text-oyster-text"
                          : "text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface/50"
                      }`}
                    >
                      {conv.pinned ? (
                        <Pin size={11} className="shrink-0 text-oyster-accent fill-oyster-accent" />
                      ) : (
                        <MessageSquare size={11} className="shrink-0 opacity-50" />
                      )}
                      <span className="truncate flex-1">{conv.title}</span>
                    </button>
                  )}

                  {renamingId !== conv.id && (
                    <button
                      onClick={(e) => openMenu(e, conv.id)}
                      aria-label={`Options for ${conv.title}`}
                      aria-haspopup="menu"
                      aria-expanded={menu?.id === conv.id}
                      title="More options"
                      className={`cursor-pointer absolute right-1 top-1/2 -translate-y-1/2 p-1 rounded text-oyster-muted hover:text-oyster-text hover:bg-oyster-bg/60 transition-opacity outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60 ${
                        menu?.id === conv.id ? "opacity-100" : "opacity-0 group-hover:opacity-100 focus:opacity-100 focus-visible:opacity-100"
                      }`}
                    >
                      <MoreHorizontal size={13} />
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        </>
        {/* Footer */}
        <div className="px-3 py-2.5 border-t border-oyster-border shrink-0 flex items-center gap-2">
          {isSignedIn ? (
          <div className="relative flex-1 min-w-0">
            <select
              value={selectedModel}
              onChange={(e) => onModelChange(e.target.value)}
              className="cursor-pointer w-full appearance-none bg-transparent hover:bg-oyster-surface/60 rounded-md pl-2 pr-6 py-1.5 text-xs text-oyster-text outline-none transition-colors truncate"
              title="Model"
              aria-label="Model"
            >
              {UI_MODELS.map((m) => (
                <option key={m.key} value={m.key}>
                  {m.label}
                </option>
              ))}
            </select>
            <ChevronsUpDown size={11} className="pointer-events-none absolute right-1.5 top-1/2 -translate-y-1/2 text-oyster-muted" />
          </div>
          ) : (
          <span className="flex-1 text-xs text-oyster-muted truncate pl-1">Oyster AI</span>
          )}

          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              backendOk === null ? "bg-yellow-500 animate-pulse" : backendOk ? "bg-green-500" : "bg-red-500 animate-pulse"
            }`}
            title={backendOk ? "Oyster online" : backendOk === null ? "Connecting…" : "Backend offline"}
          />

          {/* Help lives here so it is reachable from EVERY mode (Red Team and
              Blue Team included) without cluttering each panel — the sidebar is
              always present. It opens the context-aware Company Handbook. */}
          <button
            onClick={onOpenHandbook}
            className="cursor-pointer p-1.5 rounded-md text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface/60 transition-colors shrink-0 outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60"
            title="Company Handbook — how to use Oyster"
            aria-label="Open the Company Handbook"
          >
            <BookOpen size={16} />
          </button>

          {/* Deliberately OUTSIDE the isSignedIn guards around it: Oyster has an
              anonymous tier, and the people who hit a bug before they ever sign
              up are exactly the ones you otherwise never hear from. Signed-in
              reporters get their email filled in; everyone else types it. */}
          <ReportBugButton userEmail={email} />

          {/* The one Settings button. It used to be two — a grey gear here for
              Oyster configuration and a red wheel in the chat header for the
              account and agreement — which split one idea across two places.
              Now it is a single door onto everything (see AccountSettingsModal). */}
          {isSignedIn && (
          <button
            onClick={onOpenSettings}
            className="rw-btn cursor-pointer p-1.5 rounded-md text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface/60 transition-colors shrink-0"
            title="Settings"
            aria-label="Settings"
          >
            <SettingsWheel size={16} />
          </button>
          )}
        </div>
      </aside>

      {/* Conversation actions menu — portalled so it never clips, flips up near the bottom */}
      {mounted && menu && menuConv &&
        createPortal(
          <>
            <div className="fixed inset-0 z-[60]" onClick={() => setMenu(null)} />
            <div
              role="menu"
              aria-label="Conversation actions"
              style={{
                position: "fixed",
                left: Math.max(8, menu.right - MENU_W),
                top: menu.up ? menu.top - 6 : menu.bottom + 6,
                transform: menu.up ? "translateY(-100%)" : undefined,
                width: MENU_W,
              }}
              className="z-[61] bg-oyster-sidebar border border-oyster-border rounded-lg shadow-2xl py-1 text-xs"
            >
              <button
                role="menuitem"
                onClick={() => startRename(menuConv)}
                className="cursor-pointer w-full flex items-center gap-2.5 px-3 py-2 text-left text-oyster-text hover:bg-oyster-surface focus:bg-oyster-surface outline-none transition-colors"
              >
                <Pencil size={13} className="shrink-0" />
                Rename
              </button>
              <button
                role="menuitem"
                onClick={() => { setMenu(null); onPinConv(menuConv.id, !menuConv.pinned); }}
                className="cursor-pointer w-full flex items-center gap-2.5 px-3 py-2 text-left text-oyster-text hover:bg-oyster-surface focus:bg-oyster-surface outline-none transition-colors"
              >
                {menuConv.pinned ? <PinOff size={13} className="shrink-0" /> : <Pin size={13} className="shrink-0" />}
                {menuConv.pinned ? "Unpin" : "Pin"}
              </button>
              <div className="my-1 border-t border-oyster-border" />
              <button
                role="menuitem"
                onClick={() => { setMenu(null); setDeleting(menuConv); }}
                className="cursor-pointer w-full flex items-center gap-2.5 px-3 py-2 text-left text-oyster-text hover:text-red-400 focus:text-red-400 hover:bg-red-500/10 focus:bg-red-500/10 outline-none transition-colors"
              >
                <Trash2 size={13} className="shrink-0" />
                Delete
              </button>
            </div>
          </>,
          document.body
        )}

      {/* Delete confirmation dialog */}
      {deleting && (
        <div
          className="fixed inset-0 z-[70] flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-conv-title"
          onKeyDown={(e) => e.key === "Escape" && setDeleting(null)}
        >
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setDeleting(null)} />
          <div className="relative w-full max-w-xs bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl p-5">
            <h2 id="delete-conv-title" className="text-sm font-semibold text-oyster-text mb-1.5">
              Delete this chat?
            </h2>
            <p className="text-xs text-oyster-muted leading-relaxed mb-4">
              This action cannot be undone.
              <span className="block mt-1 text-oyster-text/80 truncate">“{deleting.title}”</span>
            </p>
            <div className="flex items-center justify-end gap-2">
              <button
                onClick={() => setDeleting(null)}
                className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface border border-oyster-border transition-colors outline-none focus-visible:ring-1 focus-visible:ring-oyster-accent/60"
              >
                Cancel
              </button>
              <button
                ref={deleteBtnRef}
                onClick={confirmDelete}
                className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium text-oyster-text border border-oyster-border hover:bg-red-500 hover:text-white hover:border-red-500 focus:bg-red-500 focus:text-white focus:border-red-500 transition-colors outline-none focus-visible:ring-1 focus-visible:ring-red-400"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

/**
 * The operator project switcher — the button that shows the active project, and
 * a portalled popover to switch / create / rename / delete projects. Portalled
 * (like the conversation menu) so it never clips inside the sidebar. Backing
 * endpoints all exist server-side; page.tsx owns the state and the reloads.
 */
function ProjectSwitcher({
  activeProjectName,
  activeProjectId,
  projects,
  onSwitch,
  onCreate,
  onRename,
  onDelete,
}: {
  activeProjectName: string;
  activeProjectId: string;
  projects: ProjectSummary[];
  onSwitch: (id: string) => void;
  onCreate: (name: string) => void;
  onRename: (id: string, name: string) => void;
  onDelete: (id: string) => Promise<string | null>;
}) {
  const [anchor, setAnchor] = useState<{ left: number; top: number; width: number } | null>(null);
  const [mounted, setMounted] = useState(false);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [creating, setCreating] = useState(false);
  const [createValue, setCreateValue] = useState("");
  const [confirmDel, setConfirmDel] = useState<ProjectSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => setMounted(true), []);

  const openMenu = () => {
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    setAnchor({ left: r.left, top: r.bottom + 6, width: r.width });
    setError(null);
  };
  const close = () => {
    setAnchor(null);
    setRenamingId(null);
    setCreating(false);
    setCreateValue("");
    setError(null);
  };

  const commitRename = () => {
    if (renamingId) {
      const next = renameValue.trim();
      const cur = projects.find((p) => p.id === renamingId);
      if (next && next !== cur?.name) onRename(renamingId, next);
    }
    setRenamingId(null);
  };

  const commitCreate = () => {
    const name = createValue.trim();
    if (name) {
      onCreate(name);
      close();
    } else {
      setCreating(false);
      setCreateValue("");
    }
  };

  const doDelete = async () => {
    if (!confirmDel) return;
    const err = await onDelete(confirmDel.id);
    setConfirmDel(null);
    if (err) setError(err);
  };

  return (
    <div className="px-3 pb-3 shrink-0">
      <button
        ref={btnRef}
        onClick={() => (anchor ? close() : openMenu())}
        className="cursor-pointer w-full flex items-center gap-2.5 px-3 py-2 rounded-lg bg-oyster-surface/70 border border-oyster-border hover:border-oyster-accent/40 transition-colors"
        title="Switch project"
        aria-haspopup="menu"
        aria-expanded={!!anchor}
      >
        <span className="w-5 h-5 rounded-md bg-oyster-accent/20 text-oyster-accent flex items-center justify-center text-[10px] font-bold shrink-0">
          {(activeProjectName || "O").charAt(0).toUpperCase()}
        </span>
        <div className="min-w-0 flex-1 text-left">
          <p className="text-[10px] text-oyster-muted leading-none mb-0.5">Project</p>
          <p className="text-[13px] text-oyster-text font-medium truncate leading-tight">
            {activeProjectName || "Default Engagement"}
          </p>
        </div>
        <ChevronsUpDown size={13} className="text-oyster-muted shrink-0" />
      </button>

      {mounted && anchor &&
        createPortal(
          <>
            <div className="fixed inset-0 z-[60]" onClick={close} />
            <div
              role="menu"
              aria-label="Projects"
              style={{ position: "fixed", left: anchor.left, top: anchor.top, width: Math.max(anchor.width, 224) }}
              className="z-[61] bg-oyster-sidebar border border-oyster-border rounded-lg shadow-2xl py-1 text-xs max-h-[60vh] overflow-y-auto"
            >
              <p className="px-3 pt-1.5 pb-1 text-[10px] font-semibold text-oyster-muted uppercase tracking-widest">
                Projects
              </p>
              {projects.length === 0 ? (
                <p className="px-3 py-2 text-oyster-muted">No projects</p>
              ) : (
                projects.map((p) => (
                  <div key={p.id} className="group/proj relative">
                    {renamingId === p.id ? (
                      <input
                        autoFocus
                        value={renameValue}
                        onChange={(e) => setRenameValue(e.target.value)}
                        onBlur={commitRename}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") { e.preventDefault(); commitRename(); }
                          if (e.key === "Escape") { e.preventDefault(); setRenamingId(null); }
                        }}
                        aria-label="Rename project"
                        className="mx-2 my-0.5 w-[calc(100%-1rem)] bg-oyster-surface border border-oyster-accent/50 rounded-md px-2 py-1.5 text-xs text-oyster-text outline-none"
                      />
                    ) : (
                      <button
                        role="menuitem"
                        onClick={() => { onSwitch(p.id); close(); }}
                        className="cursor-pointer w-full flex items-center gap-2 pl-3 pr-14 py-2 text-left text-oyster-text hover:bg-oyster-surface transition-colors"
                      >
                        <Check
                          size={13}
                          className={`shrink-0 ${p.id === activeProjectId ? "text-oyster-accent" : "opacity-0"}`}
                        />
                        <span className="truncate flex-1">{p.name}</span>
                      </button>
                    )}

                    {renamingId !== p.id && (
                      <div className="absolute right-1.5 top-1/2 -translate-y-1/2 flex items-center gap-0.5 opacity-0 group-hover/proj:opacity-100 transition-opacity">
                        <button
                          onClick={(e) => { e.stopPropagation(); setRenamingId(p.id); setRenameValue(p.name); }}
                          title="Rename project"
                          aria-label={`Rename ${p.name}`}
                          className="cursor-pointer p-1 rounded text-oyster-muted hover:text-oyster-text hover:bg-oyster-bg/60"
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setConfirmDel(p); }}
                          title="Delete project"
                          aria-label={`Delete ${p.name}`}
                          className="cursor-pointer p-1 rounded text-oyster-muted hover:text-red-400 hover:bg-red-500/10"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    )}
                  </div>
                ))
              )}

              <div className="my-1 border-t border-oyster-border" />

              {creating ? (
                <input
                  autoFocus
                  value={createValue}
                  placeholder="Project name…"
                  onChange={(e) => setCreateValue(e.target.value)}
                  onBlur={commitCreate}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") { e.preventDefault(); commitCreate(); }
                    if (e.key === "Escape") { e.preventDefault(); setCreating(false); setCreateValue(""); }
                  }}
                  aria-label="New project name"
                  className="mx-2 my-0.5 w-[calc(100%-1rem)] bg-oyster-surface border border-oyster-accent/50 rounded-md px-2 py-1.5 text-xs text-oyster-text placeholder:text-oyster-muted outline-none"
                />
              ) : (
                <button
                  role="menuitem"
                  onClick={() => { setCreating(true); setCreateValue(""); }}
                  className="cursor-pointer w-full flex items-center gap-2.5 px-3 py-2 text-left text-oyster-text hover:bg-oyster-surface transition-colors"
                >
                  <FolderPlus size={13} className="shrink-0 text-oyster-accent" />
                  New project
                </button>
              )}

              {error && <p className="px-3 py-1.5 text-[11px] text-red-400 leading-snug">{error}</p>}
            </div>
          </>,
          document.body
        )}

      {mounted && confirmDel &&
        createPortal(
          <div
            className="fixed inset-0 z-[70] flex items-center justify-center p-4"
            role="dialog"
            aria-modal="true"
            onKeyDown={(e) => e.key === "Escape" && setConfirmDel(null)}
          >
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setConfirmDel(null)} />
            <div className="relative w-full max-w-xs bg-oyster-sidebar border border-oyster-border rounded-2xl shadow-2xl p-5">
              <h2 className="text-sm font-semibold text-oyster-text mb-1.5">Delete this project?</h2>
              <p className="text-xs text-oyster-muted leading-relaxed mb-4">
                The project is removed from the switcher. This cannot be undone.
                <span className="block mt-1 text-oyster-text/80 truncate">“{confirmDel.name}”</span>
              </p>
              <div className="flex items-center justify-end gap-2">
                <button
                  onClick={() => setConfirmDel(null)}
                  className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium text-oyster-muted hover:text-oyster-text hover:bg-oyster-surface border border-oyster-border transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={doDelete}
                  className="cursor-pointer px-3 py-1.5 rounded-lg text-xs font-medium text-oyster-text border border-oyster-border hover:bg-red-500 hover:text-white hover:border-red-500 transition-colors"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
}
