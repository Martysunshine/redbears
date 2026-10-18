/**
 * Hackathon navigation: signed-in users get exactly Security Intel, Red Bears
 * and Findings; the old Dashboard/Chat, Red Team, Blue Team, RAG Analyst and
 * Execute entries are gone; the model picker offers only Oyster and Huihui.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";

vi.mock("@/components/AuthGate", () => ({ useAuth: () => ({ email: "a@example.com" }) }));
vi.mock("../AuthGate", () => ({ useAuth: () => ({ email: "a@example.com" }) }));

import { Sidebar } from "@/components/Sidebar";

afterEach(() => cleanup());

const props = (over = {}) => ({
  tier: "admin" as const, mode: "intel" as const, onModeChange: vi.fn(), conversations: [], activeConvId: "",
  onSelectConv: vi.fn(), onNewConv: vi.fn(), onRenameConv: vi.fn(), onDeleteConv: vi.fn(), onPinConv: vi.fn(),
  backendOk: true, isOpen: true, onToggle: vi.fn(), selectedModel: "oyster-dolphin-v2", onModelChange: vi.fn(),
  activeProjectName: "p", onOpenSettings: vi.fn(), onOpenHandbook: vi.fn(), searchOpen: false, onToggleSearch: vi.fn(),
  projects: [], activeProjectId: "p", onSwitchProject: vi.fn(), onCreateProject: vi.fn(), onRenameProject: vi.fn(),
  onDeleteProject: vi.fn(async () => null), ...over,
});

describe("Sidebar (hackathon navigation)", () => {
  it("shows only Security Intel, Red Bears and Findings and routes each to its view", () => {
    const p = props();
    render(<Sidebar {...p} />);
    const nav = within(screen.getByRole("navigation", { name: "Primary" }));
    expect(screen.getByRole("button", {name: "New Chat"})).toBeVisible();
    expect(nav.getAllByRole("button").map((b) => b.textContent)).toEqual(["Security Intel", "Red Bears", "Findings"]);
    for (const gone of ["Chat", "Dashboard", "Red Team", "Blue Team", "RAG Analyst", "Execute"]) {
      expect(screen.queryByText(gone)).toBeNull();
    }
    fireEvent.click(nav.getByText("Red Bears")); fireEvent.click(nav.getByText("Findings")); fireEvent.click(nav.getByText("Security Intel"));
    expect(p.onModeChange.mock.calls.map((c) => c[0])).toEqual(["redbears", "findings", "intel"]);
  });

  it("offers only Oyster and Huihui as models", () => {
    render(<Sidebar {...props()} />);
    const opts = within(screen.getByLabelText("Model")).getAllByRole("option").map((o) => o.textContent);
    expect(opts).toEqual(["Oyster", "Huihui"]);
  });

  it("anonymous visitors keep plain Chat only", () => {
    render(<Sidebar {...props({ tier: "anon", mode: "basic" })} />);
    const nav = within(screen.getByRole("navigation", { name: "Primary" }));
    expect(screen.getByRole("button", {name: "New Chat"})).toBeVisible();
    expect(nav.getAllByRole("button").map((b) => b.textContent)).toEqual(["Chat"]);
  });
});
