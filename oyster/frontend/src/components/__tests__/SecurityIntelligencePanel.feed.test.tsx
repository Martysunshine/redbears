/**
 * "Latest intelligence" feed inside Security Intel: loads the cached feed on
 * mount, lets a manual refresh happen, shows the stale/not-configured state
 * honestly, and wires "Research this CVE" through to the investigation
 * workflow without claiming a lab scenario ran when none is compatible.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const feedState = {
  entries: [
    {
      cve_id: "CVE-2024-9999", title: "Example vulnerability", description: "An example description.",
      created_at: "2026-10-15T00:00:00Z", updated_at: "2026-10-17T00:00:00Z",
      newly_published: true, recently_modified: false,
    },
  ],
  last_synced_at: 1760000000, last_attempt_at: 1760000000, last_error: null, stale: false, configured: true,
};

vi.mock("@/lib/api", async (orig) => {
  const real = await orig<typeof import("@/lib/api")>();
  return {
    ...real,
    getSecurityIntelFeed: vi.fn(async () => feedState),
    refreshSecurityIntelFeed: vi.fn(async () => feedState),
    researchCve: vi.fn(async () => ({
      investigation_id: "inv1", lab_validation: "skipped", scenario_id: null,
    })),
    classifySecurityQuestion: vi.fn(async () => null),
  };
});

import { SecurityIntelligencePanel } from "@/components/SecurityIntelligencePanel";

afterEach(() => cleanup());

describe("SecurityIntelligencePanel — Latest intelligence feed", () => {
  it("shows cached CVE entries with newly_published/recently_modified labels", async () => {
    render(<SecurityIntelligencePanel onToggleSidebar={() => {}} sidebarOpen selectedModel="oyster-dolphin-v2" />);
    await waitFor(() => expect(screen.getByText("CVE-2024-9999")).toBeInTheDocument());
    expect(screen.getByText("newly published")).toBeInTheDocument();
    expect(screen.queryByText("recently modified")).toBeNull();
  });

  it("'Research this CVE' reports research-only when no scenario is compatible", async () => {
    render(<SecurityIntelligencePanel onToggleSidebar={() => {}} sidebarOpen selectedModel="oyster-dolphin-v2" />);
    await waitFor(() => expect(screen.getByText("CVE-2024-9999")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Research this CVE/i }));
    await waitFor(() => expect(screen.getByText(/Research only — no compatible lab test/)).toBeInTheDocument());
  });
});
