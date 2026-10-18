/**
 * "Latest intelligence" feed inside Security Intel: loads the cached feed on
 * mount, lets a manual refresh happen, shows the stale/not-configured state
 * honestly, and wires "Research this CVE" through to the investigation
 * workflow without claiming a lab scenario ran when none is compatible.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const feedState = {
  source: "opencve" as const,
  entries: [
    {
      cve_id: "CVE-2024-9999", title: "Example vulnerability", description: "An example description.",
      created_at: "2026-10-15T00:00:00Z", updated_at: "2026-10-17T00:00:00Z",
      newly_published: true, recently_modified: false,
    },
  ],
  last_synced_at: 1760000000, last_attempt_at: 1760000000, last_error: null, stale: false, configured: true,
};

const kevFeedState = {
  source: "cisa_kev" as const,
  entries: [
    {
      cve_id: "CVE-2021-44228", vendor_project: "Apache", product: "Log4j2",
      vulnerability_name: "Apache Log4j2 Remote Code Execution Vulnerability",
      short_description: "Apache Log4j2 contains a remote code execution vulnerability.",
      date_added: "2021-12-10", required_action: "Apply updates per vendor instructions.",
      due_date: "2021-12-24", source_url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    },
  ],
  last_synced_at: 1760000000, last_attempt_at: 1760000000, last_error: null, stale: false, configured: true,
};

let currentFeed: typeof feedState | typeof kevFeedState = feedState;

vi.mock("@/lib/api", async (orig) => {
  const real = await orig<typeof import("@/lib/api")>();
  return {
    ...real,
    getSecurityIntelFeed: vi.fn(async () => currentFeed),
    refreshSecurityIntelFeed: vi.fn(async () => currentFeed),
    researchCve: vi.fn(async () => ({
      investigation_id: "inv1", lab_validation: "skipped", scenario_id: null,
    })),
    classifySecurityQuestion: vi.fn(async () => null),
  };
});

import { SecurityIntelligencePanel } from "@/components/SecurityIntelligencePanel";

afterEach(() => { cleanup(); currentFeed = feedState; });

describe("SecurityIntelligencePanel — Latest intelligence feed", () => {
  it("falls back to CISA KEV when OpenCVE has no token, and never shows a severity score", async () => {
    currentFeed = kevFeedState;
    render(<SecurityIntelligencePanel onToggleSidebar={() => {}} sidebarOpen selectedModel="oyster-dolphin-v2" />);
    await waitFor(() => expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument());
    expect(screen.getByText("Source: CISA KEV")).toBeInTheDocument();
    expect(screen.getByText(/not every CVE/)).toBeInTheDocument();
    expect(screen.getByText("Apache Log4j2 Remote Code Execution Vulnerability")).toBeInTheDocument();
    expect(screen.getByText(/Remediation: Apply updates per vendor instructions\./)).toBeInTheDocument();
    // The entry's own detail line (OpenCVE's "severity scoring unavailable" caveat) must not appear for KEV.
    expect(screen.queryByText(/severity scoring unavailable/i)).toBeNull();
    expect(screen.getByText(/Added to CISA KEV/)).not.toHaveTextContent(/severity|cvss/i);
  });

  it("'Research this CVE' from a KEV entry still goes through the Investigate workflow", async () => {
    currentFeed = kevFeedState;
    render(<SecurityIntelligencePanel onToggleSidebar={() => {}} sidebarOpen selectedModel="oyster-dolphin-v2" />);
    await waitFor(() => expect(screen.getByText("CVE-2021-44228")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Research this CVE/i }));
    await waitFor(() => expect(screen.getByText(/Research only — no compatible lab test/)).toBeInTheDocument());
  });

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
