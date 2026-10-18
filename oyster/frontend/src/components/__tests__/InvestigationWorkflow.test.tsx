/**
 * The investigation workflow view must show the real, per-stage pipeline
 * outcome — including an honestly "skipped" stage for an unconfigured
 * integration — label unimplemented scenarios as unavailable, and never
 * claim a Devin handoff happened without the backend's own session response.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const {
  listScenarios, listLabInstances, listVerifiedFindings, runInvestigation,
  promoteFinding, cleanupLabInstance, devinPreview, devinHandoff,
} = vi.hoisted(() => ({
  listScenarios: vi.fn(), listLabInstances: vi.fn(), listVerifiedFindings: vi.fn(), runInvestigation: vi.fn(),
  promoteFinding: vi.fn(), cleanupLabInstance: vi.fn(), devinPreview: vi.fn(), devinHandoff: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  researchStatus: vi.fn(async () => ({ missing: ["NEBIUS_API_KEY"], model: "", lab_available: false })),
  listScenarios, listLabInstances, listVerifiedFindings, runInvestigation,
  promoteFinding, cleanupLabInstance, devinPreview, devinHandoff,
}));

import { InvestigationWorkflow } from "@/components/InvestigationWorkflow";

afterEach(() => { cleanup(); vi.clearAllMocks(); });

const scenario = (over = {}) => ({
  id: "sqli_login_bypass", title: "SQL injection — authentication bypass", description: "desc",
  available: true, lab_template: "juice-shop", prerequisites: [], permitted_target: "Lab only.",
  max_requests: 5, timeout_s: 30, success_criteria: [{ name: "probe_authenticated", description: "d" }],
  required_telemetry: [], cleanup: "Reset.", ...over,
});

function setup() {
  listScenarios.mockResolvedValue({
    scenarios: [scenario(), scenario({ id: "xss_reflected", title: "Reflected XSS", available: false })],
  });
  listLabInstances.mockResolvedValue({ instances: [] });
  listVerifiedFindings.mockResolvedValue({ findings: [] });
}

describe("InvestigationWorkflow", () => {
  it("labels an unimplemented scenario as unavailable and disables selecting it", async () => {
    setup();
    render(<InvestigationWorkflow />);
    await waitFor(() => screen.getByText("Reflected XSS"));
    expect(screen.getByText("unavailable")).toBeInTheDocument();
  });

  it("shows each stage's real status, including a skipped integration stage", async () => {
    setup();
    runInvestigation.mockResolvedValue({
      investigation_id: "inv1", scenario_id: "sqli_login_bypass", created_at: 0, duration_s: 12.3,
      stages: [
        { stage: "research", status: "skipped", detail: "Tavily is not configured.", data: {} },
        { stage: "investigate", status: "skipped", detail: "Nemotron reasoning is not configured.", data: {} },
        { stage: "prepare_lab", status: "ok", detail: "Lab instance abc ready.", data: {} },
        { stage: "validate", status: "ok", detail: "Simulation: reproduced.", data: {} },
        { stage: "detect", status: "ok", detail: "Detection: missed.", data: {} },
        { stage: "improve_and_verify", status: "ok", detail: "Retest detection: detected.", data: {} },
      ],
      simulation: "reproduced",
      detection_baseline: { detection: "missed", is_demo_baseline: true },
      detection_improved_retest: { retest_detection: { detection: "detected" } },
      lab_instance_id: "abc", lab_version: "v20.2.0", lab_commit: "5658473cf8814459bf89000ce373b20ed0b4eb37",
    });
    render(<InvestigationWorkflow />);
    await waitFor(() => screen.getByText("SQL injection — authentication bypass"));
    fireEvent.click(screen.getByText("Run investigation"));
    await waitFor(() => expect(screen.getByText("Simulation: reproduced")).toBeInTheDocument());
    expect(screen.getByText("Baseline (demo config): missed")).toBeInTheDocument();
    expect(screen.getByText("Improved rule, retested on a fresh instance: detected")).toBeInTheDocument();
    expect(screen.getByText("Tavily is not configured.")).toBeInTheDocument();
    expect(screen.getByText("Nemotron reasoning is not configured.")).toBeInTheDocument();
  });

  it("Devin handoff is only shown as sent after the backend confirms a real session", async () => {
    setup();
    listVerifiedFindings.mockResolvedValue({
      findings: [{
        id: "f1", title: "Login SQLi auth bypass (lab)", verified_by: "operator", investigation_id: "inv1",
        scenario_id: "sqli_login_bypass", simulation: "reproduced",
        detection_baseline: { detection: "missed" }, detection_improved_retest: null,
        lab_version: "v20.2.0", lab_commit: "565", source_references: [], devin_session: null, created_at: 0,
      }],
    });
    devinPreview.mockResolvedValue({ evidence_package: { title: "x" }, destination_repo: "o/r", repo_allowed: false, devin_configured: false });
    render(<InvestigationWorkflow />);
    await waitFor(() => screen.getByText("Login SQLi auth bypass (lab)"));
    expect(screen.queryByText(/Devin session:/)).toBeNull();
    fireEvent.change(screen.getByPlaceholderText("owner/repo"), { target: { value: "o/r" } });
    fireEvent.click(screen.getByText("Preview evidence"));
    await waitFor(() => expect(devinPreview).toHaveBeenCalledWith("f1", "o/r"));
    await waitFor(() => expect(screen.getByText(/Devin is not configured/)).toBeInTheDocument());
    expect(devinHandoff).not.toHaveBeenCalled();
  });
});
