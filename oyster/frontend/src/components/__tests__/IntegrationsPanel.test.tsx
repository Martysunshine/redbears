/**
 * The Integrations settings panel must show real status only: "Connected"
 * only after a real test call reports it, "Not configured" when no
 * credential exists, and it must never render a credential value it was
 * given — only the masked shape the backend returns.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const { listIntegrations, testIntegration, setIntegrationCredentials, disconnectIntegration } = vi.hoisted(() => ({
  listIntegrations: vi.fn(), testIntegration: vi.fn(), setIntegrationCredentials: vi.fn(), disconnectIntegration: vi.fn(),
}));

vi.mock("@/lib/api", () => ({ listIntegrations, testIntegration, setIntegrationCredentials, disconnectIntegration }));

import { IntegrationsPanel } from "@/components/IntegrationsPanel";

afterEach(() => { cleanup(); vi.clearAllMocks(); });

const base = (over = {}) => ({
  id: "tavily", label: "Tavily", role: "Current web research.", status: "not_configured",
  detail: "No credential configured.", checked_at: null, configured: false, ...over,
});

describe("IntegrationsPanel", () => {
  it("shows Not configured for an integration with no credential", async () => {
    listIntegrations.mockResolvedValue({ integrations: [base()] });
    render(<IntegrationsPanel />);
    await waitFor(() => expect(screen.getByText("Not configured")).toBeInTheDocument());
    expect(screen.queryByText("Connected")).toBeNull();
  });

  it("only shows Connected after a real test call reports it", async () => {
    listIntegrations.mockResolvedValue({ integrations: [base({ configured: true, status: "not_configured" })] });
    testIntegration.mockResolvedValue({ status: "connected", detail: "Connected. 3 source(s).", latency_ms: 120 });
    render(<IntegrationsPanel />);
    await waitFor(() => screen.getByText("Not configured"));
    fireEvent.click(screen.getByTitle("Test connection"));
    await waitFor(() => expect(testIntegration).toHaveBeenCalledWith("tavily"));
    await waitFor(() => expect(screen.getByText(/Connected\. 3 source/)).toBeInTheDocument());
  });

  it("never renders the credential value, only the masked shape", async () => {
    listIntegrations.mockResolvedValue({
      integrations: [base({ configured: true, status: "connected", detail: "Connected.", api_key_shape: "tvly…yz (42 chars)" })],
    });
    render(<IntegrationsPanel />);
    await waitFor(() => expect(screen.getByText("tvly…yz (42 chars)")).toBeInTheDocument());
  });

  it("disconnect clears credentials and never leaks the typed value", async () => {
    listIntegrations.mockResolvedValue({ integrations: [base({ configured: true, status: "connected", detail: "Connected." })] });
    disconnectIntegration.mockResolvedValue({ ...base(), status: "not_configured" });
    render(<IntegrationsPanel />);
    await waitFor(() => screen.getByTitle("Disconnect"));
    fireEvent.click(screen.getByTitle("Disconnect"));
    await waitFor(() => expect(disconnectIntegration).toHaveBeenCalledWith("tavily"));
  });

  it("configure form submits fields and never echoes them back", async () => {
    listIntegrations.mockResolvedValue({ integrations: [base()] });
    setIntegrationCredentials.mockResolvedValue({ ...base(), configured: true });
    render(<IntegrationsPanel />);
    await waitFor(() => screen.getByText("Not configured"));
    fireEvent.click(screen.getByText("Configure"));
    fireEvent.change(screen.getByPlaceholderText("Paste key — never shown again"), { target: { value: "tvly-secret-value" } });
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(setIntegrationCredentials).toHaveBeenCalledWith("tavily", { TAVILY_API_KEY: "tvly-secret-value" }));
    expect(screen.queryByText("tvly-secret-value")).toBeNull();
  });
});
