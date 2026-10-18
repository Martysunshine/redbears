import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Listener = (event: string, session: unknown) => void;
const auth = {
  listener: null as Listener | null,
  getSession: vi.fn(),
};

vi.mock("@/lib/supabase", () => ({
  supabase: {
    auth: {
      getSession: () => auth.getSession(),
      onAuthStateChange: (cb: Listener) => {
        auth.listener = cb;
        return { data: { subscription: { unsubscribe: vi.fn() } } };
      },
      signOut: vi.fn(),
    },
    rpc: vi.fn(),
  },
}));

const getMe = vi.fn();
vi.mock("@/lib/api", () => ({
  getMe: () => getMe(),
  setTrainingConsent: vi.fn(),
  deleteAccount: vi.fn(),
}));

const unauthorized = { handler: null as (() => void) | null };
vi.mock("@/lib/request", () => ({
  onUnauthorized: (cb: (() => void) | null) => {
    unauthorized.handler = cb;
  },
  resetUnauthorized: vi.fn(),
}));

vi.mock("@/components/AgreementGate", () => ({ AgreementGate: () => null }));

import { AuthGate, useAuth } from "@/components/AuthGate";

function Probe() {
  const { tier, authReady, sessionExpired } = useAuth();
  return <div data-testid="probe">{`tier=${tier ?? "null"} ready=${authReady} expired=${sessionExpired}`}</div>;
}

const person = (id: string, email = `${id}@example.test`) => ({
  user: { id, email },
  access_token: `tok-${id}`,
});

beforeEach(() => {
  auth.listener = null;
  auth.getSession.mockReset();
  getMe.mockReset().mockResolvedValue({ tier: "user", email: "u1@example.test" });
  unauthorized.handler = null;
});

describe("AuthGate", () => {
  it("keeps tier null until the stored session is read — never an anonymous flash", async () => {
    let resolveSession: (v: unknown) => void = () => {};
    auth.getSession.mockReturnValue(new Promise((r) => (resolveSession = r)));
    render(
      <AuthGate>
        <Probe />
      </AuthGate>
    );
    expect(screen.getByTestId("probe").textContent).toContain("tier=null");
    expect(screen.getByTestId("probe").textContent).toContain("ready=false");
    await act(async () => {
      resolveSession({ data: { session: person("u1") } });
    });
    await waitFor(() => expect(screen.getByTestId("probe").textContent).toContain("tier=user"));
    expect(screen.getByTestId("probe").textContent).toContain("ready=true");
    expect(getMe).toHaveBeenCalledTimes(1);
  });

  it("ignores SIGNED_IN re-emissions and TOKEN_REFRESHED for the same person", async () => {
    auth.getSession.mockResolvedValue({ data: { session: person("u1") } });
    render(
      <AuthGate>
        <Probe />
      </AuthGate>
    );
    await waitFor(() => expect(screen.getByTestId("probe").textContent).toContain("tier=user"));
    await act(async () => {
      auth.listener?.("SIGNED_IN", person("u1"));
      auth.listener?.("TOKEN_REFRESHED", person("u1"));
      auth.listener?.("SIGNED_IN", person("u1"));
    });
    expect(getMe).toHaveBeenCalledTimes(1);
  });

  it("re-resolves for a different person and goes anonymous on SIGNED_OUT", async () => {
    auth.getSession.mockResolvedValue({ data: { session: person("u1") } });
    render(
      <AuthGate>
        <Probe />
      </AuthGate>
    );
    await waitFor(() => expect(screen.getByTestId("probe").textContent).toContain("tier=user"));
    await act(async () => {
      auth.listener?.("SIGNED_IN", person("u2"));
    });
    await waitFor(() => expect(getMe).toHaveBeenCalledTimes(2));
    await act(async () => {
      auth.listener?.("SIGNED_OUT", null);
    });
    await waitFor(() => expect(screen.getByTestId("probe").textContent).toContain("tier=anon"));
  });

  it("an anonymous visitor resolves to anon once the (empty) session is read", async () => {
    auth.getSession.mockResolvedValue({ data: { session: null } });
    render(
      <AuthGate>
        <Probe />
      </AuthGate>
    );
    await waitFor(() => expect(screen.getByTestId("probe").textContent).toContain("tier=anon"));
    expect(getMe).not.toHaveBeenCalled();
  });

  it("shows the session-expired banner when the request layer reports a refused token", async () => {
    auth.getSession.mockResolvedValue({ data: { session: person("u1") } });
    render(
      <AuthGate>
        <Probe />
      </AuthGate>
    );
    await waitFor(() => expect(screen.getByTestId("probe").textContent).toContain("tier=user"));
    await act(async () => {
      unauthorized.handler?.();
    });
    expect(screen.getByText(/session has expired/i)).toBeInTheDocument();
    expect(screen.getByTestId("probe").textContent).toContain("expired=true");
  });
});
