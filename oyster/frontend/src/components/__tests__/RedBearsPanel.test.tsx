/**
 * The Red Bears panel must tell the truth about reranking: "reranked" only when
 * Nemotron's order was used, an explicit fallback (with the reason) otherwise,
 * and the sources shown must be the ones the stream delivered, numbered to match [n].
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const frames: unknown[] = [];
vi.mock("@/lib/api", async (orig) => {
  const real = await orig<typeof import("@/lib/api")>();
  return {
    ...real,
    askKnowledgeStream: vi.fn(async (_q: string, _m: string, _r: boolean, onFrame: (f: unknown) => void) => {
      for (const f of frames) onFrame(f);
    }),
  };
});

import { RedBearsPanel } from "@/components/RedBearsPanel";

afterEach(() => { cleanup(); frames.length = 0; });

const cite = (n: number, id: string, extra = {}) => ({
  n, chunk_id: id, document: `doc${n}`, chunk: `passage text ${n}`, score: 0.5, source_title: `Title ${n}`, ...extra,
});
const base = { type: "meta", model: "oyster-dolphin-v2", ollama_model: "x", grounded: true, retrieval_ms: 10 };

async function ask() {
  render(<RedBearsPanel onToggleSidebar={() => {}} sidebarOpen selectedModel="oyster-dolphin-v2" onModelChange={() => {}} />);
  fireEvent.click(screen.getByRole("tab", { name: /Switch to Ask view/i }));
  fireEvent.change(screen.getByLabelText(/Ask a security question/i), { target: { value: "q?" } });
  fireEvent.click(screen.getByRole("button", { name: /Ask/ }));
}

describe("RedBearsPanel", () => {
  it("shows a reranked badge, reranked numbering and scores when Nemotron ran", async () => {
    frames.push(
      { ...base, citations: [cite(1, "b", { rerank_score: 7.5, retrieval_rank: 3 }), cite(2, "a", { rerank_score: 1.0, retrieval_rank: 1 })],
        rerank: { requested: true, status: "ran", reason: null, model: "m", endpoint: "local", latency_ms: 900,
                  candidates: 16, returned: 2, order_changed: true } },
      { type: "token", text: "Answer [1]." },
      { type: "done", answer: "Answer [1].", quality_flags: [], ttft_ms: 100, total_ms: 200 },
    );
    await ask();
    await waitFor(() => expect(screen.getByText(/Nemotron reranked 16 → 2/)).toBeInTheDocument());
    expect(screen.getByText(/order changed/)).toBeInTheDocument();
    expect(screen.getByText(/retrieval rank 3 → 1/)).toBeInTheDocument();
    expect(screen.getByText("Answer [1].")).toBeInTheDocument();
  });

  it("shows an explicit fallback with the reason, never 'reranked', when the reranker failed", async () => {
    frames.push(
      { ...base, citations: [cite(1, "a")],
        rerank: { requested: true, status: "fell_back", reason: "reranker timed out after 15s", model: "m",
                  endpoint: "local", latency_ms: 15000, candidates: 16, returned: 1, order_changed: false } },
      { type: "done", answer: "x", quality_flags: [], ttft_ms: 1, total_ms: 2 },
    );
    await ask();
    await waitFor(() => expect(screen.getByText(/did not run — using existing retrieval order/)).toBeInTheDocument());
    expect(screen.getByText(/timed out after 15s/)).toBeInTheDocument();
    expect(screen.queryByText(/Nemotron reranked/)).toBeNull();
  });

  it("shows an in-band stream error", async () => {
    frames.push({ type: "error", detail: "model not found" });
    await ask();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("model not found"));
  });

  it("renders the Chat tab's chatPane, restoring access to Oyster chat alongside Investigate", () => {
    render(
      <RedBearsPanel
        onToggleSidebar={() => {}}
        sidebarOpen
        selectedModel="oyster-dolphin-v2"
        onModelChange={() => {}}
        chatPane={<div data-testid="chat-pane">full chat window</div>}
      />
    );
    expect(screen.getByRole("tab", { name: /Switch to Chat view/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("chat-pane")).toBeInTheDocument();
    // Ask/Investigate stay reachable from the same switcher.
    expect(screen.getByRole("tab", { name: /Switch to Ask view/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /Switch to Investigate view/i })).toBeInTheDocument();
  });

  it("tells the truth when no chatPane is supplied, instead of silently showing nothing", () => {
    render(<RedBearsPanel onToggleSidebar={() => {}} sidebarOpen selectedModel="oyster-dolphin-v2" onModelChange={() => {}} />);
    fireEvent.click(screen.getByRole("tab", { name: /Switch to Chat view/i }));
    expect(screen.getByText(/Chat is unavailable right now/i)).toBeInTheDocument();
  });
});
