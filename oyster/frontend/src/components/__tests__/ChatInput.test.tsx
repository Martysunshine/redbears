/**
 * The composer's two reliability guarantees, both regressions this reliability
 * pass fixed:
 *   1. text is cleared ONLY when the send actually proceeded — a guarded-out
 *      or failed send never loses what was typed.
 *   2. while a generation is streaming, the send button IS a working Stop
 *      button — it used to be a decorative icon that did nothing.
 * Plus the double-submit guard: a fast double click must not call onSend twice
 * for the same message, since there is a real `await` between the click and
 * the parent flipping its own isStreaming flag.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";

vi.mock("@/components/AuthGate", () => ({
  useAuth: () => ({ trainingConsent: false }),
}));

import { ChatInput } from "@/components/ChatInput";

afterEach(() => cleanup());

const baseProps = {
  projectId: "p1",
  onUploadFiles: vi.fn(),
  onUploadFolder: vi.fn(),
  onUploadImages: vi.fn(),
  onUploadVideos: vi.fn(),
  onCreateNote: vi.fn(),
  onOpenKnowledge: vi.fn(),
  artifacts: [],
  onRemoveArtifact: vi.fn(),
  onSummarizeArtifact: vi.fn(),
  onOpenArtifact: vi.fn(),
  isUploading: false,
};

function typeAndGetSendButton(text = "hello") {
  const textarea = screen.getByPlaceholderText(/ask oyster/i);
  fireEvent.change(textarea, { target: { value: text } });
  return { textarea, button: screen.getByLabelText("Send") };
}

describe("ChatInput — composer text", () => {
  it("clears the text when onSend resolves true", async () => {
    const onSend = vi.fn().mockResolvedValue(true);
    render(<ChatInput {...baseProps} onSend={onSend} isStreaming={false} />);
    const { textarea, button } = typeAndGetSendButton();
    fireEvent.click(button);
    await vi.waitFor(() => expect(onSend).toHaveBeenCalledWith("hello"));
    await vi.waitFor(() => expect((textarea as HTMLTextAreaElement).value).toBe(""));
  });

  it("keeps the text when onSend resolves false (guarded out or failed)", async () => {
    const onSend = vi.fn().mockResolvedValue(false);
    render(<ChatInput {...baseProps} onSend={onSend} isStreaming={false} />);
    const { textarea, button } = typeAndGetSendButton("don't lose me");
    fireEvent.click(button);
    await vi.waitFor(() => expect(onSend).toHaveBeenCalledTimes(1));
    expect((textarea as HTMLTextAreaElement).value).toBe("don't lose me");
  });

  it("keeps the text when onSend rejects outright", async () => {
    const onSend = vi.fn().mockRejectedValue(new Error("network down"));
    render(<ChatInput {...baseProps} onSend={onSend} isStreaming={false} />);
    const { textarea, button } = typeAndGetSendButton("still here");
    // handleSend's try/finally must not let a rejection escape uncaught.
    expect(() => fireEvent.click(button)).not.toThrow();
    await vi.waitFor(() => expect(onSend).toHaveBeenCalledTimes(1));
    expect((textarea as HTMLTextAreaElement).value).toBe("still here");
  });

  it("a fast double click sends only once", async () => {
    let resolve!: (v: boolean) => void;
    const onSend = vi.fn(() => new Promise<boolean>((r) => (resolve = r)));
    render(<ChatInput {...baseProps} onSend={onSend} isStreaming={false} />);
    const { button } = typeAndGetSendButton();
    fireEvent.click(button);
    fireEvent.click(button); // fired before the first call's promise settles
    expect(onSend).toHaveBeenCalledTimes(1);
    resolve(true);
  });
});

describe("ChatInput — Stop", () => {
  it("calls onStop, not onSend, while streaming", () => {
    const onSend = vi.fn().mockResolvedValue(true);
    const onStop = vi.fn();
    render(<ChatInput {...baseProps} onSend={onSend} onStop={onStop} isStreaming={true} />);
    fireEvent.click(screen.getByLabelText("Stop generating"));
    expect(onStop).toHaveBeenCalledTimes(1);
    expect(onSend).not.toHaveBeenCalled();
  });

  it("without onStop, the button while streaming is disabled rather than silently failing", () => {
    const onSend = vi.fn().mockResolvedValue(true);
    render(<ChatInput {...baseProps} onSend={onSend} isStreaming={true} />);
    const button = screen.getByLabelText("Send");
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(onSend).not.toHaveBeenCalled();
  });

  it("Enter does not send while streaming", () => {
    const onSend = vi.fn().mockResolvedValue(true);
    render(<ChatInput {...baseProps} onSend={onSend} onStop={vi.fn()} isStreaming={true} />);
    const textarea = screen.getByPlaceholderText(/ask oyster/i);
    fireEvent.change(textarea, { target: { value: "hi" } });
    fireEvent.keyDown(textarea, { key: "Enter" });
    expect(onSend).not.toHaveBeenCalled();
  });
});

describe("ChatInput — locked (anonymous quota spent)", () => {
  it("clicking while locked triggers the upsell, never onSend", () => {
    const onSend = vi.fn().mockResolvedValue(true);
    const onLockedClick = vi.fn();
    render(<ChatInput {...baseProps} onSend={onSend} isStreaming={false} isLocked onLockedClick={onLockedClick} />);
    // The button sits inside the composer wrapper, which ALSO fires
    // onLockedClick on click (so tapping anywhere in the locked composer
    // opens the upsell, not just the button) — so this click bubbles and
    // fires it twice. What matters here is only that it fires, and onSend
    // never does.
    fireEvent.click(screen.getByLabelText("Unlock unlimited chat"));
    expect(onLockedClick).toHaveBeenCalled();
    expect(onSend).not.toHaveBeenCalled();
  });
});
