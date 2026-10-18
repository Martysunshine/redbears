import { describe, expect, it } from "vitest";
import {
  conversationStoreReducer as reduce,
  emptyStore,
  getConv,
  listFor,
  type ConversationStoreState,
} from "@/lib/conversationStore";
import type { Conversation, Message } from "@/types/chat";

function conv(id: string, over: Partial<Conversation> = {}): Conversation {
  return { id, title: "t", messages: [], createdAt: new Date("2026-01-01"), mode: "basic", pinned: false, ...over };
}

function msg(id: string, over: Partial<Message> = {}): Message {
  return { id, role: "assistant", content: "", timestamp: new Date("2026-01-01"), ...over };
}

function withMessages(state: ConversationStoreState, id: string, messages: Message[]): ConversationStoreState {
  let s = reduce(state, { type: "mergeList", mode: "basic", rows: [conv(id)] });
  return reduce(s, { type: "setMessages", id, messages });
}

describe("mergeList — the bug this store exists to prevent", () => {
  it("never touches messages or hydration of a conversation that is already hydrated", () => {
    let s = withMessages(emptyStore(), "c1", [msg("m1", { content: "hi" })]);
    expect(getConv(s, "c1")?.hydration).toBe("loaded");

    // The list refresh that used to wipe this — e.g. a re-boot on tab switch.
    s = reduce(s, { type: "mergeList", mode: "basic", rows: [conv("c1", { title: "renamed" })] });

    const c = getConv(s, "c1")!;
    expect(c.messages).toEqual([msg("m1", { content: "hi" })]);
    expect(c.hydration).toBe("loaded");
    expect(c.title).toBe("renamed"); // title/pinned DO update
  });

  it("upserts title and pinned without disturbing an in-progress hydration", () => {
    let s = reduce(emptyStore(), { type: "mergeList", mode: "basic", rows: [conv("c1")] });
    s = reduce(s, { type: "setHydration", id: "c1", hydration: "loading" });
    s = reduce(s, { type: "mergeList", mode: "basic", rows: [conv("c1", { title: "x", pinned: true })] });
    const c = getConv(s, "c1")!;
    expect(c.hydration).toBe("loading");
    expect(c.title).toBe("x");
    expect(c.pinned).toBe(true);
  });

  it("a row missing from the new list is removed, unless kept", () => {
    let s = reduce(emptyStore(), {
      type: "mergeList",
      mode: "basic",
      rows: [conv("c1"), conv("c2")],
    });
    // c2 deleted server-side; c1 (the row we're actively streaming into) is
    // kept even though the list that came back doesn't include it (e.g. a
    // list fetched before the draft was promoted to a real row).
    s = reduce(s, { type: "mergeList", mode: "basic", rows: [], keepIds: ["c1"] });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["c1"]);
    expect(getConv(s, "c2")).toBeUndefined();
  });

  it("a local- draft survives a list merge when kept, and is not duplicated once it's also listed", () => {
    let s = reduce(emptyStore(), { type: "upsertDraft", conv: conv("local-1") });
    s = reduce(s, { type: "mergeList", mode: "basic", rows: [], keepIds: ["local-1"] });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["local-1"]);
    // Once the draft is promoted (replaceConvId) and the server starts
    // listing the real id, the list should show exactly one row.
    s = reduce(s, { type: "replaceConvId", oldId: "local-1", newId: "real-1" });
    s = reduce(s, { type: "mergeList", mode: "basic", rows: [conv("real-1")] });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["real-1"]);
  });

  it("keeps basic and rag lists independent", () => {
    let s = reduce(emptyStore(), { type: "mergeList", mode: "basic", rows: [conv("b1")] });
    s = reduce(s, { type: "mergeList", mode: "rag", rows: [conv("r1", { mode: "rag" })] });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["b1"]);
    expect(listFor(s, "rag").map((c) => c.id)).toEqual(["r1"]);
  });

  it("preserves server order (pinned-first, recency) rather than re-sorting", () => {
    const s = reduce(emptyStore(), {
      type: "mergeList",
      mode: "basic",
      rows: [conv("pinned-old", { pinned: true }), conv("unpinned-new")],
    });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["pinned-old", "unpinned-new"]);
  });
});

describe("loadAnon", () => {
  it("seeds every conversation as already loaded and preserves given order", () => {
    const s = reduce(emptyStore(), {
      type: "loadAnon",
      convs: [conv("c1", { messages: [msg("m1")] }), conv("c2")],
    });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["c1", "c2"]);
    expect(getConv(s, "c1")?.hydration).toBe("loaded");
    expect(getConv(s, "c1")?.messages).toHaveLength(1);
  });

  it("replaces the whole store rather than merging", () => {
    let s = withMessages(emptyStore(), "stale", [msg("old")]);
    s = reduce(s, { type: "loadAnon", convs: [conv("fresh")] });
    expect(getConv(s, "stale")).toBeUndefined();
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["fresh"]);
  });

  it("routes rag-mode rows into the rag order", () => {
    const s = reduce(emptyStore(), {
      type: "loadAnon",
      convs: [conv("b1"), conv("r1", { mode: "rag" })],
    });
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["b1"]);
    expect(listFor(s, "rag").map((c) => c.id)).toEqual(["r1"]);
  });
});

describe("hydration lifecycle", () => {
  it("none -> loading -> loaded is independent of message content", () => {
    let s = reduce(emptyStore(), { type: "mergeList", mode: "basic", rows: [conv("c1")] });
    expect(getConv(s, "c1")?.hydration).toBe("none");
    s = reduce(s, { type: "setHydration", id: "c1", hydration: "loading" });
    expect(getConv(s, "c1")?.hydration).toBe("loading");
    // A genuinely empty (new) chat, hydrated with zero messages — must read as
    // loaded-and-empty, not none-and-empty, or the UI can't tell "never
    // fetched" from "fetched, and there's nothing there".
    s = reduce(s, { type: "setMessages", id: "c1", messages: [] });
    expect(getConv(s, "c1")).toMatchObject({ hydration: "loaded", messages: [] });
  });

  it("a failed hydrate records the error and leaves prior messages alone", () => {
    let s = withMessages(emptyStore(), "c1", [msg("m1")]);
    s = reduce(s, { type: "setHydration", id: "c1", hydration: "error", error: "network" });
    const c = getConv(s, "c1")!;
    expect(c.hydration).toBe("error");
    expect(c.hydrationError).toBe("network");
    expect(c.messages).toHaveLength(1);
  });

  it("setHydration on an unknown id is a no-op, not a crash", () => {
    const s = emptyStore();
    expect(() => reduce(s, { type: "setHydration", id: "ghost", hydration: "loading" })).not.toThrow();
    expect(reduce(s, { type: "setHydration", id: "ghost", hydration: "loading" })).toBe(s);
  });
});

describe("message operations", () => {
  it("appendMessages adds without replacing", () => {
    let s = withMessages(emptyStore(), "c1", [msg("m1")]);
    s = reduce(s, { type: "appendMessages", id: "c1", messages: [msg("m2")] });
    expect(getConv(s, "c1")?.messages.map((m) => m.id)).toEqual(["m1", "m2"]);
  });

  it("replaceMessages swaps the whole array — used by chatStream's onReset on resume", () => {
    let s = withMessages(emptyStore(), "c1", [msg("m1", { content: "stale" })]);
    s = reduce(s, { type: "replaceMessages", id: "c1", messages: [msg("m1", { content: "fresh" })] });
    expect(getConv(s, "c1")?.messages).toEqual([msg("m1", { content: "fresh" })]);
  });

  it("patchMessage updates one message by id and leaves the rest untouched", () => {
    let s = withMessages(emptyStore(), "c1", [msg("m1", { content: "a" }), msg("m2", { content: "b" })]);
    s = reduce(s, { type: "patchMessage", id: "c1", messageId: "m1", patch: { content: "a2" } });
    expect(getConv(s, "c1")?.messages.map((m) => m.content)).toEqual(["a2", "b"]);
  });

  it("removeMessage drops exactly one message", () => {
    let s = withMessages(emptyStore(), "c1", [msg("m1"), msg("m2")]);
    s = reduce(s, { type: "removeMessage", id: "c1", messageId: "m1" });
    expect(getConv(s, "c1")?.messages.map((m) => m.id)).toEqual(["m2"]);
  });

  it("replaceMessageId swaps an optimistic client id for the server's id", () => {
    let s = withMessages(emptyStore(), "c1", [msg("local-abc")]);
    s = reduce(s, { type: "replaceMessageId", convId: "c1", oldId: "local-abc", newId: "srv-1" });
    expect(getConv(s, "c1")?.messages.map((m) => m.id)).toEqual(["srv-1"]);
  });
});

describe("replaceConvId — draft promotion", () => {
  it("moves a draft's record and its position in order to the new id", () => {
    let s = reduce(emptyStore(), { type: "upsertDraft", conv: conv("local-1") });
    s = reduce(s, { type: "setMessages", id: "local-1", messages: [msg("m1")] });
    s = reduce(s, { type: "replaceConvId", oldId: "local-1", newId: "real-1" });
    expect(getConv(s, "local-1")).toBeUndefined();
    expect(getConv(s, "real-1")?.messages).toHaveLength(1);
    expect(listFor(s, "basic").map((c) => c.id)).toEqual(["real-1"]);
  });

  it("is a no-op for an id that does not exist", () => {
    const s = emptyStore();
    expect(reduce(s, { type: "replaceConvId", oldId: "ghost", newId: "x" })).toBe(s);
  });
});

describe("removeConv", () => {
  it("removes from byId and from whichever mode's order it was in", () => {
    let s = reduce(emptyStore(), { type: "mergeList", mode: "rag", rows: [conv("c1", { mode: "rag" })] });
    s = reduce(s, { type: "removeConv", id: "c1" });
    expect(getConv(s, "c1")).toBeUndefined();
    expect(listFor(s, "rag")).toEqual([]);
  });
});

describe("patchConv", () => {
  it("shallow-patches conversation fields", () => {
    let s = reduce(emptyStore(), { type: "mergeList", mode: "basic", rows: [conv("c1")] });
    s = reduce(s, { type: "patchConv", id: "c1", patch: { pinned: true } });
    expect(getConv(s, "c1")?.pinned).toBe(true);
  });
});
