/**
 * The conversation store — a pure reducer for the sidebar history.
 *
 * WHY THIS EXISTS. `page.tsx` used to hold conversations in two plain
 * `useState<Conversation[]>` arrays and mutate them with `.map()` calls
 * scattered across a dozen callbacks. The bug this caused: `loadWorkspace`
 * (called on boot, on project switch, and — before F1 — on every tab-switch
 * re-boot) replaced the WHOLE array with fresh rows from `listConversations`,
 * which carry no messages. If that ran after a conversation had already been
 * hydrated (its messages fetched and merged in), the replacement silently
 * wiped them back to empty — "the chat loads empty until I refresh" was this,
 * not a network failure. A list refresh must be able to update titles/pinned
 * WITHOUT touching a conversation's messages or hydration state, and nothing
 * in the codebase would say so directly — a raw array can't express the
 * distinction. A reducer can, because state IS the distinction.
 *
 * SHAPE. `byId` keyed by conversation id, `order` as an explicit array per
 * mode (list order matters — pinned-first, then recency — and is the
 * server's call, not derived by re-sorting on every read). A record's
 * `hydration` is `none | loading | loaded | error`, independent of whether it
 * HAS messages — a freshly listed row is `none` with `messages: []`, a
 * hydrated-but-genuinely-empty new chat is `loaded` with `messages: []`, and
 * only the second one is allowed to render "How can I help?" instead of a
 * spinner.
 */
import type { Conversation, Message, Mode } from "@/types/chat";

export type Hydration = "none" | "loading" | "loaded" | "error";

export interface StoreConversation extends Conversation {
  hydration: Hydration;
  hydrationError?: string;
}

export interface ConversationStoreState {
  byId: Record<string, StoreConversation>;
  order: { basic: string[]; rag: string[] };
}

export function emptyStore(): ConversationStoreState {
  return { byId: {}, order: { basic: [], rag: [] } };
}

function orderKey(mode: Mode): "basic" | "rag" {
  return mode === "rag" ? "rag" : "basic";
}

function withRecord(
  state: ConversationStoreState,
  id: string,
  fn: (c: StoreConversation) => StoreConversation
): ConversationStoreState {
  const existing = state.byId[id];
  if (!existing) return state;
  const next = fn(existing);
  if (next === existing) return state;
  return { ...state, byId: { ...state.byId, [id]: next } };
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type ConversationStoreAction =
  /** A fresh list from the server for one mode. Upserts title/pinned/
   *  createdAt ONLY — never touches messages or hydration of a record that
   *  already exists, and never drops a row the caller says to keep (a
   *  `local-*` draft, or the id the caller is actively streaming into —
   *  the row that made the request that produced this very list). Rows
   *  present before that are absent from the new list AND not kept are
   *  removed (a delete from another tab, or — for a project switch — simply
   *  gone because they belong to a different workspace now). */
  | { type: "mergeList"; mode: Mode; rows: Conversation[]; keepIds?: string[] }
  /** Wholesale replace — used only by `resetForProject`, where every existing
   *  row genuinely belongs to a workspace we are leaving. */
  | { type: "resetForProject" }
  /** Seed the store from an anonymous visitor's localStorage history at boot.
   *  Unlike `mergeList`, every row here already carries its messages (there is
   *  no server to hydrate FROM for an anonymous visitor — their whole history
   *  lives in this browser), so every record is marked `loaded` outright and
   *  the store is replaced wholesale, matching the boot-once semantics of the
   *  anonymous flow (it never re-runs mid-session the way a project switch
   *  does). Order is taken from `convs` as given — callers pass it already
   *  sorted newest-first, the same order the array has always rendered in. */
  | { type: "loadAnon"; convs: Conversation[] }
  | { type: "setHydration"; id: string; hydration: Hydration; error?: string }
  | { type: "setMessages"; id: string; messages: Message[] }
  | { type: "appendMessages"; id: string; messages: Message[] }
  /** Replace ALL of a record's messages with these (used by chatStream's
   *  onReset: a resumed generation re-sends its answer from the start, so the
   *  bubble must be replaced, not appended a second time). */
  | { type: "replaceMessages"; id: string; messages: Message[] }
  | { type: "patchMessage"; id: string; messageId: string; patch: Partial<Message> }
  | { type: "removeMessage"; id: string; messageId: string }
  /** A `local-*` draft was promoted to a real server row. */
  | { type: "replaceConvId"; oldId: string; newId: string }
  /** The server assigned a real id to a message that was optimistic
   *  (client-generated). Needed so a rating/edit on a just-sent message
   *  reaches the right row instead of 404ing until the next reload. */
  | { type: "replaceMessageId"; convId: string; oldId: string; newId: string }
  | { type: "upsertDraft"; conv: Conversation }
  | { type: "patchConv"; id: string; patch: Partial<Conversation> }
  | { type: "removeConv"; id: string };

export function conversationStoreReducer(
  state: ConversationStoreState,
  action: ConversationStoreAction
): ConversationStoreState {
  switch (action.type) {
    case "mergeList": {
      const key = orderKey(action.mode);
      const keep = new Set(action.keepIds ?? []);
      const incomingIds = new Set(action.rows.map((r) => r.id));
      const byId = { ...state.byId };

      for (const row of action.rows) {
        const existing = byId[row.id];
        if (existing) {
          // Never touch messages/hydration here — that is the whole point.
          byId[row.id] = { ...existing, title: row.title, pinned: row.pinned, createdAt: row.createdAt };
        } else {
          byId[row.id] = { ...row, hydration: "none" };
        }
      }
      // Drop rows that used to be in this mode's order but are neither in
      // the fresh list nor explicitly kept (a delete, or a workspace switch)
      // — and remove them from byId too, so a stale record can never be read
      // back by id after it has fallen out of every order array.
      const survivingOrder = state.order[key].filter((id) => incomingIds.has(id) || keep.has(id));
      for (const id of state.order[key]) {
        if (!survivingOrder.includes(id)) delete byId[id];
      }
      const newOrder = [...survivingOrder];
      for (const row of action.rows) {
        if (!newOrder.includes(row.id)) newOrder.push(row.id);
      }
      return { ...state, byId, order: { ...state.order, [key]: newOrder } };
    }

    case "resetForProject":
      return emptyStore();

    case "loadAnon": {
      const byId: Record<string, StoreConversation> = {};
      const basic: string[] = [];
      const rag: string[] = [];
      for (const c of action.convs) {
        byId[c.id] = { ...c, hydration: "loaded" };
        (c.mode === "rag" ? rag : basic).push(c.id);
      }
      return { byId, order: { basic, rag } };
    }

    case "setHydration":
      return withRecord(state, action.id, (c) => ({
        ...c,
        hydration: action.hydration,
        hydrationError: action.hydration === "error" ? action.error : undefined,
      }));

    case "setMessages":
      return withRecord(state, action.id, (c) => ({ ...c, messages: action.messages, hydration: "loaded" }));

    case "appendMessages":
      return withRecord(state, action.id, (c) => ({ ...c, messages: [...c.messages, ...action.messages] }));

    case "replaceMessages":
      return withRecord(state, action.id, (c) => ({ ...c, messages: action.messages }));

    case "patchMessage":
      return withRecord(state, action.id, (c) => ({
        ...c,
        messages: c.messages.map((m) => (m.id === action.messageId ? { ...m, ...action.patch } : m)),
      }));

    case "removeMessage":
      return withRecord(state, action.id, (c) => ({
        ...c,
        messages: c.messages.filter((m) => m.id !== action.messageId),
      }));

    case "replaceConvId": {
      const existing = state.byId[action.oldId];
      if (!existing) return state;
      const byId = { ...state.byId };
      delete byId[action.oldId];
      byId[action.newId] = { ...existing, id: action.newId };
      const order = {
        basic: state.order.basic.map((id) => (id === action.oldId ? action.newId : id)),
        rag: state.order.rag.map((id) => (id === action.oldId ? action.newId : id)),
      };
      return { byId, order };
    }

    case "replaceMessageId":
      return withRecord(state, action.convId, (c) => ({
        ...c,
        messages: c.messages.map((m) => (m.id === action.oldId ? { ...m, id: action.newId } : m)),
      }));

    case "upsertDraft": {
      const key = orderKey(action.conv.mode);
      const byId = { ...state.byId, [action.conv.id]: { ...action.conv, hydration: "loaded" as Hydration } };
      const order = state.order[key].includes(action.conv.id)
        ? state.order[key]
        : [action.conv.id, ...state.order[key]];
      return { byId, order: { ...state.order, [key]: order } };
    }

    case "patchConv":
      return withRecord(state, action.id, (c) => ({ ...c, ...action.patch }));

    case "removeConv": {
      if (!state.byId[action.id]) return state;
      const byId = { ...state.byId };
      delete byId[action.id];
      return {
        byId,
        order: {
          basic: state.order.basic.filter((id) => id !== action.id),
          rag: state.order.rag.filter((id) => id !== action.id),
        },
      };
    }

    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------

export function listFor(state: ConversationStoreState, mode: Mode): StoreConversation[] {
  const key = orderKey(mode);
  return state.order[key].map((id) => state.byId[id]).filter((c): c is StoreConversation => !!c);
}

export function getConv(state: ConversationStoreState, id: string): StoreConversation | undefined {
  return state.byId[id];
}
