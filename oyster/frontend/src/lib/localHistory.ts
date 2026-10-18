// Chat history for visitors who have not signed in.
//
// Deliberately browser-side (localStorage), not a server row keyed by a
// tracking cookie: an anonymous visitor has no account to own the data, and
// storing strangers' conversations server-side would mean holding personal
// data we cannot let them manage or delete. localStorage is first-party
// functional storage — it survives refreshes and browser restarts, it never
// leaves the device, and clearing site data removes it completely.
//
// On sign-up/sign-in these conversations are migrated into the account (see
// migrateLocalHistory in page.tsx) and then cleared.

import type { Conversation, Message } from "@/types/chat";

const KEY = "oyster-anon-history-v1";
const MAX_CONVERSATIONS = 20;

type StoredMessage = Omit<Message, "timestamp"> & { timestamp: string };
type StoredConversation = Omit<Conversation, "messages" | "createdAt"> & {
  messages: StoredMessage[];
  createdAt: string;
};

function revive(c: StoredConversation): Conversation {
  return {
    ...c,
    createdAt: new Date(c.createdAt),
    messages: (c.messages ?? []).map((m) => ({ ...m, timestamp: new Date(m.timestamp) })),
  };
}

export function loadLocalHistory(): Conversation[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as StoredConversation[];
    return Array.isArray(parsed) ? parsed.map(revive) : [];
  } catch {
    return []; // corrupted or unavailable (private mode) — start clean
  }
}

export function saveLocalHistory(conversations: Conversation[]): void {
  if (typeof window === "undefined") return;
  try {
    // Keep only conversations that actually contain something, newest first,
    // so the store cannot grow without bound from empty "New chat" shells.
    const trimmed = conversations
      .filter((c) => c.messages.length > 0)
      .slice(0, MAX_CONVERSATIONS);
    localStorage.setItem(KEY, JSON.stringify(trimmed));
  } catch {
    /* quota exceeded or storage disabled — history is a nicety, never fatal */
  }
}

export function clearLocalHistory(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
