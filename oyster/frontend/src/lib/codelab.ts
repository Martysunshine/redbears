// Browser-local storage for the Red Team Code Lab. Snippets never leave the
// browser (copy-only lab, no server execution) — this mirrors the localStorage
// pattern in lib/localHistory.ts. Promoting a snippet to a Finding is the only
// thing that touches the backend (see CodeLabPanel → createUserFinding).

export interface CodeSnippet {
  id: string;
  name: string;
  code: string;
  comment: string;
  createdAt: number;
  updatedAt: number;
}

const KEY = "oyster.codelab.snippets.v1";

export function loadSnippets(): CodeSnippet[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as CodeSnippet[]) : [];
  } catch {
    return [];
  }
}

export function saveSnippets(snippets: CodeSnippet[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(snippets));
  } catch {
    /* quota / disabled storage — non-fatal */
  }
}

export function newSnippet(): CodeSnippet {
  // Avoid Date.now collisions within a tick with a short random suffix.
  const id = `snip_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
  const ts = Date.now();
  return {
    id,
    name: "Untitled snippet",
    code: "# Python scratch — write, save, copy. Test it in your own terminal.\n",
    comment: "",
    createdAt: ts,
    updatedAt: ts,
  };
}
