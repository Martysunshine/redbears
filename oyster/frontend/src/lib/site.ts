// Links back to the main Red Orca site.
//
// In production Oyster is proxied onto redorca.tech at /oyster, so it shares
// an ORIGIN with the main site and a root-relative "/dashboard" already
// resolves correctly. Locally the same is true (the zone is proxied through
// :3000). The env var only matters if the app is opened at its raw Vercel zone
// URL, where the main site is a different host.
//
// Note these are deliberately plain hrefs, never next/link: <Link> prefixes
// basePath, which would turn "/dashboard" into "/oyster/dashboard" and 404.
const SITE_URL = (process.env.NEXT_PUBLIC_REDORCA_SITE_URL || "").replace(/\/$/, "");

export function siteUrl(path: string): string {
  return `${SITE_URL}${path}`;
}

// The one Red Orca hub: profile, all three tools (Oyster/Dolphin/Shark), and
// account settings. This absorbed the old /account route, which now 308s here.
export const DASHBOARD_URL = siteUrl("/dashboard");
// Deep-links to the Oyster section: someone opening "Privacy" from inside
// Oyster wants the part about their chats, not the call-recording clauses.
export const PRIVACY_URL = siteUrl("/privacy#oyster");
export const TERMS_URL = siteUrl("/terms");

// The canonical sign-in / sign-up form lives on the main Red Orca site — Oyster
// has none of its own. The whole ecosystem shares ONE account and ONE login
// page, so we send the browser there and pass a `next` that brings them straight
// back to wherever they were in Oyster once the session exists (same origin +
// same Supabase project in production, so that session is already valid here).
export function loginUrl(mode: "signin" | "signup"): string {
  // window.location.pathname is the REAL shared-origin path ("/oyster…"), not
  // the basePath-stripped one — exactly what the main site needs to send the
  // browser back here. SSR-safe fallback to the Oyster root.
  const back =
    typeof window !== "undefined"
      ? window.location.pathname + window.location.search
      : "/oyster";
  const params = new URLSearchParams();
  if (mode === "signup") params.set("mode", "register");
  params.set("next", back);
  return siteUrl(`/login?${params.toString()}`);
}
