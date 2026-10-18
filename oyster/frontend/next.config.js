// Mirrors the CSP approach in Voiceiq/frontend/next.config.js: derive the
// allow-listed origins from the same env vars the app actually calls, so the
// policy can't silently drift from the code. Production only — `next dev`
// needs ws:/eval that a strict policy would block.
function originOf(u) {
  try { return new URL(u).origin; } catch { return ""; }
}
const toWs = (origin) => (origin ? origin.replace(/^http/, "ws") : "");
const SUPABASE_ORIGIN = originOf(process.env.NEXT_PUBLIC_SUPABASE_URL || "");
// The CSP MUST allow-list the exact origin the client calls, or the browser
// blocks every backend fetch ("Can't reach Oyster" — reproduced 2026-10-06 with
// `connect-src` missing the API origin). The client (src/lib/api.ts) falls back
// to http://127.0.0.1:8001 when NEXT_PUBLIC_API_URL is unset, so the CSP uses
// the SAME fallback here — otherwise a build/start without that env var ships a
// policy that refuses the very backend the app talks to. Both loopback
// hostnames are included because the page can be opened on either.
const API_ORIGIN = originOf(process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8001");
const connectSrc = [
  "'self'",
  "https://*.supabase.co", "wss://*.supabase.co",
  SUPABASE_ORIGIN, toWs(SUPABASE_ORIGIN),
  API_ORIGIN, toWs(API_ORIGIN),
  "http://127.0.0.1:8001", "ws://127.0.0.1:8001",
  "http://localhost:8001", "ws://localhost:8001",
].filter(Boolean).join(" ");
const csp = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "img-src 'self' data: blob:",
  "font-src 'self' data: https://fonts.gstatic.com",
  `connect-src ${connectSrc}`,
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
].join("; ");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // No "X-Powered-By: Next.js" — a framework fingerprint on every response.
  poweredByHeader: false,
  // Empty locally so `npm run dev` stays at localhost:3001 exactly as before.
  // Production sets OYSTER_BASE_PATH=/oyster (Vercel project env var) so this
  // zone serves everything under redorca.tech/oyster — see docs/runbooks/OYSTER_DEPLOY.md.
  basePath: process.env.OYSTER_BASE_PATH || "",
  // Mirror the basePath into the client bundle: raw <img>/fetch URLs are not
  // basePath-prefixed by Next (only next/image and <Link> are), so components
  // that build such URLs need the value at runtime — see OysterMascot.
  env: {
    NEXT_PUBLIC_BASE_PATH: process.env.OYSTER_BASE_PATH || "",
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          ...(process.env.NODE_ENV === "production"
            ? [{ key: "Content-Security-Policy", value: csp }]
            : []),
        ],
      },
    ];
  },
};

module.exports = nextConfig;
