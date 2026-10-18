import { createClient, type SupabaseClient } from "@supabase/supabase-js";

// The Supabase browser client — same project as the Dolphin/VoiceIQ frontend.
// URL + anon key are PUBLIC BY DESIGN (the anon key only grants what Supabase
// Auth rules allow); the backend independently verifies every token via JWKS
// and checks the email against its own admin allow-list. The service_role key
// is used NOWHERE in this codebase and must never be.
//
// Null when the env vars are absent — local dev with NEXT_PUBLIC_OYSTER_DISABLE_AUTH
// unset runs entirely without Supabase. Every caller must guard for null.
const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

// flowType "pkce": the raw access/refresh tokens never appear in the address
// bar or browser history — the more secure browser flow, Supabase's own
// recommendation (matches Voiceiq/frontend/lib/supabase.ts).
export const supabase: SupabaseClient | null =
  url && anonKey
    ? createClient(url, anonKey, {
        auth: {
          flowType: "pkce",
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
        },
      })
    : null;
