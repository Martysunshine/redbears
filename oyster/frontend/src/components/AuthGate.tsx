"use client";

// Public-tier auth for Oyster.
//
// This used to be a hard wall ("Authorized operator access only") in front of
// the whole app. Oyster is now open: anonymous visitors land straight in the
// chat with a small daily allowance, any signed-up account gets unlimited
// chat, and the two operator accounts keep the full toolset. The backend
// enforces all of it (routers/chat.py + require_chat_access) — everything
// here is UX.
//
// Oyster has NO sign-in form of its own. The whole Red Orca ecosystem shares
// one account and one login page (Voiceiq/frontend/app/login), so openAuth()
// sends the browser there and it returns via a `next` param. In production
// Oyster is proxied onto the same origin and talks to the same Supabase
// project, so the session created on that page is already valid here on return.
//
// Since 2026-08-04 an account must also ACCEPT THE USER AGREEMENT before it may
// chat (see oyster/AGREEMENT.md). That is enforced server-side; because sign-up
// now happens on the shared login page (which knows nothing of Oyster's terms),
// the single door left in front of it is the blocking AgreementGate — it opens
// for any signed-in account that has not accepted the current version, whether
// brand-new or predating it.
//
// 2026-09-14 — identity, not object identity. auth-js re-emits SIGNED_IN with a
// NEW session object on every hidden→visible transition (and TOKEN_REFRESHED
// every ~55 minutes). This provider used to store each one, which re-ran the
// tier lookup and, downstream, the entire workspace boot: nine requests per
// tab switch on a phone, a blank chat when the reload replaced already-loaded
// messages, and the rate limiter tripping on the storm. Now the session is
// adopted only when the PERSON changes (user id), and `tier` stays null until
// the stored session has actually been read, so nothing paints an anonymous
// draft over a signed-in account while the check is in flight.
//
// Exports:
//   <AuthGate>   — context provider + agreement gate. Children ALWAYS render.
//   useAuth()    — see AuthContextValue.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase";
import { deleteAccount as deleteAccountApi, getMe, setTrainingConsent, type AgreementState } from "@/lib/api";
import { onUnauthorized, resetUnauthorized } from "@/lib/request";
import { clearLocalHistory } from "@/lib/localHistory";
import { loginUrl } from "@/lib/site";
import { AgreementGate } from "./AgreementGate";
import { SessionExpiredBanner } from "./SessionExpiredBanner";

const AUTH_ENABLED = process.env.NEXT_PUBLIC_OYSTER_DISABLE_AUTH !== "true";

export type Tier = "anon" | "user" | "admin";
export type AuthMode = "signin" | "signup";

interface AuthContextValue {
  session: Session | null;
  /** null while resolving; then the backend-confirmed tier. */
  tier: Tier | null;
  email: string | null;
  /** Backend-confirmed: may this account's chats be used for training? */
  trainingConsent: boolean;
  /** null for anonymous visitors and while resolving. */
  agreement: AgreementState | null;
  /** True once the stored session has been read. Before that, `tier` is null
   *  and nothing should assume "anonymous". */
  authReady: boolean;
  /** A request that carried this session's token was refused (401): the
   *  session expired or was revoked. Cleared when a fresh session arrives. */
  sessionExpired: boolean;
  dismissSessionExpired: () => void;
  /** Accept (true) or withdraw (false). Withdrawing also ends chat access. */
  setAgreementAccepted: (accepted: boolean) => Promise<void>;
  /** Re-read the agreement state from the backend (e.g. after a 403). */
  refreshAgreement: () => Promise<void>;
  /** Erase the account and everything in it. Irreversible; signs out. */
  deleteAccount: () => Promise<DeleteAccountOutcome>;
  openAuth: (mode: AuthMode) => void;
  signOut: () => void;
}

/** Deletion happens in two systems, so "did it work?" has three answers. */
export type DeleteAccountOutcome =
  | { ok: true }
  /** Oyster data is genuinely gone; only the empty Supabase login remains. */
  | { ok: true; loginRemains: true }
  | { ok: false; error: string };

const AuthContext = createContext<AuthContextValue>({
  session: null,
  tier: null,
  email: null,
  trainingConsent: false,
  agreement: null,
  authReady: false,
  sessionExpired: false,
  dismissSessionExpired: () => {},
  setAgreementAccepted: async () => {},
  refreshAgreement: async () => {},
  deleteAccount: async () => ({ ok: false, error: "not ready" }),
  openAuth: () => {},
  signOut: () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  // Resolved immediately when auth is off or unconfigured: there is no stored
  // session to wait for in either case.
  const [sessionResolved, setSessionResolved] = useState<boolean>(!AUTH_ENABLED || !supabase);
  const [tier, setTier] = useState<Tier | null>(AUTH_ENABLED ? null : "admin");
  const [email, setEmail] = useState<string | null>(null);
  const [trainingConsent, setTrainingConsent_] = useState(false);
  const [agreement, setAgreement] = useState<AgreementState | null>(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  // The user id of the session currently in state — the ONLY thing that
  // decides whether a new session object is news.
  const identityRef = useRef<string | null>(null);

  useEffect(() => {
    if (!AUTH_ENABLED) {
      // Deliberate local-dev bypass: everything behaves as operator, matching
      // the backend's OYSTER_DISABLE_AUTH bypass.
      setTier("admin");
      return;
    }
    if (!supabase) {
      // Auth is ON but the Supabase client is missing (misconfigured build):
      // degrade to anonymous — never show the operator UI on a config error.
      setTier("anon");
      return;
    }

    const adopt = (s: Session | null) => {
      const id = s?.user?.id ?? null;
      if (id === identityRef.current) return; // same person — nothing to re-resolve
      identityRef.current = id;
      setSession(s);
      if (id) {
        setSessionExpired(false);
        resetUnauthorized();
      }
    };

    supabase.auth
      .getSession()
      .then(({ data }) => {
        adopt(data.session);
        setSessionResolved(true);
      })
      .catch(() => setSessionResolved(true));

    const { data: sub } = supabase.auth.onAuthStateChange((event, s) => {
      switch (event) {
        case "INITIAL_SESSION":
          adopt(s);
          setSessionResolved(true);
          break;
        case "SIGNED_IN":
          adopt(s);
          break;
        case "SIGNED_OUT":
          adopt(null);
          break;
        case "USER_UPDATED":
          // Same account, possibly a new email. Not a new session.
          setEmail(s?.user?.email ?? null);
          break;
        default:
          // TOKEN_REFRESHED and friends: same person, new token. authFetch
          // reads the current token from the client on every request, so
          // there is nothing to store — and storing it is exactly what used
          // to reboot the app.
          break;
      }
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  // The request layer raises this once per session when a token was refused.
  useEffect(() => {
    onUnauthorized(() => setSessionExpired(true));
    return () => onUnauthorized(null);
  }, []);

  // Resolve the tier from the backend whenever the PERSON changes. The
  // backend is the authority (admin vs user is its allow-list, not ours).
  // Gated on sessionResolved so a signed-in account never flashes as anon
  // while the stored session is still being read.
  useEffect(() => {
    if (!AUTH_ENABLED || !supabase) return;
    if (!sessionResolved) return;
    let cancelled = false;
    if (!session) {
      setTier("anon");
      setEmail(null);
      setTrainingConsent_(false);
      setAgreement(null);
      return;
    }
    setTier(null);
    getMe()
      .then((me) => {
        if (cancelled) return;
        setTier(me.tier === "admin" ? "admin" : "user");
        setEmail(me.email ?? session.user?.email ?? null);
        // Backend is the source of truth for the agreement — never assume.
        setTrainingConsent_(!!me.training_consent);
        setAgreement(me.agreement ?? null);
      })
      .catch(() => {
        // Backend unreachable or token hiccup. Treat as a plain user, but do
        // NOT synthesise an agreement state: showing the blocking gate on a
        // network blip would wall people out of an app that is merely
        // offline, and hiding it costs nothing because /chat enforces the
        // real answer per request (403 → the gate opens then).
        if (!cancelled) {
          setTier("user");
          setEmail(session.user?.email ?? null);
          setTrainingConsent_(false); // fail closed: never claim an agreement we can't confirm
          setAgreement(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [session, sessionResolved]);

  // No in-app form: hand off to the shared Red Orca login page. A full browser
  // navigation (not next/router) is deliberate — that page is a different zone,
  // and window.location is not basePath-prefixed, so "/login" resolves at the
  // site root rather than "/oyster/login".
  const openAuth = useCallback((mode: AuthMode) => {
    if (typeof window !== "undefined") window.location.assign(loginUrl(mode));
  }, []);
  const signOut = useCallback(() => {
    supabase?.auth.signOut();
  }, []);
  const dismissSessionExpired = useCallback(() => setSessionExpired(false), []);

  const refreshAgreement = useCallback(async () => {
    try {
      const me = await getMe();
      setTrainingConsent_(!!me.training_consent);
      setAgreement(me.agreement ?? null);
    } catch {
      /* leave state as-is; /chat stays the enforcer */
    }
  }, []);

  const setAgreementAccepted = useCallback(
    async (accepted: boolean) => {
      // No optimistic update here (unlike the old optional toggle): this
      // decides whether the app is usable at all, so the UI must reflect what
      // the server actually stored, not what we hoped it would.
      const res = await setTrainingConsent(accepted);
      setTrainingConsent_(!!res.allowed);
      if (res.agreement) setAgreement(res.agreement);
      else await refreshAgreement();
    },
    [refreshAgreement]
  );

  // Account deletion runs across two systems, in this order for a reason:
  //   1. our backend erases the data  — needs a valid token, so it must go
  //      first, while the account still exists;
  //   2. Supabase erases the login    — via its own security-definer function,
  //      so the service_role key never has to live on our server;
  //   3. clear this browser and sign out.
  // If (2) fails, (1) already succeeded: the data really is gone and only an
  // empty login remains. That gets its own outcome rather than being reported
  // as a failure, because telling someone their deletion failed when their
  // data is already destroyed would be the worst possible lie here.
  const deleteAccount = useCallback(async (): Promise<DeleteAccountOutcome> => {
    try {
      await deleteAccountApi();
    } catch (e) {
      return { ok: false, error: e instanceof Error ? e.message : "Could not delete your data." };
    }

    let loginRemains = false;
    try {
      const { error } = (await supabase?.rpc("delete_own_account")) ?? { error: null };
      if (error) loginRemains = true;
    } catch {
      loginRemains = true;
    }

    try {
      clearLocalHistory();
    } catch {
      /* private mode — nothing cached to clear */
    }

    if (loginRemains) {
      // Do NOT sign out yet. Signing out flips the session, which re-renders
      // the tree and tore down the panel carrying this message before anyone
      // could read it — so the app silently claimed a clean deletion while the
      // login still existed. The caller signs out when the user dismisses it.
      return { ok: true, loginRemains: true };
    }
    await supabase?.auth.signOut();
    return { ok: true };
  }, []);

  // Existing accounts (and anyone who accepted a superseded version) meet the
  // gate here. Operators are exempt — the backend sets required:false for them.
  const mustAccept =
    tier === "user" && agreement !== null && agreement.required && !agreement.accepted;

  return (
    <AuthContext.Provider
      value={{
        session,
        tier,
        email,
        trainingConsent,
        agreement,
        authReady: sessionResolved,
        sessionExpired,
        dismissSessionExpired,
        setAgreementAccepted,
        refreshAgreement,
        deleteAccount,
        openAuth,
        signOut,
      }}
    >
      {children}
      {sessionExpired && (
        <SessionExpiredBanner onSignIn={() => openAuth("signin")} onDismiss={dismissSessionExpired} />
      )}
      {mustAccept && <AgreementGate />}
    </AuthContext.Provider>
  );
}
