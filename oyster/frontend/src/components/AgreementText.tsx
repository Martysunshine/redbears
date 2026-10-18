"use client";

// The user agreement, rendered in one place and shown in three:
//   • the sign-up modal (must be accepted to create an account)
//   • the blocking gate (existing accounts, after a version bump)
//   • Settings (read it again any time, see what you accepted and when)
//
// Keep this in sync with oyster/AGREEMENT.md and CONSENT_VERSION in
// backend/services/training/user_consent.py. All three must move together,
// and the version must be BUMPED whenever the meaning changes — that is what
// re-asks every existing account.

import { PRIVACY_URL, TERMS_URL } from "@/lib/site";

/** Mirrors CONSENT_VERSION in the backend. Display only — the backend decides. */
export const AGREEMENT_VERSION = "2026-08-04.v2";

/** One-line summary beside the sign-up checkbox. */
export function AgreementCheckboxLabel() {
  return (
    <span className="text-[11px] leading-relaxed text-oyster-muted">
      I agree to the{" "}
      <a
        href={TERMS_URL}
        target="_blank"
        rel="noopener noreferrer"
        className="text-oyster-accent underline underline-offset-2 hover:text-oyster-accent-hover"
      >
        Terms
      </a>{" "}
      and{" "}
      <a
        href={PRIVACY_URL}
        target="_blank"
        rel="noopener noreferrer"
        className="text-oyster-accent underline underline-offset-2 hover:text-oyster-accent-hover"
      >
        Privacy Policy
      </a>
      , including that{" "}
      <span className="text-oyster-text">
        my conversations are stored and used to improve Oyster&apos;s AI
      </span>
      . Required to create an account.
    </span>
  );
}

function Section({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-1 text-[12px] font-semibold text-oyster-text">
        {n}. {title}
      </h3>
      <div className="space-y-1.5 text-[11px] leading-relaxed text-oyster-muted">{children}</div>
    </section>
  );
}

/** The full agreement. Scrolls inside whatever box contains it. */
export function AgreementText() {
  return (
    <div className="space-y-3.5">
      <Section n={1} title="What Oyster is">
        <p>
          Oyster is a security-focused AI assistant by Red Orca. It is free, provided
          as-is, with no uptime or accuracy guarantee. Its answers can be wrong. You
          are responsible for what you do with them, and for only testing systems you
          are authorised to test.
        </p>
      </Section>

      <Section n={2} title="Your conversations are stored">
        <p>
          While you are signed in, your conversations are saved to your account so you
          can come back to them. They are visible only to you.
        </p>
      </Section>

      <Section n={3} title="Your conversations are used to improve Oyster's AI">
        <p>
          <span className="text-oyster-text">
            This is a condition of using the free tier, not an optional extra.
          </span>{" "}
          By creating an account you agree that Red Orca may use your conversations to
          evaluate and train Oyster&apos;s models.
        </p>
        <p>
          Before any conversation is used this way it is automatically scanned, and
          anything that looks like a credential, key, or other secret causes the whole
          exchange to be dropped rather than redacted.{" "}
          <span className="text-oyster-text">
            Do not paste real secrets, personal data about other people, or
            client-confidential material into Oyster
          </span>{" "}
          — no automated scan catches everything.
        </p>
        <p>If you are not comfortable with this, do not create an account — see §5.</p>
      </Section>

      <Section n={4} title="Withdrawing">
        <p>You can withdraw at any time from Settings. Two things happen, both immediately:</p>
        <ul className="ml-4 list-disc space-y-1">
          <li>Your conversations are excluded from every dataset built afterwards.</li>
          <li>
            <span className="text-oyster-text">Your chat access ends</span>, because
            acceptance is what grants it. Accept again at any time to restore it.
          </li>
        </ul>
        <p>
          A model that has already been trained cannot be untrained. Withdrawing removes
          you from future training, not from a model that already exists.
        </p>
      </Section>

      <Section n={5} title="Using Oyster without an account">
        <p>
          Anonymous visitors get a small daily allowance. Anonymous conversations are{" "}
          <span className="text-oyster-text">not stored on our servers</span> and are{" "}
          <span className="text-oyster-text">never used for training</span> — they stay
          in your own browser. No agreement is required, and none is recorded.
        </p>
      </Section>

      <Section n={6} title="Deleting your data">
        <p>
          Delete individual conversations from the sidebar at any time. To delete your
          account and everything in it, email{" "}
          <a
            href="mailto:techredorca@gmail.com"
            className="text-oyster-accent underline underline-offset-2 hover:text-oyster-accent-hover"
          >
            techredorca@gmail.com
          </a>
          .
        </p>
      </Section>

      <Section n={7} title="Changes">
        <p>
          If this agreement changes materially, you will be asked to accept the new
          version before you can continue using the chat.
        </p>
      </Section>
    </div>
  );
}
