# Oyster user agreement

**Current version: `2026-08-04.v2`** — must match `CONSENT_VERSION` in
`backend/services/training/user_consent.py` and the copy rendered by
`frontend/src/components/AgreementText.tsx`.

This file is the single source of truth for the wording. Change it, change
both of those, and **bump the version** — bumping invalidates every stored
acceptance, so all existing accounts are asked again on their next visit.
That is deliberate: an acceptance of old wording is not an acceptance of new
wording.

---

## The agreement (as shown to users)

### 1. What Oyster is

Oyster is a security-focused AI assistant by Red Orca. It is offered free of
charge, as-is, with no uptime or accuracy guarantee. Its answers can be wrong.
You are responsible for what you do with them, and for only testing systems you
are authorised to test.

### 2. Your conversations are stored

When you are signed in, your conversations are saved to your account so you can
come back to them. They are visible only to you.

### 3. Your conversations are used to improve Oyster's AI

**This is a condition of using the free tier, not an optional extra.** By
creating an account you agree that Red Orca may use your conversations to
evaluate and train Oyster's models.

Before any conversation is used this way it is automatically scanned, and
anything that looks like a credential, key, or other secret causes the whole
exchange to be dropped rather than redacted. Do not paste real secrets,
personal data about other people, or client-confidential material into Oyster —
no automated scan catches everything.

If you are not comfortable with this, do not create an account. You can still
use Oyster anonymously (see §5).

### 4. Withdrawing

You can withdraw at any time from Settings. Two things happen, and both are
immediate:

- Your conversations are excluded from every dataset built afterwards.
- **Your chat access ends**, because acceptance is what grants it. You can
  accept again at any time to restore access.

A model that has already been trained cannot be untrained. Withdrawing removes
you from future training, not from a model that already exists.

### 5. Using Oyster without an account

Anonymous visitors get a small daily allowance. Anonymous conversations are
**not** stored on our servers and are **never** used for training — they stay
in your own browser. No agreement is required, and none is recorded.

### 6. Deleting your data

Delete individual conversations from the sidebar at any time.

To delete everything, open **Settings → Delete my account**. This immediately
and permanently removes your account, every conversation and message, every
file you uploaded, and your agreement record — which also removes you from all
future training. It cannot be undone, and a model that has already been trained
cannot be untrained.

If anything goes wrong with that, email techredorca@gmail.com and we will
finish it by hand.

### 7. Changes

If this agreement changes materially, you will be asked to accept the new
version before you can continue using the chat.

---

## Operator note — NOT shown to users

**Do not call this "consent" in a privacy policy.** Because acceptance is a
condition of receiving the service, it is not "freely given" under GDPR
Art. 7(4), so it does not qualify as consent under Art. 6(1)(a). It is
contractual terms of use. If a lawful basis must be stated for the training
use, the honest candidates are contract (Art. 6(1)(b)) or legitimate interests
(Art. 6(1)(f), which requires a balancing test and an opt-out right that this
design does not currently give).

The database column is still named `allowed` and the module is still
`user_consent.py` for data continuity — the naming predates this change and is
not a claim about the legal basis.

**Done (2026-08-04):** the published documents now match this agreement.

* `Voiceiq/frontend/app/privacy/page.tsx` §6 "Oyster: Your Conversations &
  AI Training" describes the training use in full, names **contract
  (Art. 6(1)(b))** as the basis rather than consent, and explains the
  version/re-acceptance mechanism. §7 states explicitly that Dolphin call data
  is *not* used for training, so the two products cannot be confused.
* `Voiceiq/frontend/app/terms/page.tsx` §5 is the Oyster section (free/as-is,
  authorised-testing-only, the training condition, withdrawal, no-secrets, fair
  use). §8 was corrected: the old licence grant said Red Orca could process
  your data "solely to provide the Service", which contradicted training —
  it now carves out Oyster conversations explicitly and only those.
* Oyster's Settings links to `/privacy#oyster`, not the top of the policy.

**Still outstanding:**

1. This wording has not been reviewed by a lawyer. It is written to be honest
   and internally consistent, which is not the same as being advised.
2. No account-deletion self-service (§6 routes to email). GDPR erasure requests
   are therefore manual — someone has to actually action them within 30 days,
   which the policy promises.
3. No cookie banner. The site sets essential cookies only (which need no
   consent), but the policy mentions optional analytics cookies — if analytics
   are ever switched on, a banner becomes mandatory first.
4. Governing law is England and Wales (Terms §12) while the data lives in
   Germany and the controller is not stated as a registered entity. Worth a
   lawyer's eye when Red Orca incorporates.
