"""Deterministic, synthetic fixtures for the Red Bears IDOR demo lab.

Single source of truth for both modes (vulnerable / patched) and the tests, so
the only behavioural difference between modes is the ownership check in app.py —
never the data. Nothing here is real or sensitive:

* Two demo identities, ``alice`` and ``bob``.
* Two records, ``101`` owned by alice and ``202`` owned by bob, each a tiny
  synthetic object. No personal data, credentials, or anything to protect.
* Two demo-only bearer tokens, one per persona. These authenticate a request to
  a persona; they are NOT secrets. Real values (if set via env) stay out of git
  and logs; the fallbacks below are obvious throwaways so the lab runs with no
  configuration at all.

The agent/model never sees a token: the gateway (Emre's track) maps an
allowlisted persona to the matching demo token. The app only ever resolves an
incoming token back to a persona.
"""

from __future__ import annotations

import os

# Valid personas. An authenticated request is always one of these two.
PERSONAS: tuple[str, ...] = ("alice", "bob")

# The seeded records. `label` is a benign human-readable string — no secrets,
# no realistic customer data. Identical in both modes.
RECORDS: dict[int, dict] = {
    101: {"id": 101, "owner": "alice", "label": "Alice's demo record"},
    202: {"id": 202, "owner": "bob", "label": "Bob's demo record"},
}

# Demo-only, non-secret dev fallbacks so the lab runs with zero configuration.
# Override per persona via env for a shared/handoff setup; the real values never
# belong in git, chat or logs (see lab/.env.example).
_DEV_FALLBACK_TOKENS: dict[str, str] = {
    "alice": "dev-alice-token",
    "bob": "dev-bob-token",
}

_ENV_VAR: dict[str, str] = {
    "alice": "ALICE_TEST_TOKEN",
    "bob": "BOB_TEST_TOKEN",
}


def demo_token(persona: str) -> str:
    """The bearer token a client sends to act as ``persona`` (env or fallback)."""
    if persona not in PERSONAS:
        raise KeyError(f"unknown persona {persona!r}")
    return os.environ.get(_ENV_VAR[persona]) or _DEV_FALLBACK_TOKENS[persona]


def persona_for_token(token: str | None) -> str | None:
    """Resolve a bearer token back to a persona, or None if it matches neither.

    Rebuilt per call so an env change (e.g. in a test) takes effect immediately,
    and so a persona whose token is unset/empty can never be matched by an empty
    incoming token.
    """
    if not token:
        return None
    for persona in PERSONAS:
        if token == demo_token(persona):
            return persona
    return None
