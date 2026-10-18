"""Each account's acceptance of the Oyster user agreement.

Distinct from ``training/consent.py``, which is the OPERATOR's project-level
switch. This module records the individual account holder's acceptance, and it
is the only thing that can put a public user's chat into a training dataset.

**This is a REQUIRED term of use, not an optional opt-in** (changed
2026-08-04). Oyster's free tier is offered on the condition that conversations
may be stored and used to improve its model; an account that has not accepted
the current agreement cannot use the chat at all (``routers/chat.py`` returns
403 ``terms_acceptance_required``). Read that honestly: because acceptance is
a condition of the service, it is contractual terms-of-use — it is NOT the
"freely given consent" of GDPR Art. 6(1)(a), and it should not be described as
consent in user-facing copy or in a privacy policy. See the note in
``AGREEMENT.md`` before changing the wording.

What stays true regardless:

* **Evidence, not just a boolean.** We store when they accepted and WHICH
  wording (``consent_version``). When the terms change materially, bump the
  version: previously-recorded acceptances stop counting and every account is
  asked again. You cannot retroactively widen what someone agreed to.
* **Withdrawable**, and withdrawal is immediate for every dataset built
  afterwards (``conversation_service.list_for_training`` joins this table
  live). Withdrawing also ends chat access, because acceptance is what grants
  it — the UI says so plainly before the user confirms. Models already trained
  cannot be untrained; the UI says that too.
* Anonymous visitors are absent by construction: they have no account to
  attach a decision to, their chats are never stored server-side, and they are
  never asked to accept anything.
* **Operators are exempt.** The admin allow-list is the data controller, not a
  user of someone else's service; their chats were always trainable via the
  project-level switch.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from threading import Lock

import config

# Bump ONLY when the user-facing agreement changes in a way that alters what is
# being agreed to. Rows recorded against an older version stop counting, which
# re-prompts every account on their next visit — that is the intended effect.
#
# v2 (2026-08-04): the training clause became a REQUIRED condition of use
# rather than an optional extra. A "yes" recorded against v1 answered a
# materially different (optional) question, so v1 acceptances do not carry
# over — every existing account is asked again.
CONSENT_VERSION = "2026-08-04.v2"

_DB_PATH = config.MEMORY_DB
_lock = Lock()

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS user_training_consent (
    user_id         TEXT PRIMARY KEY,
    email           TEXT,
    allowed         INTEGER NOT NULL DEFAULT 0,
    consent_version TEXT,
    updated_at      TEXT NOT NULL
)
"""


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock:
        con = _conn()
        con.execute(_TABLE_SQL)
        con.commit()
        con.close()


def get(user_id: str) -> dict:
    """Current decision for one account. No row → not consented."""
    with _conn() as con:
        con.execute(_TABLE_SQL)
        row = con.execute(
            "SELECT * FROM user_training_consent WHERE user_id = ?", (user_id,)
        ).fetchone()
    if row is None:
        return {"allowed": False, "consent_version": None, "updated_at": None,
                "current_version": CONSENT_VERSION}
    return {
        # A stored "yes" against superseded wording is NOT current consent.
        "allowed": bool(row["allowed"]) and row["consent_version"] == CONSENT_VERSION,
        "consent_version": row["consent_version"],
        "updated_at": row["updated_at"],
        "current_version": CONSENT_VERSION,
    }


def set_allowed(user_id: str, allowed: bool, email: str | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        con = _conn()
        con.execute(_TABLE_SQL)
        con.execute(
            """
            INSERT INTO user_training_consent (user_id, email, allowed, consent_version, updated_at)
            VALUES (?,?,?,?,?)
            ON CONFLICT(user_id) DO UPDATE SET
                email = excluded.email,
                allowed = excluded.allowed,
                consent_version = excluded.consent_version,
                updated_at = excluded.updated_at
            """,
            (user_id, email, 1 if allowed else 0,
             CONSENT_VERSION if allowed else None, now),
        )
        con.commit()
        con.close()
    return get(user_id)


def delete(user_id: str) -> int:
    """Erase this account's agreement record entirely (account deletion).

    Note what this does NOT do: it does not retroactively remove the user from
    datasets that were already built. It does remove them from every future
    one, because list_for_training joins this table live — so a deleted
    account stops being trainable the moment the row goes.
    """
    if not user_id:
        return 0
    with _lock:
        con = _conn()
        con.execute(_TABLE_SQL)
        cur = con.execute("DELETE FROM user_training_consent WHERE user_id = ?", (user_id,))
        con.commit()
        removed = cur.rowcount
        con.close()
    return removed


def has_accepted(user_id: str) -> bool:
    """Has this account accepted the CURRENT agreement?

    The gate the chat route asks. An account that accepted a superseded
    version answers False and is asked again — that is how a terms change
    reaches people who signed up before it.
    """
    if not user_id:
        return False
    return bool(get(user_id)["allowed"])
