"""Who someone is *in public* — a nickname, never an email.

Oyster has no user table (identity is the Supabase token), but the public
findings feed needs to show an author. Showing the email would republish the
exact personal data the project-privacy work just stopped leaking, so every
account instead gets:

  * a **member number**, assigned in account order (1, 2, 3 …), and
  * a default handle built from it — "User 7" —
  * which they can replace with a nickname of their own in Settings.

The number is stable and carries nothing identifying. Existing accounts are
backfilled once, ordered by their earliest activity (first conversation or
project), so the numbering matches the order people actually joined rather than
whoever happens to log in first after this ships.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from threading import Lock

import config
from services import db

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()

MAX_NAME = 32
# "User 7" is generated, so a custom nickname may not impersonate that shape.
_RESERVED = re.compile(r"^\s*user\s*\d+\s*$", re.IGNORECASE)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn() -> sqlite3.Connection:
    # Shared helper — the point is WAL (enabled once in main.py), which stops
    # readers and the writer from blocking each other on this shared file.
    # See services/db.py.
    # Resolve at call time so isolated tests and a runtime corpus snapshot can
    # switch the configured database without leaving this reader on a stale
    # import-time path.
    return db.connect(config.MEMORY_DB)


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id      TEXT PRIMARY KEY,
                member_no    INTEGER NOT NULL,
                display_name TEXT,
                created_at   TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_member
                ON user_profiles(member_no);
            """
        )
        # One-time backfill: number the accounts we already know about by when
        # they first did anything, so "User 1" really is the earliest member.
        empty = con.execute("SELECT COUNT(*) AS n FROM user_profiles").fetchone()["n"] == 0
        if empty:
            seen: dict[str, str] = {}

            def _collect(sql: str) -> None:
                try:
                    for row in con.execute(sql):
                        uid, first = row[0], row[1]
                        if not uid:
                            continue
                        if uid not in seen or (first and first < seen[uid]):
                            seen[uid] = first or ""
                except sqlite3.OperationalError:
                    pass  # table not created yet on a fresh install

            _collect("SELECT user_id, MIN(created_at) FROM conversations "
                     "WHERE user_id IS NOT NULL AND user_id != '' GROUP BY user_id")
            _collect("SELECT owner_id, MIN(created_at) FROM projects "
                     "WHERE owner_id IS NOT NULL AND owner_id != '' GROUP BY owner_id")

            now = _ts()
            for n, (uid, _first) in enumerate(sorted(seen.items(), key=lambda kv: kv[1]), start=1):
                con.execute(
                    "INSERT OR IGNORE INTO user_profiles (user_id, member_no, display_name, created_at) "
                    "VALUES (?,?,NULL,?)",
                    (uid, n, now),
                )
        con.commit()
        con.close()


def ensure(user_id: str) -> dict | None:
    """The caller's profile, creating it (with the next member number) on first
    sight. Returns None only for a missing id."""
    if not user_id:
        return None
    with _lock:
        con = _conn()
        row = con.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)).fetchone()
        if row is None:
            nxt = con.execute(
                "SELECT COALESCE(MAX(member_no), 0) + 1 AS n FROM user_profiles"
            ).fetchone()["n"]
            con.execute(
                "INSERT OR IGNORE INTO user_profiles (user_id, member_no, display_name, created_at) "
                "VALUES (?,?,NULL,?)",
                (user_id, nxt, _ts()),
            )
            con.commit()
            row = con.execute("SELECT * FROM user_profiles WHERE user_id = ?", (user_id,)).fetchone()
        con.close()
    return _row(row) if row else None


def _row(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["handle"] = (d.get("display_name") or "").strip() or f"User {d['member_no']}"
    return d


def handle(user_id: str) -> str:
    """Public label for an account. Never an email."""
    prof = ensure(user_id)
    return prof["handle"] if prof else "Unknown"


def handles_for(user_ids: list[str]) -> dict[str, str]:
    """Bulk lookup for the feed — one query instead of one per row. Accounts
    with no profile yet fall back to a number-less label rather than being
    created here (a read must not mint rows for other people)."""
    ids = [u for u in {u for u in user_ids if u}]
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    with _conn() as con:
        try:
            rows = con.execute(
                f"SELECT user_id, member_no, display_name FROM user_profiles WHERE user_id IN ({marks})",
                ids,
            ).fetchall()
        except sqlite3.OperationalError as exc:
            # A public read must remain useful during first boot or an
            # isolated migration where the optional profile table has not yet
            # been created. Never mint rows from a read; use the anonymous
            # fallback label until init_db runs.
            if "no such table: user_profiles" not in str(exc):
                raise
            rows = []
    out = {r["user_id"]: ((r["display_name"] or "").strip() or f"User {r['member_no']}") for r in rows}
    for u in ids:
        out.setdefault(u, "User")
    return out


class NameRejected(ValueError):
    """The nickname is empty-after-trim, too long, or impersonates a generated one."""


def set_display_name(user_id: str, name: str | None) -> dict | None:
    """Set (or clear, with None/empty) the caller's nickname."""
    prof = ensure(user_id)
    if prof is None:
        return None
    cleaned = (name or "").strip()
    if cleaned:
        if len(cleaned) > MAX_NAME:
            raise NameRejected(f"Keep it to {MAX_NAME} characters or fewer.")
        if _RESERVED.match(cleaned):
            raise NameRejected("Names like “User 7” are reserved — pick something else.")
        # Control characters would let a name break the layout it is rendered in.
        if any(ch < " " for ch in cleaned):
            raise NameRejected("That name contains characters that aren’t allowed.")
    with _lock:
        con = _conn()
        con.execute(
            "UPDATE user_profiles SET display_name = ? WHERE user_id = ?",
            (cleaned or None, user_id),
        )
        con.commit()
        con.close()
    return ensure(user_id)
