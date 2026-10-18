"""Persistent per-IP daily allowance for anonymous public chat.

One tiny SQLite table in the existing memory DB (config.MEMORY_DB) so the
allowance survives container restarts — an in-memory counter would hand every
anonymous visitor a fresh allowance on each redeploy. Traffic on this path is
at most a handful of writes per visitor per DAY, so a connection per call is
fine and keeps this dependency-free.

``consume()`` is atomic (single UPSERT incrementing the counter and returning
the new value), so two racing requests cannot both pass a separate
check-then-increment. Days are UTC.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import config
from services import db

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS anon_chat_quota (
    ip    TEXT NOT NULL,
    day   TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, day)
)
"""


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def seconds_until_utc_midnight() -> int:
    now = datetime.now(timezone.utc)
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((tomorrow - now).total_seconds()))


def used_today(ip: str) -> int:
    with db.connect() as conn:
        conn.execute(_TABLE_SQL)
        row = conn.execute(
            "SELECT count FROM anon_chat_quota WHERE ip = ? AND day = ?",
            (ip, _today()),
        ).fetchone()
        return int(row[0]) if row else 0


def consume(ip: str) -> int:
    """Atomically count one message against today's allowance; returns the
    new total for this ip+day (callers compare against the limit)."""
    # Every anonymous message writes here, so it is one of the hottest write
    # paths in the app — it benefits most from WAL not blocking concurrent reads.
    with db.connect() as conn:
        conn.execute(_TABLE_SQL)
        row = conn.execute(
            """
            INSERT INTO anon_chat_quota (ip, day, count) VALUES (?, ?, 1)
            ON CONFLICT(ip, day) DO UPDATE SET count = count + 1
            RETURNING count
            """,
            (ip, _today()),
        ).fetchone()
        return int(row[0])
