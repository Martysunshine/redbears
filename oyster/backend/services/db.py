"""One way to open the SQLite database, with the settings that make it survive
more than one person at a time.

Every subsystem in Oyster — conversations, findings, projects, profiles, memory,
quotas, knowledge — shares a single file (``config.MEMORY_DB``), and each module
opened it with ``sqlite3.connect`` and the library defaults.

**The fix that matters is WAL.** The journal mode defaults to ``DELETE`` (a
rollback journal), where a writer takes an exclusive lock over the whole file:
readers block the writer and the writer blocks readers. Every feed load, every
sidebar refresh and every chat-history read therefore contends with every save.
In WAL mode readers do not block the writer and the writer does not block
readers — reading the findings feed while someone else saves a finding simply
stops being a conflict. WAL is a property of the *database file*, not of a
connection, so it is set once at startup (``apply_startup_pragmas``) and
persists.

``synchronous=NORMAL`` is the standard companion to WAL: still crash-safe for
the process, far fewer fsyncs, and only the last transactions are at risk if the
whole machine loses power — the right trade for this data, and a real saving on
a busy 2-vCPU box.

**A note on ``busy_timeout``, because it is easy to get wrong:** Python's DB-API
already passes ``timeout=5.0`` on ``connect()``, which maps to a 5000 ms
``busy_timeout``. So this was *never* the "database is locked" culprit some
write-ups assume — the previous code was already waiting, not failing instantly.
It is set explicitly here anyway so the value is visible and cannot be lost if a
caller ever passes its own ``timeout`` or the driver changes.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import config

# How long a connection waits for a lock before giving up. Long enough to ride
# out any write this app makes (they are all small), short enough that a genuine
# deadlock still surfaces instead of hanging a request forever.
BUSY_TIMEOUT_MS = 5000


def connect(path: str | Path | None = None) -> sqlite3.Connection:
    """A connection to the shared database, configured for concurrent use.

    Callers keep their existing pattern of one connection per operation — that
    is fine and avoids cross-thread sharing; what was missing was the settings.
    """
    con = sqlite3.connect(str(path or config.MEMORY_DB), check_same_thread=False)
    con.row_factory = sqlite3.Row
    # Wait for a lock instead of raising "database is locked" at everyone.
    con.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    # Safe with WAL: still crash-safe, far fewer fsyncs.
    con.execute("PRAGMA synchronous = NORMAL")
    return con


# ---------------------------------------------------------------------------
# One-time migrations
#
# Every ``init_db`` in this codebase is idempotent DDL — CREATE IF NOT EXISTS,
# ALTER guarded by PRAGMA table_info — and that is the right shape for schema.
# It is the WRONG shape for a data rewrite: an UPDATE that re-files rows is
# "idempotent" only against the state it expects, and re-running it on every
# boot means it also re-files rows the user has since moved on purpose.
# conversation_service learned this the hard way (see its init_db): the
# home-workspace migration ran at every start and quietly pulled a signed-in
# account's conversations back to ``u_<sub>`` after they had created or
# activated another project — history that "disappeared" from the sidebar.
#
# ``run_once`` is the small thing that makes a data migration a migration:
# a named row in ``schema_migrations`` records that it has been applied, in
# the same transaction as the change itself, so it can never half-apply or
# apply twice. Rolling back to an image that predates the marker is harmless —
# the old code ignores the table and runs its UPDATE as before.
# ---------------------------------------------------------------------------

_MIGRATIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "  name       TEXT PRIMARY KEY,"
    "  applied_at TEXT NOT NULL"
    ")"
)


def ensure_migrations_table(con: sqlite3.Connection) -> None:
    con.execute(_MIGRATIONS_DDL)


def migration_applied(con: sqlite3.Connection, name: str) -> bool:
    ensure_migrations_table(con)
    row = con.execute(
        "SELECT 1 FROM schema_migrations WHERE name = ?", (name,)
    ).fetchone()
    return row is not None


def mark_migration(con: sqlite3.Connection, name: str) -> None:
    """Record ``name`` as applied. Does not commit — the caller's transaction
    owns that, so the marker lands together with the change it describes."""
    from datetime import datetime, timezone

    ensure_migrations_table(con)
    con.execute(
        "INSERT OR IGNORE INTO schema_migrations (name, applied_at) VALUES (?, ?)",
        (name, datetime.now(timezone.utc).isoformat()),
    )


def run_once(con: sqlite3.Connection, name: str, apply) -> bool:
    """Run ``apply(con)`` if the migration ``name`` has not been recorded, then
    record it. Returns True when it ran this time. No commit here either: the
    caller commits, so a failure inside ``apply`` leaves neither the change
    nor the marker behind."""
    if migration_applied(con, name):
        return False
    apply(con)
    mark_migration(con, name)
    return True


def apply_startup_pragmas() -> str:
    """Put the database file into WAL mode. Called once from main.py.

    Returns the journal mode actually in force, so a failure to switch is
    visible in the boot log rather than silently leaving the old behaviour.
    WAL persists in the file, so this is idempotent and cheap on later boots.
    """
    con = sqlite3.connect(str(config.MEMORY_DB), check_same_thread=False)
    try:
        con.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        mode = con.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        con.execute("PRAGMA synchronous = NORMAL")
        con.commit()
        return str(mode)
    finally:
        con.close()
