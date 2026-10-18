"""Conversation persistence — chat history that survives refresh.

Conversations belong to a project (the aggregate root from Slice 1) and are
stored in the same SQLite database as memory/projects. Each conversation owns an
ordered list of messages. This is what backs the sidebar history: create, list,
rename, delete, and message append are all durable here — no in-memory-only or
localStorage tricks.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from threading import Lock

import config
from services import db

_DB_PATH = config.MEMORY_DB
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
_lock = Lock()


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id() -> str:
    return str(uuid.uuid4())[:12]


def _conn() -> sqlite3.Connection:
    # Shared helper — the point is WAL (enabled once in main.py), which stops
    # readers and the writer from blocking each other on this shared file.
    # See services/db.py.
    return db.connect(_DB_PATH)


def init_db() -> None:
    with _lock:
        con = _conn()
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id          TEXT PRIMARY KEY,
                project_id  TEXT NOT NULL,
                user_id     TEXT,
                mode        TEXT NOT NULL DEFAULT 'basic',
                title       TEXT NOT NULL DEFAULT 'New Chat',
                pinned      INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_messages (
                id                TEXT PRIMARY KEY,
                conversation_id   TEXT NOT NULL,
                role              TEXT NOT NULL,
                content           TEXT NOT NULL,
                citations         TEXT NOT NULL DEFAULT '[]',
                documents_queried INTEGER,
                ord               INTEGER NOT NULL DEFAULT 0,
                created_at        TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS message_feedback (
                id              TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                message_id      TEXT NOT NULL,
                user_id         TEXT NOT NULL DEFAULT '',
                rating          TEXT NOT NULL,
                correction      TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL,
                UNIQUE(message_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_conv_project ON conversations(project_id, mode);
            CREATE INDEX IF NOT EXISTS idx_msg_conv ON conversation_messages(conversation_id, ord);
            CREATE INDEX IF NOT EXISTS idx_feedback_conv ON message_feedback(conversation_id);
            """
        )
        # Migration: add pinned column to pre-existing conversations tables.
        cols = con.execute("PRAGMA table_info(conversations)").fetchall()
        if not any(c["name"] == "pinned" for c in cols):
            con.execute("ALTER TABLE conversations ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
        # Migration: per-user ownership. Rows created before Oyster had
        # accounts keep user_id NULL — those are the operators' own history and
        # stay visible ONLY to admins (see list_by/can_access below). Every new
        # conversation is stamped with the Supabase subject id of its owner.
        if not any(c["name"] == "user_id" for c in cols):
            con.execute("ALTER TABLE conversations ADD COLUMN user_id TEXT")
        # owner_tier records WHO the conversation belongs to ('admin' | 'user';
        # NULL = pre-accounts operator history). It exists so the privacy rule
        # "public users' chats are never mined" is enforceable in SQL rather
        # than remembered by each caller — see list_for_training().
        if not any(c["name"] == "owner_tier" for c in cols):
            con.execute("ALTER TABLE conversations ADD COLUMN owner_tier TEXT")
        con.execute("CREATE INDEX IF NOT EXISTS idx_conv_user ON conversations(user_id, updated_at)")
        # Migration: file each account's history under its own workspace —
        # ONCE. See _migrate_home_workspace for what it does and why. It used
        # to run unconditionally on every boot, which was a bug, not
        # idempotence: a conversation belongs to the project it was created
        # in, and GET /conversations lists the caller's CURRENT workspace
        # (services/project_context.py). Re-running the rewrite at each start
        # pulled every conversation a user had created inside another project
        # back to ``u_<sub>`` — so after they created or activated a project,
        # their history "vanished" from that project's sidebar, and reappeared
        # in the home workspace after the next deploy. The marker in
        # schema_migrations makes it run exactly once per database.
        db.run_once(con, HOME_WORKSPACE_MIGRATION, _migrate_home_workspace)
        con.commit()
        con.close()


# The marker name for the one-time re-filing below. Bump the suffix only if
# the rewrite itself ever has to change; the old name stays recorded.
HOME_WORKSPACE_MIGRATION = "conversations_home_workspace_v1"


def _migrate_home_workspace(con: sqlite3.Connection) -> None:
    """Move each account's pre-workspace conversations under ``u_<sub>``.

    Before per-account workspaces existed (services/project_context.py), a
    signed-in user's conversations were stamped with whatever project happened
    to be globally ACTIVE at the time — usually the operators'. list_by queries
    project_id = 'u_<sub>' for the home workspace, so without this those chats
    would simply vanish from the sidebar. Operator history moves the same way:
    admins used to land in the globally active project ("Default Engagement"),
    and now every account works in its own workspace. Rows with no owner at all
    (owner_tier IS NULL: pre-accounts history, possibly several people's) are
    deliberately left where they are, unreachable, rather than being handed to
    whoever migrates first.
    """
    con.execute(
        "UPDATE conversations SET project_id = 'u_' || user_id "
        "WHERE owner_tier = 'user' AND user_id IS NOT NULL AND user_id != '' "
        "AND project_id != 'u_' || user_id"
    )
    con.execute(
        "UPDATE conversations SET project_id = 'u_' || user_id "
        "WHERE owner_tier = 'admin' AND user_id IS NOT NULL AND user_id != '' "
        "AND project_id != 'u_' || user_id"
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _msg_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["citations"] = json.loads(d.get("citations") or "[]")
    except Exception:
        d["citations"] = []
    return d


def _conv_row(row: sqlite3.Row, message_count: int = 0) -> dict:
    d = dict(row)
    d["pinned"] = bool(d.get("pinned"))
    d["message_count"] = message_count
    return d


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create(project_id: str, mode: str = "basic", title: str = "New Chat",
           user_id: str | None = None, owner_tier: str | None = None) -> dict:
    now = _ts()
    cid = _id()
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO conversations (id,project_id,user_id,owner_tier,mode,title,pinned,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (cid, project_id, user_id, owner_tier, mode, title or "New Chat", 0, now, now),
        )
        con.commit()
        con.close()
    return {"id": cid, "project_id": project_id, "user_id": user_id, "owner_tier": owner_tier,
            "mode": mode, "title": title or "New Chat", "pinned": False, "created_at": now,
            "updated_at": now, "message_count": 0}


def list_for_training(project_id: str, mode: str | None = None) -> list[dict]:
    """Conversations eligible to build training datasets from.

    Two sources, and nothing else:
      1. Operator-owned — pre-accounts history (owner_tier IS NULL) and the
         operators' own chats.
      2. Public users who accepted the CURRENT user agreement, joined live
         against user_training_consent so a withdrawal takes effect on the very
         next dataset build. Acceptance recorded against superseded wording
         does not count (the version must match the current one) — after a
         terms change nobody is included until they accept the new one.

    A user who never answered, or withdrew, is absent by construction. This is
    the single query the "only what people agreed to" promise rests on — keep
    the join here, not in a caller.
    """
    from services.training import user_consent  # local: avoids an import cycle

    # The consent table is normally created by main.py at real app startup
    # (services.training.user_consent.init_db()), but this function must also
    # work for any caller that runs before/without that — a script, a test, or
    # a future entrypoint. init_db() is idempotent (CREATE TABLE IF NOT
    # EXISTS), so calling it here just guarantees the table this query depends
    # on always exists, without duplicating its schema definition.
    user_consent.init_db()

    sql = (
        "SELECT c.*, (SELECT COUNT(*) FROM conversation_messages m WHERE m.conversation_id = c.id) AS message_count "
        "FROM conversations c WHERE c.project_id = ? "
        "AND ( c.owner_tier IS NULL OR c.owner_tier = 'admin' "
        "      OR c.user_id IN (SELECT user_id FROM user_training_consent "
        "                       WHERE allowed = 1 AND consent_version = ?) )"
    )
    params: list = [project_id, user_consent.CONSENT_VERSION]
    if mode:
        sql += " AND c.mode = ?"
        params.append(mode)
    sql += " ORDER BY c.pinned DESC, c.updated_at DESC"
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [_conv_row(r, r["message_count"]) for r in rows]


def list_by(project_id: str, mode: str | None = None, user_id: str | None = None,
            include_legacy: bool = False) -> list[dict]:
    """Conversations visible to one caller.

    ``user_id`` is REQUIRED for correctness on a multi-user deployment: without
    it every account would see every other account's chats. ``include_legacy``
    additionally returns the pre-accounts rows (user_id IS NULL) and must only
    ever be True for operators — that data is theirs.
    """
    sql = (
        "SELECT c.*, (SELECT COUNT(*) FROM conversation_messages m WHERE m.conversation_id = c.id) AS message_count "
        "FROM conversations c WHERE c.project_id = ?"
    )
    params: list = [project_id]
    if include_legacy:
        sql += " AND (c.user_id = ? OR c.user_id IS NULL)"
    else:
        sql += " AND c.user_id = ?"
    params.append(user_id)
    if mode:
        sql += " AND c.mode = ?"
        params.append(mode)
    sql += " ORDER BY c.pinned DESC, c.updated_at DESC"
    with _conn() as con:
        # The consent table may not exist yet on a fresh DB; the training path
        # must fail closed (no rows) rather than crash a dataset build.
        con.execute(
            "CREATE TABLE IF NOT EXISTS user_training_consent ("
            "user_id TEXT PRIMARY KEY, email TEXT, allowed INTEGER NOT NULL DEFAULT 0, "
            "consent_version TEXT, updated_at TEXT NOT NULL)"
        )
        rows = con.execute(sql, params).fetchall()
    # Hide empty conversations. New chats are created lazily on the frontend
    # (a client-side draft that only becomes a row once it has a first message),
    # so a persisted conversation should always carry at least one message. This
    # filter also sweeps away any legacy empty "New Chat" shells left by the old
    # eager-create behaviour, so they never clutter the sidebar again.
    return [_conv_row(r, r["message_count"]) for r in rows if r["message_count"] > 0]


def can_access(conversation_id: str, user_id: str | None, allow_legacy: bool = False) -> bool:
    """Ownership gate for every single-conversation operation.

    Callers translate False into a 404 (not 403) so a probing user cannot even
    learn that someone else's conversation id exists.
    """
    with _conn() as con:
        row = con.execute(
            "SELECT user_id FROM conversations WHERE id = ?", (conversation_id,)
        ).fetchone()
    if row is None:
        return False
    owner = row["user_id"]
    if owner is None:
        return allow_legacy
    return bool(user_id) and owner == user_id


def get(conversation_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if row is None:
            return None
        msgs = con.execute(
            "SELECT * FROM conversation_messages WHERE conversation_id = ? ORDER BY ord ASC",
            (conversation_id,),
        ).fetchall()
    conv = _conv_row(row, len(msgs))
    conv["messages"] = [_msg_to_dict(m) for m in msgs]
    return conv


def rename(conversation_id: str, title: str) -> dict | None:
    title = (title or "").strip()
    if not title:
        return None
    with _lock:
        con = _conn()
        cur = con.execute(
            "UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?",
            (title, _ts(), conversation_id),
        )
        con.commit()
        changed = cur.rowcount
        con.close()
    return get(conversation_id) if changed else None


def set_pinned(conversation_id: str, pinned: bool) -> dict | None:
    with _lock:
        con = _conn()
        cur = con.execute(
            "UPDATE conversations SET pinned = ?, updated_at = ? WHERE id = ?",
            (1 if pinned else 0, _ts(), conversation_id),
        )
        con.commit()
        changed = cur.rowcount
        con.close()
    return get(conversation_id) if changed else None


def delete(conversation_id: str) -> bool:
    with _lock:
        con = _conn()
        cur = con.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))
        con.execute("DELETE FROM conversation_messages WHERE conversation_id = ?", (conversation_id,))
        con.commit()
        deleted = cur.rowcount > 0
        con.close()
    return deleted


def delete_all_for_user(user_id: str) -> int:
    """Every conversation owned by one account, across ALL projects.

    Deliberately NOT project-scoped, unlike almost everything else in this
    module. A public user's conversations are filed under whichever project
    happened to be active when they were created (routers/conversations.py
    reads project_service.get_active_project_id()), so an account's history
    scatters across projects as the operators switch theirs. Scoping this
    delete to one project would leave conversations behind and quietly break
    the erasure promise in the privacy policy.

    Returns the number of conversations removed.
    """
    if not user_id:
        # Never let a falsy id match the pre-accounts rows (user_id IS NULL) —
        # that would delete the operators' legacy history.
        return 0
    with _lock:
        con = _conn()
        con.execute(
            "DELETE FROM conversation_messages WHERE conversation_id IN "
            "(SELECT id FROM conversations WHERE user_id = ?)",
            (user_id,),
        )
        cur = con.execute("DELETE FROM conversations WHERE user_id = ?", (user_id,))
        con.commit()
        removed = cur.rowcount
        con.close()
    return removed


def truncate_from(conversation_id: str, message_id: str) -> int | None:
    """Delete ``message_id`` and every message after it in the conversation.

    This backs "edit a previous message": the client drops the edited user
    message plus everything downstream (the now-stale assistant reply and any
    later turns), then resends the edited text as a fresh turn — a clean
    regenerated continuation rather than a misleadingly spliced history.

    Returns the number of messages removed, or ``None`` if the message does not
    belong to this conversation (the caller turns that into a 404).
    """
    with _lock:
        con = _conn()
        row = con.execute(
            "SELECT ord FROM conversation_messages WHERE id = ? AND conversation_id = ?",
            (message_id, conversation_id),
        ).fetchone()
        if row is None:
            con.close()
            return None
        cur = con.execute(
            "DELETE FROM conversation_messages WHERE conversation_id = ? AND ord >= ?",
            (conversation_id, row["ord"]),
        )
        con.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (_ts(), conversation_id))
        con.commit()
        removed = cur.rowcount
        con.close()
    return removed


def add_message(
    conversation_id: str,
    role: str,
    content: str,
    citations: list | None = None,
    documents_queried: int | None = None,
) -> dict | None:
    now = _ts()
    mid = _id()
    with _lock:
        con = _conn()
        exists = con.execute("SELECT 1 FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if exists is None:
            con.close()
            return None
        ord_row = con.execute(
            "SELECT COALESCE(MAX(ord), -1) + 1 AS next FROM conversation_messages WHERE conversation_id = ?",
            (conversation_id,),
        ).fetchone()
        ord_val = ord_row["next"]
        con.execute(
            "INSERT INTO conversation_messages "
            "(id,conversation_id,role,content,citations,documents_queried,ord,created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (mid, conversation_id, role, content, json.dumps(citations or []), documents_queried, ord_val, now),
        )
        con.execute("UPDATE conversations SET updated_at = ? WHERE id = ?", (now, conversation_id))
        con.commit()
        con.close()
    return {"id": mid, "conversation_id": conversation_id, "role": role, "ord": ord_val, "created_at": now}


# ---------------------------------------------------------------------------
# Message feedback — was this answer any good?
# ---------------------------------------------------------------------------
#
# Oyster had NO signal distinguishing a good answer from a bad one. That is not
# a cosmetic gap: without it, training on past conversations treats every reply
# as a positive example — hallucinations, errors and "[local model unavailable]"
# fallbacks included — which teaches the model its own mistakes rather than
# correcting them.
#
# A correction is the more valuable half. A thumbs-down only says "not this";
# a correction says what the answer SHOULD have been, which turns a bad exchange
# into a good training example instead of merely discarding it.

RATINGS = ("up", "down")


def set_feedback(conversation_id: str, message_id: str, rating: str,
                 correction: str = "", user_id: str | None = None) -> dict | None:
    """Record (or replace) one person's verdict on one assistant message.

    user_id defaults to '' rather than NULL because SQLite treats NULLs as
    distinct in a UNIQUE constraint — with NULL, the same person could stack up
    unlimited duplicate rows for one message instead of updating their vote.
    """
    if rating not in RATINGS:
        return None
    now = _ts()
    uid = user_id or ""
    with _lock:
        con = _conn()
        exists = con.execute(
            "SELECT 1 FROM conversation_messages WHERE id = ? AND conversation_id = ?",
            (message_id, conversation_id)).fetchone()
        if exists is None:
            con.close()
            return None
        con.execute(
            "INSERT INTO message_feedback "
            "(id,conversation_id,message_id,user_id,rating,correction,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(message_id,user_id) DO UPDATE SET "
            "rating=excluded.rating, correction=excluded.correction, updated_at=excluded.updated_at",
            (_id(), conversation_id, message_id, uid, rating, correction.strip(), now, now),
        )
        con.commit()
        con.close()
    return {"message_id": message_id, "rating": rating, "correction": correction.strip(),
            "updated_at": now}


def clear_feedback(message_id: str, user_id: str | None = None) -> bool:
    """Un-rate a message (clicking an active thumb again)."""
    with _lock:
        con = _conn()
        cur = con.execute("DELETE FROM message_feedback WHERE message_id = ? AND user_id = ?",
                          (message_id, user_id or ""))
        con.commit()
        removed = cur.rowcount > 0
        con.close()
    return removed


def feedback_for_conversation(conversation_id: str, user_id: str | None = None) -> dict:
    """message_id -> {rating, correction}, so the UI can show what was rated."""
    with _conn() as con:
        rows = con.execute(
            "SELECT message_id, rating, correction FROM message_feedback "
            "WHERE conversation_id = ? AND user_id = ?",
            (conversation_id, user_id or "")).fetchall()
    return {r["message_id"]: {"rating": r["rating"], "correction": r["correction"]} for r in rows}


def feedback_map_for_project(project_id: str) -> dict:
    """Every verdict on messages in one project, for dataset building.

    Deliberately ignores WHO gave the feedback: for training purposes a message
    anyone marked wrong is not a good example to imitate, regardless of who
    said so.
    """
    with _conn() as con:
        rows = con.execute(
            "SELECT f.message_id, f.rating, f.correction FROM message_feedback f "
            "JOIN conversations c ON c.id = f.conversation_id WHERE c.project_id = ?",
            (project_id,)).fetchall()
    out: dict = {}
    for r in rows:
        prev = out.get(r["message_id"])
        # A correction outranks a bare vote, and a downvote outranks an upvote —
        # if anyone flagged it, treat it as flagged.
        if prev is None or (r["correction"] and not prev["correction"]) or r["rating"] == "down":
            out[r["message_id"]] = {"rating": r["rating"], "correction": r["correction"]}
    return out
