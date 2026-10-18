"""Findings — a user's own saved chat messages ("profile evidence").

A finding is a chat message the user decided is worth keeping: a payload the
agent produced, a vulnerability write-up, a command that worked. It is captured
with one click from the message toolbar and lives in a per-user, per-project
list they can title, revisit (jump back into the source chat), and optionally
publish as a read-only public link.

This is DISTINCT from ``routers/findings.py`` + ``evidence_service`` — that is
the admin-only, instance-global pentest-report evidence store
(``data/evidence.json``). This one is personal, project-scoped, and copies the
per-user ownership model that ``conversation_service`` already proved: every
row carries ``user_id`` (the Supabase subject id), and ``can_access`` gates
every single-row operation so one account can never touch another's.

The captured **content** is stored (not just a message id): a just-streamed
message carries a client-side id, not the persisted DB id, so keying off the id
would be fragile. Content + ``conversation_id`` makes a finding self-sufficient
and lets "open the source chat" work by conversation.
"""

from __future__ import annotations

import json
import secrets
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
            CREATE TABLE IF NOT EXISTS user_findings (
                id              TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL,
                project_id      TEXT NOT NULL,
                conversation_id TEXT,
                conv_mode       TEXT,
                message_id      TEXT,
                title           TEXT NOT NULL,
                content         TEXT NOT NULL,
                citations       TEXT NOT NULL DEFAULT '[]',
                share_token     TEXT,
                shared_at       TEXT,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_uf_user ON user_findings(user_id, updated_at);
            CREATE INDEX IF NOT EXISTS idx_uf_user_project ON user_findings(user_id, project_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_uf_share
                ON user_findings(share_token) WHERE share_token IS NOT NULL;
            -- The public feed reads "published, newest first". Without an index
            -- ordered the same way, every feed load scans all findings and sorts
            -- them in a temp B-tree. Partial (only published rows) so it stays
            -- small no matter how many private findings exist.
            CREATE INDEX IF NOT EXISTS idx_uf_feed
                ON user_findings(shared_at DESC) WHERE share_token IS NOT NULL;
            """
        )
        # A Report is a curated subset of findings. "Add to Report" saves a
        # finding flagged in_report=1; the panel filters/toggles on it. The
        # report *document* is generated from these later. Idempotent ALTER,
        # guarded like every other migration in this codebase.
        cols = [r[1] for r in con.execute("PRAGMA table_info(user_findings)")]
        if "in_report" not in cols:
            con.execute("ALTER TABLE user_findings ADD COLUMN in_report INTEGER NOT NULL DEFAULT 0")
        # Pentest fields, absorbed from the old red-team Evidence logger — that
        # was the same concept (a finding) kept in a separate, admin-only global
        # JSON file. A finding captured from chat simply leaves them empty; one
        # logged by hand fills them in. `content` doubles as "steps to
        # reproduce" so there is exactly one body field, not two.
        for col, ddl in (
            ("severity", "TEXT NOT NULL DEFAULT 'info'"),
            ("endpoint", "TEXT NOT NULL DEFAULT ''"),
            ("method", "TEXT NOT NULL DEFAULT ''"),
            ("notes", "TEXT NOT NULL DEFAULT ''"),
            ("recommended_fix", "TEXT NOT NULL DEFAULT ''"),
            # affected_asset: a general target identifier (host/IP/service),
            # distinct from the HTTP-specific endpoint/method pair.
            # unresolved_questions: what the assessment did NOT establish —
            # lets the exported report say so instead of implying completeness.
            ("affected_asset", "TEXT NOT NULL DEFAULT ''"),
            ("unresolved_questions", "TEXT NOT NULL DEFAULT ''"),
        ):
            if col not in cols:
                con.execute(f"ALTER TABLE user_findings ADD COLUMN {col} {ddl}")
        con.commit()
        con.close()


SEVERITIES = ("critical", "high", "medium", "low", "info")


def format_report(findings: list[dict], project_id: str) -> str:
    """Render curated findings without exposing private ownership fields."""
    lines = ["# Oyster Investigation Report", "", f"Project: `{project_id}`", ""]
    if not findings:
        lines.append("No findings have been added to this report.")
    for index, finding in enumerate(findings, 1):
        lines.extend([f"## {index}. {finding.get('title') or f'Finding {index}'}", "",
                      f"**Severity:** {finding.get('severity') or 'info'}", ""])
        # affected_asset is the general target identifier (host/IP/service);
        # endpoint/method are the narrower HTTP-specific pair. Both render when
        # present — neither is invented when absent.
        if finding.get("affected_asset"):
            lines.extend([f"**Affected asset:** `{finding['affected_asset']}`", ""])
        if finding.get("endpoint"):
            lines.extend([f"**Endpoint:** `{finding['endpoint']}`", ""])
        if finding.get("method"):
            lines.extend([f"**Method:** `{finding['method']}`", ""])
        lines.extend([finding.get("content") or "", ""])
        if finding.get("notes"):
            lines.extend([f"**Notes:** {finding['notes']}", ""])
        if finding.get("recommended_fix"):
            lines.extend([f"**Recommended fix:** {finding['recommended_fix']}", ""])
        if finding.get("unresolved_questions"):
            # What the assessment did NOT establish. Rendered only when the
            # finder actually recorded one — never fabricated to fill the
            # section, so its absence here means none were recorded, not that
            # there are none.
            lines.extend([f"**Unresolved questions:** {finding['unresolved_questions']}", ""])
        citations = finding.get("citations") or []
        if citations:
            lines.append("**Supporting evidence:**")
            for i, citation in enumerate(citations, 1):
                lines.append(_citation_line(i, citation))
                excerpt = _citation_excerpt(citation)
                if excerpt:
                    lines.append(f"  > {excerpt}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_EXCERPT_MAX = 220


def _citation_excerpt(citation) -> str | None:
    """A short quote from the actual retrieved passage, so the report is
    verifiable on its own — "a citation number exists" is not the same as
    "the evidence is shown". Never invents text: returns None (renders
    nothing) when the citation carries no body text, rather than padding
    the report with a placeholder."""
    if not isinstance(citation, dict):
        return None
    for field in ("chunk", "text", "content", "snippet", "excerpt", "passage"):
        val = citation.get(field)
        if isinstance(val, str) and val.strip():
            flat = " ".join(val.split())
            return flat if len(flat) <= _EXCERPT_MAX else flat[: _EXCERPT_MAX - 1].rstrip() + "…"
    return None


def _citation_line(n: int, citation) -> str:
    """One source bullet with a MEANINGFUL title + identifier, mapping the fields
    the RAG/Knowledge paths actually emit (``source_title``/``document``/
    ``filename``/``knowledge_pack``/``source_url``/``section``/``chunk_id``), not
    the ``title``/``url`` keys they never set — which is why every source used to
    print as the bare word "Source"."""
    if not isinstance(citation, dict):
        return f"- [{n}] {citation}"
    label = (citation.get("source_title") or citation.get("document")
             or citation.get("filename") or citation.get("knowledge_pack")
             or citation.get("title") or "Untitled source")
    url = citation.get("source_url") or citation.get("url") or citation.get("canonical_url")
    # Identifier so a reader can locate the exact source: pack (+version), the
    # document section, or the chunk id.
    ident_bits = []
    pack = citation.get("knowledge_pack")
    if pack:
        ver = citation.get("pack_version")
        ident_bits.append(f"{pack}{(' ' + str(ver)) if ver else ''}")
    if citation.get("section"):
        ident_bits.append(f"§{citation['section']}")
    if citation.get("artifact_type"):
        ident_bits.append(str(citation["artifact_type"]))
    if citation.get("chunk_id"):
        ident_bits.append(f"`{citation['chunk_id']}`")
    ident = " · ".join(ident_bits)
    head = f"[{label}]({url})" if url else label
    return f"- [{n}] {head}" + (f" — {ident}" if ident else "")


def _severity(value: str | None) -> str:
    """Normalise to one of SEVERITIES; anything unknown becomes 'info' rather
    than reaching the DB and breaking the UI's colour lookup."""
    v = (value or "").strip().lower()
    return v if v in SEVERITIES else "info"


# ---------------------------------------------------------------------------
# Title derivation
# ---------------------------------------------------------------------------

def derive_title(content: str, limit: int = 60) -> str:
    """A short, human heading from the message body — the first meaningful line
    with markdown noise stripped, truncated. The user can rename it afterwards;
    this only has to be a sensible default so a fresh finding is scannable."""
    for raw in (content or "").splitlines():
        line = raw.strip().lstrip("#>-*").strip().strip("`").strip()
        if len(line) < 3:
            continue
        collapsed = " ".join(line.split())
        if len(collapsed) <= limit:
            return collapsed
        return collapsed[: limit - 1].rstrip() + "…"
    return "Untitled finding"


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _row(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["citations"] = json.loads(d.get("citations") or "[]")
    except Exception:
        d["citations"] = []
    d["shared"] = bool(d.get("share_token"))
    d["in_report"] = bool(d.get("in_report"))
    # The token IS included here — but only ever reaches the OWNER, because
    # every route serving this payload is ownership-gated (require_account +
    # can_access). The owner needs it to rebuild their public share URL after a
    # reload. The UNAUTHENTICATED public path is get_by_token(), a completely
    # separate projection that never selects share_token. So the secret is
    # visible to the person who created it and to nobody else.
    return d


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create(user_id: str, project_id: str, content: str, *,
           title: str | None = None, conversation_id: str | None = None,
           conv_mode: str | None = None, message_id: str | None = None,
           citations: list | None = None, in_report: bool = False,
           severity: str | None = None, endpoint: str = "", method: str = "",
           notes: str = "", recommended_fix: str = "",
           affected_asset: str = "", unresolved_questions: str = "") -> dict:
    now = _ts()
    fid = _id()
    heading = (title or "").strip() or derive_title(content)
    with _lock:
        con = _conn()
        con.execute(
            "INSERT INTO user_findings "
            "(id,user_id,project_id,conversation_id,conv_mode,message_id,title,content,"
            " citations,share_token,shared_at,in_report,severity,endpoint,method,notes,"
            " recommended_fix,affected_asset,unresolved_questions,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fid, user_id, project_id, conversation_id, conv_mode, message_id,
             heading, content, json.dumps(citations or []), None, None,
             1 if in_report else 0, _severity(severity), endpoint or "", method or "",
             notes or "", recommended_fix or "", affected_asset or "",
             unresolved_questions or "", now, now),
        )
        con.commit()
        con.close()
    return get(fid)


def list_by(user_id: str, project_id: str | None = None,
            in_report: bool | None = None) -> list[dict]:
    sql = "SELECT * FROM user_findings WHERE user_id = ?"
    params: list = [user_id]
    if project_id:
        sql += " AND project_id = ?"
        params.append(project_id)
    if in_report is not None:
        sql += " AND in_report = ?"
        params.append(1 if in_report else 0)
    sql += " ORDER BY updated_at DESC"
    with _conn() as con:
        rows = con.execute(sql, params).fetchall()
    return [_row(r) for r in rows]


def get(finding_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute("SELECT * FROM user_findings WHERE id = ?", (finding_id,)).fetchone()
    return _row(row) if row else None


def can_access(finding_id: str, user_id: str | None) -> bool:
    """Ownership gate. Callers turn False into 404 (not 403), so a probing user
    cannot learn that someone else's finding id exists."""
    with _conn() as con:
        row = con.execute(
            "SELECT user_id FROM user_findings WHERE id = ?", (finding_id,)
        ).fetchone()
    if row is None:
        return False
    return bool(user_id) and row["user_id"] == user_id


def update(finding_id: str, *, title: str | None = None,
           content: str | None = None, in_report: bool | None = None,
           severity: str | None = None, endpoint: str | None = None,
           method: str | None = None, notes: str | None = None,
           recommended_fix: str | None = None, affected_asset: str | None = None,
           unresolved_questions: str | None = None) -> dict | None:
    sets, params = [], []
    if title is not None:
        t = title.strip()
        if not t:
            return None
        sets.append("title = ?"); params.append(t)
    if content is not None:
        sets.append("content = ?"); params.append(content)
    if in_report is not None:
        sets.append("in_report = ?"); params.append(1 if in_report else 0)
    if severity is not None:
        sets.append("severity = ?"); params.append(_severity(severity))
    for col, val in (("endpoint", endpoint), ("method", method),
                     ("notes", notes), ("recommended_fix", recommended_fix),
                     ("affected_asset", affected_asset),
                     ("unresolved_questions", unresolved_questions)):
        if val is not None:
            sets.append(f"{col} = ?"); params.append(val)
    if not sets:
        return get(finding_id)
    sets.append("updated_at = ?"); params.append(_ts())
    params.append(finding_id)
    with _lock:
        con = _conn()
        cur = con.execute(f"UPDATE user_findings SET {', '.join(sets)} WHERE id = ?", params)
        con.commit()
        changed = cur.rowcount
        con.close()
    return get(finding_id) if changed else None


def delete(finding_id: str) -> bool:
    with _lock:
        con = _conn()
        cur = con.execute("DELETE FROM user_findings WHERE id = ?", (finding_id,))
        con.commit()
        deleted = cur.rowcount > 0
        con.close()
    return deleted


# ---------------------------------------------------------------------------
# Public sharing (read-only, unguessable token)
# ---------------------------------------------------------------------------

def set_share(finding_id: str) -> str | None:
    """Mint (or replace) the public token. Regenerating invalidates the old URL
    by construction — anyone holding it gets a 404 once the token changes."""
    token = secrets.token_urlsafe(32)
    now = _ts()
    with _lock:
        con = _conn()
        cur = con.execute(
            "UPDATE user_findings SET share_token = ?, shared_at = ?, updated_at = ? WHERE id = ?",
            (token, now, now, finding_id),
        )
        con.commit()
        changed = cur.rowcount
        con.close()
    return token if changed else None


def revoke_share(finding_id: str) -> bool:
    with _lock:
        con = _conn()
        cur = con.execute(
            "UPDATE user_findings SET share_token = NULL, shared_at = NULL, updated_at = ? WHERE id = ?",
            (_ts(), finding_id),
        )
        con.commit()
        changed = cur.rowcount > 0
        con.close()
    return changed


def list_public(viewer_id: str = "", limit: int = 100,
                offset: int = 0) -> tuple[list[dict], int]:
    """The community feed: every finding whose owner published it.

    Returns ``(page, total)`` from ONE database round trip. The router needs
    both, and fetching them separately meant two scans of the same table on
    every feed load.

    Deliberately NOT a projection of the private row — it carries the author's
    public handle (never an email) and omits project_id / conversation_id /
    message_id / user_id entirely, so browsing the feed reveals nothing about
    where a finding lives or who owns it beyond that handle. ``is_mine`` lets
    the viewer un-publish their own straight from the feed.
    """
    from services import user_profiles

    with _conn() as con:
        # COUNT(*) OVER () rides along with the page (SQLite 3.25+, window
        # functions), so the total costs no extra scan.
        rows = con.execute(
            "SELECT id, user_id, title, content, citations, severity, endpoint, method, "
            "       notes, recommended_fix, shared_at, created_at, "
            "       COUNT(*) OVER () AS total "
            "FROM user_findings WHERE share_token IS NOT NULL "
            "ORDER BY shared_at DESC LIMIT ? OFFSET ?",
            (max(1, min(limit, 200)), max(0, offset)),
        ).fetchall()

    total = rows[0]["total"] if rows else 0
    handles = user_profiles.handles_for([r["user_id"] for r in rows])
    out: list[dict] = []
    for r in rows:
        d = dict(r)
        owner = d.pop("user_id")
        d.pop("total", None)
        try:
            d["citations"] = json.loads(d.get("citations") or "[]")
        except Exception:
            d["citations"] = []
        d["author"] = handles.get(owner, "User")
        d["is_mine"] = bool(viewer_id) and owner == viewer_id
        out.append(d)
    return out, total


def count_public() -> int:
    """Standalone count. list_public returns the total alongside its page, so
    this is only for callers that want the number on its own (and tests)."""
    with _conn() as con:
        return con.execute(
            "SELECT COUNT(*) AS n FROM user_findings WHERE share_token IS NOT NULL"
        ).fetchone()["n"]


def get_by_token(token: str) -> dict | None:
    """The ONLY read path reachable without authentication. Returns a minimal
    public projection — never the owner, project, conversation or message id.
    Returns None for an unknown or revoked token (share_token NULL never
    matches, because we refuse an empty token first)."""
    if not token:
        return None
    from services import user_profiles

    with _conn() as con:
        row = con.execute(
            "SELECT user_id, title, content, citations, severity, endpoint, method, "
            "       recommended_fix, created_at FROM user_findings WHERE share_token = ?",
            (token,),
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    owner = d.pop("user_id")            # never leaves this function
    try:
        d["citations"] = json.loads(d.get("citations") or "[]")
    except Exception:
        d["citations"] = []
    d["author"] = user_profiles.handles_for([owner]).get(owner, "User")
    return d


def delete_all_for_user(user_id: str) -> int:
    """Every finding owned by one account (privacy erasure)."""
    if not user_id:
        return 0
    with _lock:
        con = _conn()
        cur = con.execute("DELETE FROM user_findings WHERE user_id = ?", (user_id,))
        con.commit()
        removed = cur.rowcount
        con.close()
    return removed
