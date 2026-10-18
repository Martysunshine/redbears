"""Who may touch which artifacts — and how much they may upload.

Attachments are a PUBLIC feature (product decision: anyone can upload files,
images, videos and notes, no account needed). That decision is kept intact
here. What is not kept is the way it was first wired: the artifacts router was
mounted with no authentication at all, and every route took ``project_id``
straight from the URL and trusted it. Verified against production before this
module existed, an anonymous request could:

  * ``GET  /projects/default/artifacts``            → list the operators' files
  * ``POST /projects/default/artifacts/note``       → write into their project
  * ``DELETE /projects/default/artifacts/{id}``     → delete their files
  * ``POST /projects/default/artifacts/ask``        → RAG-query their documents

…for any project id it could guess, and "default" guesses fine. Engagement
material (rules of engagement, client source, findings) lives in those
projects, so this was a data-exposure hole, not only an abuse one.

The fix keeps the feature and removes the trust:

  **The URL no longer decides whose data you touch — your identity does.**

  admin → the project id in the URL (operators keep full project access)
  user  → ``u_<supabase sub>``   — a sandbox of their own, auto-created
  anon  → ``anon_<hash of ip>``  — a sandbox of their own, auto-created

Non-admins can therefore ask for ``default`` all they like; they land in their
own space either way. Cross-tenant access stops being an authorisation check
that someone must remember to write — it becomes unreachable by construction.

Quotas exist for the other half of the problem: uploads run OCR, vision and
Whisper on a 2-core box, so unlimited anonymous uploads are a denial-of-service
against Oyster's chat, not just a disk-space concern.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from datetime import datetime, timezone
from threading import Lock

from fastapi import Depends, HTTPException

import config
from services import project_service
from services.auth_service import require_chat_access

_lock = Lock()

# Daily upload allowance per caller, by tier. Deliberately generous for
# accounts and tight for anonymous visitors: an account is attributable and
# revocable, an IP is neither.
ANON_DAILY_UPLOADS = int(getattr(config, "ANON_DAILY_UPLOADS", 5))
USER_DAILY_UPLOADS = int(getattr(config, "USER_DAILY_UPLOADS", 20))

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS artifact_upload_quota (
    scope_key TEXT NOT NULL,
    day       TEXT NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_key, day)
)
"""


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(config.MEMORY_DB), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock:
        con = _conn()
        con.execute(_TABLE_SQL)
        con.commit()
        con.close()


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _ip_key(ip: str | None) -> str:
    """Hash the IP: the quota table does not need to store where people live."""
    return hashlib.sha256((ip or "unknown").encode()).hexdigest()[:16]


def scope_for(identity: dict, requested_project_id: str) -> str:
    """The project id this caller is actually allowed to operate on."""
    tier = identity.get("tier")
    if tier == "admin":
        return requested_project_id

    if tier == "user":
        sub = identity.get("sub") or ""
        if not sub:
            # A verified token with no subject should be impossible; refuse
            # rather than fall through to a shared space.
            raise HTTPException(status_code=403, detail="Cannot resolve account identity")
        pid = f"u_{sub}"
        label = identity.get("email") or sub
        # Same id AND same label as services/project_context.py: this project
        # is no longer just an attachment sandbox, it is the account's whole
        # workspace (conversations, scope, memory, settings live here too).
        # Whichever module reaches ensure_project first must name it the same,
        # or the name would depend on which endpoint the account happened to
        # call first.
        project_service.ensure_project(pid, f"Workspace — {label}",
                                       "Auto-created per-account workspace.")
        return pid

    pid = f"anon_{_ip_key(identity.get('ip'))}"
    project_service.ensure_project(pid, "Attachments — guest",
                                   "Auto-created per-visitor attachment space.")
    return pid


def consume_upload(identity: dict, n: int = 1) -> None:
    """Charge n uploads against this caller's daily allowance, or 429.

    Atomic UPSERT-RETURNING like chat_quota: comparing the RETURNED count
    closes the race that two parallel uploads would win against a separate
    check-then-increment.
    """
    tier = identity.get("tier")
    if tier == "admin":
        return
    limit = USER_DAILY_UPLOADS if tier == "user" else ANON_DAILY_UPLOADS
    key = (identity.get("sub") or "") if tier == "user" else _ip_key(identity.get("ip"))
    with _lock:
        con = _conn()
        con.execute(_TABLE_SQL)
        row = con.execute(
            "INSERT INTO artifact_upload_quota (scope_key, day, count) VALUES (?,?,?) "
            "ON CONFLICT(scope_key, day) DO UPDATE SET count = count + ? "
            "RETURNING count",
            (key, _today(), n, n),
        ).fetchone()
        con.commit()
        con.close()
    if row and row["count"] > limit:
        raise HTTPException(
            status_code=429,
            detail=("upload_daily_limit" if tier == "anon" else
                    f"Daily upload limit reached ({limit}). Try again tomorrow."),
        )


def free_disk_bytes() -> int:
    try:
        return shutil.disk_usage(str(config.DATA_DIR)).free
    except OSError:
        # Can't measure → don't block uploads on a broken stat call. The
        # per-caller caps still apply.
        return 1 << 60


def assert_disk_headroom() -> None:
    """Global backstop: refuse to write when the disk is nearly full.

    This applies to EVERYONE, operators included. The per-caller caps below
    bound what any one account can own, but they cannot account for the other
    things sharing this disk (Docker images, Ollama models, the databases). A
    full disk does not degrade uploads — it takes the whole box down, so the
    last few gigabytes are not available to anybody.
    """
    floor = int(config.MIN_FREE_DISK_GB * (1 << 30))
    free = free_disk_bytes()
    if free < floor:
        raise HTTPException(
            status_code=507,
            detail=("Server storage is nearly full — uploads are paused. "
                    "This is being addressed; chat is unaffected."),
        )


def storage_used_bytes(project_id: str) -> int:
    """Bytes this caller currently occupies.

    Summed from the artifacts table rather than kept as a counter: a counter
    drifts every time something is deleted or a write half-fails, and a storage
    cap that drifts upward silently stops being a cap. This is always exact,
    and deleting files immediately frees allowance.
    """
    with _conn() as con:
        try:
            row = con.execute(
                "SELECT COALESCE(SUM(size), 0) AS b FROM artifacts WHERE project_id = ?",
                (project_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            return 0  # table not created yet
    return int(row["b"] or 0)


def storage_cap_bytes(tier: str) -> int:
    if tier == "admin":
        return 1 << 60  # operators are bounded by the disk floor only
    mb = config.USER_MAX_STORAGE_MB if tier == "user" else config.ANON_MAX_STORAGE_MB
    return int(mb) * (1 << 20)


class ArtifactScope:
    """Resolved caller + the project they may touch. Injected into every route."""

    def __init__(self, project_id: str, identity: dict):
        self.project_id = project_id
        self.identity = identity

    @property
    def tier(self) -> str:
        return self.identity.get("tier", "anon")

    def charge_upload(self, n: int = 1) -> None:
        consume_upload(self.identity, n)

    def assert_can_store(self, incoming_bytes: int) -> None:
        """Both storage checks, in the order that fails cheapest first."""
        assert_disk_headroom()
        if self.tier == "admin":
            return
        cap = storage_cap_bytes(self.tier)
        used = storage_used_bytes(self.project_id)
        if used + max(0, incoming_bytes) > cap:
            remaining = max(0, cap - used)
            raise HTTPException(
                status_code=413,
                detail=(
                    f"Storage limit reached. You're using "
                    f"{used / (1 << 20):.0f} MB of {cap / (1 << 20):.0f} MB "
                    f"({remaining / (1 << 20):.0f} MB free). "
                    "Delete some attachments to make room."
                ),
            )


async def artifact_scope(
    project_id: str, identity: dict = Depends(require_chat_access)
) -> ArtifactScope:
    """FastAPI dependency. Declares the {project_id} path param so routes no
    longer need to — which is the point: a route that cannot see the raw value
    cannot accidentally trust it."""
    return ArtifactScope(scope_for(identity, project_id), identity)
