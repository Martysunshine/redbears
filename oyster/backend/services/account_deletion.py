"""Erase everything Oyster holds about one account.

This backs the "Delete my account" control in Settings. The privacy policy
promises erasure (§10, §11) and that promise used to depend on somebody reading
an inbox and running SQL by hand; this makes it a thing the user can actually
do, immediately.

**What this module cannot do, on purpose.** It deletes everything *Oyster*
owns. It does not delete the Supabase login record, because that needs the
``service_role`` key and config.py records the invariant that the service_role
key is used nowhere in this codebase — it bypasses every row-level policy in
the whole Supabase project, and putting it on a public-facing VPS to power a
delete button trades a large permanent risk for a small convenience. The login
record is removed by the client calling a ``security definer`` function inside
Supabase (``delete_own_account``), where that privilege already lives and
cannot leak to us. See the plan / AGREEMENT.md.

Order matters here and is not arbitrary:

  artifacts → memories → findings → project row → conversations → consent → quota

Artifacts must go BEFORE the project row: ``project_service.delete_project``
cascades project_events/memories/scan_results/attack_surface but **not**
artifacts, their files on disk, or their Chroma vectors, so deleting the
project first would orphan all three with no owner left to find them by.
"""

from __future__ import annotations

import hashlib
import sqlite3

import config
import log_config
from services import project_service
from services.artifacts import service as artifact_service
from services.artifacts import store as artifact_store
from services.training import user_consent
from services.user_memory import service as memory_service


def sandbox_project_id(sub: str) -> str:
    """The per-account artifact space. Must match services/artifact_scope.py."""
    return f"u_{sub}"


def _delete_upload_quota(sub: str) -> int:
    with sqlite3.connect(str(config.MEMORY_DB)) as con:
        try:
            cur = con.execute("DELETE FROM artifact_upload_quota WHERE scope_key = ?", (sub,))
            con.commit()
            return cur.rowcount
        except sqlite3.OperationalError:
            return 0  # table not created yet — nothing to erase


async def purge_account(sub: str, email: str | None = None) -> dict:
    """Delete every trace of one account. Returns per-category counts.

    Best-effort per category: one failing step must not abandon the rest
    half-deleted, because a partial erasure that reports failure is worse for
    the user than a complete one that reports which parts were awkward. Any
    failures are returned so the caller can be honest about them.
    """
    if not sub:
        raise ValueError("purge_account requires a subject id")

    counts: dict = {"conversations": 0, "artifacts": 0, "memories": 0,
                    "findings": 0, "project": False, "agreement": 0,
                    "upload_quota": 0}
    failures: list[str] = []
    pid = sandbox_project_id(sub)

    # 1. Artifacts first — this also removes the files, thumbnails, sampled
    #    frames and Chroma vectors (services/artifacts/service.py::delete).
    try:
        for rec in artifact_store.list_for_project(pid):
            if await artifact_service.delete(pid, rec["id"]):
                counts["artifacts"] += 1
    except Exception as exc:  # noqa: BLE001 — never abort the rest of the purge
        failures.append(f"artifacts: {exc}")

    # 2. User memories + their vectors.
    try:
        counts["memories"] = await memory_service.delete_all_personal_data(pid)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"memories: {exc}")

    # 3. The account's own findings (saved chat messages + any share tokens),
    #    across every project, before the project row is removed.
    try:
        from services import user_findings_service
        counts["findings"] = user_findings_service.delete_all_for_user(sub)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"findings: {exc}")

    # 4. The now-empty sandbox project. force=True because this IS a personal
    #    home workspace (u_<sub>), which delete_project otherwise refuses — here
    #    the whole account is being erased, so it must go.
    try:
        counts["project"] = bool(project_service.delete_project(pid, force=True))
    except Exception as exc:  # noqa: BLE001
        failures.append(f"project: {exc}")

    # 5. Conversations + messages, across every project (see the docstring on
    #    conversation_service.delete_all_for_user for why this is not scoped).
    try:
        from services import conversation_service
        counts["conversations"] = conversation_service.delete_all_for_user(sub)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"conversations: {exc}")

    # 6. The agreement record — after the data it governed, so a crash midway
    #    never leaves chats present with no record of what was agreed.
    try:
        counts["agreement"] = user_consent.delete(sub)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"agreement: {exc}")

    try:
        counts["upload_quota"] = _delete_upload_quota(sub)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"upload_quota: {exc}")

    # Accountability without retention: GDPR wants evidence that an erasure
    # happened, not a copy of whose it was. Hash the subject and drop the
    # email entirely — logging it here would re-create the personal data we
    # were just asked to destroy.
    log_config.audit("account_deleted", {
        "subject_hash": hashlib.sha256(sub.encode()).hexdigest()[:16],
        **counts,
        "failures": failures,
    })

    return {"status": "deleted" if not failures else "partial",
            "deleted": counts, "failures": failures}
