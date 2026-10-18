"""Which project a caller is actually working in.

The operator surface (projects, scope, red-team planning, conversations,
long-term memory, per-project settings) was built for a single operator and
therefore leans on one global pointer: ``project_service.get_active_project_id()``.
That is fine when the only callers are two people who share a workspace on
purpose. It is not fine now that every signed-in account gets the same surface —
one account switching project, setting scope or storing a memory would land in
whatever project happened to be globally active, i.e. in someone else's
workspace.

This module resolves the project per request from the caller's identity, so the
isolation is structural rather than a check each route has to remember:

  every signed-in account (admins included) → their OWN active project
          (``user_prefs``), or ``u_<sub>`` — their personal home workspace,
          auto-created on first use — when they have not picked one. Accounts
          create and switch between their own private projects; the choice is
          per-account, so one account switching can never move another, and
          nobody inherits a shared "Default Engagement" full of other people's
          chats.
  anon  → refused (401)

``u_<sub>`` is deliberately the SAME id ``services/artifact_scope.scope_for``
already mints for attachments, so an account's uploads, conversations, scope,
memories and settings all land in one coherent workspace instead of being
scattered across two naming schemes.

``project_service.ensure_project`` never activates what it creates, so a user
provisioning their workspace can never swap the operators' active project out
from under them.
"""

from __future__ import annotations

from fastapi import HTTPException, status

from services import project_service, user_prefs


def _personal_workspace(identity: dict) -> str:
    """The caller's own home project id, created on first use."""
    sub = identity.get("sub") or ""
    if not sub:
        # A verified token with no subject should be impossible. Refuse rather
        # than fall through to a shared space — the same call this module's
        # sibling (artifact_scope) makes.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot resolve account identity",
        )
    pid = f"u_{sub}"
    label = identity.get("email") or sub
    project_service.ensure_project(
        pid,
        f"Workspace — {label}",
        "Auto-created per-account workspace.",
    )
    # The home workspace is owned by its account even if the projects table
    # predates owner_id (the init_db backfill covers pre-existing rows; this
    # covers a row created fresh by ensure_project, whose INSERT OR IGNORE does
    # not set owner_id).
    if project_service.owner_of(pid) != sub:
        project_service.set_owner(pid, sub)
    return pid


def _active_workspace(identity: dict) -> str:
    """The project a caller lands in when the route does not name one.

    Resolution order:
      1. the caller's own active project (user_prefs) — if it still exists AND
         is theirs to see (a stale pointer to a deleted or now-inaccessible
         project is ignored, never trusted);
      2. else the fallback: admins → the global active project (today's
         behaviour, keeps the shared operator surfaces coherent); users → their
         personal ``u_<sub>`` home workspace.
    """
    sub = identity.get("sub") or ""
    chosen = user_prefs.get_active_project_id(sub) if sub else None
    if chosen and project_service.is_visible_to(identity, chosen):
        return chosen
    # Everyone — admins included — falls back to their OWN workspace. Admins
    # used to land in the globally-active project ("Default Engagement"), which
    # is now invisible to them; landing somewhere you cannot see in the switcher
    # is worse than having no shared project at all.
    return _personal_workspace(identity)


def workspace_id(identity: dict) -> str:
    """The project for a route that does NOT name one in its path.

    Used by chat, conversations, scope and red-team — everywhere that used to
    call ``get_active_project_id()`` directly.
    """
    tier = identity.get("tier")
    if tier in ("admin", "user"):
        return _active_workspace(identity)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sign in to use this feature",
        headers={"WWW-Authenticate": "Bearer"},
    )


def workspace_for_path(identity: dict, requested_project_id: str) -> str:
    """The project for a route that DOES name one in its path.

    Admins may address any project id in the URL (operator behaviour). A user
    may address a project id ONLY if they own it; anything else — ``default``,
    another account's workspace — resolves to their own active workspace rather
    than 403ing, exactly as artifacts already behave.
    """
    tier = identity.get("tier")
    if tier == "admin":
        return requested_project_id
    if tier == "user":
        if requested_project_id and project_service.is_visible_to(identity, requested_project_id):
            return requested_project_id
        return _active_workspace(identity)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sign in to use this feature",
        headers={"WWW-Authenticate": "Bearer"},
    )


def is_operator(identity: dict) -> bool:
    return identity.get("tier") == "admin"
