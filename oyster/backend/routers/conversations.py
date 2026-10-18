"""Conversation history HTTP surface — durable sidebar chats.

Every signed-in account gets its own history. Conversations are stamped with
the caller's Supabase subject id at creation and EVERY route below re-checks
ownership before touching a row — this router is reachable by any signed-in
user, so the ownership check is the only thing standing between accounts.
Anonymous callers get 401: their history lives in their own browser
(localStorage), nothing about them is persisted server-side.

Rows predating accounts (user_id IS NULL) are the operators' own history and
remain visible only to admins.

Handlers here are deliberately plain ``def``, not ``async def``. Every one of
them does synchronous SQLite work under ``conversation_service._lock`` and
awaits nothing; declared ``async`` (as they were until 2026-09-14) that work
ran directly on the event loop, so one contended write — up to the store's
5 s ``busy_timeout`` — stalled every other request in flight, including every
heartbeat and token of someone else's chat stream. As plain ``def`` FastAPI
runs them in its threadpool, where blocking is harmless. The two background
tasks are ``async`` (they await the memory service) and push their own SQLite
reads off the loop with ``asyncio.to_thread``. ``tests/test_router_sync_rule.py``
pins this so it cannot quietly regress.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

import log_config
from models.schemas import (
    ConversationCreateRequest,
    ConversationMessageRequest,
    ConversationRenameRequest,
    MessageFeedbackRequest,
)
from services import conversation_service, project_context
from services.auth_service import require_account
from services.user_memory import service as memory_service

router = APIRouter(tags=["conversations"])


def _owner(identity: dict) -> str:
    """Stable per-account id. Supabase's `sub` never changes for an account —
    unlike email, which a user can change."""
    return identity.get("sub") or identity.get("email") or ""


def _is_admin(identity: dict) -> bool:
    return identity.get("tier") == "admin"


def _not_found(conversation_id: str) -> HTTPException:
    # 404 (never 403) for someone else's row: a wrong-owner and a
    # non-existent id must be indistinguishable.
    return HTTPException(status_code=404, detail=f"Conversation '{conversation_id}' not found.")


async def _capture_memory(conversation_id: str) -> None:
    """Best-effort: on a persisted assistant turn, extract candidate long-term
    memories from the (user, assistant) pair and resolve them. Never raises —
    errors are swallowed inside memory_service.capture_from_exchange itself.

    SIGNED-IN TURNS ONLY (enforced by the caller). Memory is written against
    the conversation's own project_id, which project_context resolved from the
    caller's identity — an account's memories land in its own workspace, never
    in the operators' store or another account's.
    """
    conv = await asyncio.to_thread(conversation_service.get, conversation_id)
    if conv is None or not conv.get("messages"):
        return
    messages = conv["messages"]
    if messages[-1]["role"] != "assistant":
        return
    user_msg = next((m["content"] for m in reversed(messages[:-1]) if m["role"] == "user"), None)
    if not user_msg:
        return
    await memory_service.capture_from_exchange(
        conv["project_id"], user_msg, messages[-1]["content"],
        conversation_id=conversation_id, message_id=messages[-1]["id"],
    )


@router.get("/conversations")
def list_conversations(mode: str | None = None, identity: dict = Depends(require_account)):
    project_id = project_context.workspace_id(identity)
    conversations = conversation_service.list_by(
        project_id, mode, user_id=_owner(identity), include_legacy=_is_admin(identity)
    )
    return {"conversations": conversations, "total": len(conversations), "project_id": project_id}


@router.post("/conversations")
def create_conversation(request: ConversationCreateRequest,
                        identity: dict = Depends(require_account)):
    project_id = project_context.workspace_id(identity)
    conv = conversation_service.create(
        project_id, request.mode, request.title,
        user_id=_owner(identity), owner_tier=identity.get("tier"),
    )
    return {"status": "ok", "conversation": conv}


@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, identity: dict = Depends(require_account)):
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)
    conv = conversation_service.get(conversation_id)
    if conv is None:
        raise _not_found(conversation_id)
    return {"conversation": conv}


@router.patch("/conversations/{conversation_id}")
def update_conversation(conversation_id: str, request: ConversationRenameRequest,
                        identity: dict = Depends(require_account)):
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)
    conv = None
    if request.title is not None:
        conv = conversation_service.rename(conversation_id, request.title)
        if conv is None:
            raise HTTPException(status_code=404, detail="Conversation not found or title empty.")
    if request.pinned is not None:
        conv = conversation_service.set_pinned(conversation_id, request.pinned)
        if conv is None:
            raise _not_found(conversation_id)
    if conv is None:
        raise HTTPException(status_code=400, detail="Nothing to update (provide title and/or pinned).")
    return {"status": "ok", "conversation": conv}


@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: str, identity: dict = Depends(require_account)):
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)
    deleted = conversation_service.delete(conversation_id)
    if not deleted:
        raise _not_found(conversation_id)
    return {"status": "ok", "deleted": conversation_id}


@router.post("/conversations/{conversation_id}/messages")
def add_message(conversation_id: str, request: ConversationMessageRequest,
                background_tasks: BackgroundTasks,
                identity: dict = Depends(require_account)):
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)
    msg = conversation_service.add_message(
        conversation_id,
        request.role,
        request.content,
        request.citations,
        request.documents_queried,
    )
    if msg is None:
        raise _not_found(conversation_id)
    if request.role == "assistant":
        background_tasks.add_task(_capture_memory, conversation_id)
    return {"status": "ok", "message": msg}


@router.post("/conversations/{conversation_id}/messages/{message_id}/truncate")
def truncate_conversation(conversation_id: str, message_id: str,
                           identity: dict = Depends(require_account)):
    """Delete a message and everything after it — the server side of editing a
    previous message. The client then resends the edited text as a fresh turn.

    Ownership is enforced exactly like every other single-conversation route, so
    one account can never truncate another's chat (404, not 403, for a row that
    isn't theirs — a wrong owner and a missing id stay indistinguishable).
    """
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)
    removed = conversation_service.truncate_from(conversation_id, message_id)
    if removed is None:
        raise HTTPException(status_code=404, detail="Message not found in this conversation.")
    return {"status": "ok", "removed": removed}


async def _remember_correction(conversation_id: str, correction: str) -> None:
    """Store a correction as a memory so it changes the NEXT answer.

    This is what makes giving feedback worth the click. Training is a slow,
    offline, batch process — and on this box a trained adapter cannot currently
    change what Oyster says at all. Memory, by contrast, is retrieved into the
    prompt on the very next message: the correction lands immediately, stays
    visible to the user in Settings, and can be deleted if it was itself wrong.

    Written against the CONVERSATION's project_id, matching _capture_memory
    above, so a correction lands in the same workspace as the chat it came from
    and never leaks into another account's store. Best-effort throughout —
    feedback must still be recorded if the memory write fails.
    """
    conv = await asyncio.to_thread(conversation_service.get, conversation_id)
    if conv is None:
        return
    try:
        await memory_service.manual_add(
            conv["project_id"], "fact",
            "correction to a previous answer", correction,
        )
    except Exception as exc:  # noqa: BLE001 — never fail the feedback call
        log_config.error("conversations._remember_correction", str(exc),
                         {"conversation_id": conversation_id})


@router.post("/conversations/{conversation_id}/messages/{message_id}/feedback")
def set_message_feedback(conversation_id: str, message_id: str,
                         request: MessageFeedbackRequest,
                         background_tasks: BackgroundTasks,
                         identity: dict = Depends(require_account)):
    """Rate one assistant answer, optionally saying what it should have said.

    The rating alone only lets a bad answer be EXCLUDED from training. The
    optional correction is the half that actually improves anything: it becomes
    the training target in place of the wrong answer, and lands in memory right
    away.
    """
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)

    if request.rating is None:
        removed = conversation_service.clear_feedback(message_id, _owner(identity))
        return {"status": "ok", "cleared": removed}

    result = conversation_service.set_feedback(
        conversation_id, message_id, request.rating,
        correction=request.correction or "", user_id=_owner(identity),
    )
    if result is None:
        raise HTTPException(
            status_code=404 if request.rating in conversation_service.RATINGS
            else 400,
            detail="Message not found in this conversation."
            if request.rating in conversation_service.RATINGS
            else f"rating must be one of {conversation_service.RATINGS} or null to clear.",
        )

    if result["correction"]:
        background_tasks.add_task(_remember_correction, conversation_id, result["correction"])
    return {"status": "ok", "feedback": result}


@router.get("/conversations/{conversation_id}/feedback")
def get_message_feedback(conversation_id: str,
                         identity: dict = Depends(require_account)):
    """What this caller already rated in this conversation, so the UI can show it."""
    if not conversation_service.can_access(conversation_id, _owner(identity), _is_admin(identity)):
        raise _not_found(conversation_id)
    return {"feedback": conversation_service.feedback_for_conversation(
        conversation_id, _owner(identity))}
