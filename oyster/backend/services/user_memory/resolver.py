"""Deduplication + update-vs-conflict resolution for candidate memories.

A new candidate is matched against existing memories in the same project by
embedding similarity (semantic — catches paraphrases, not just exact text).
When a close match exists, a deterministic lexical-overlap heuristic decides
whether the new content REFINES the existing memory (supersede, keep an audit
chain via ``supersedes_id``) or CONTRADICTS it (keep both, flag as
``conflicting`` for the operator to resolve — never silently pick a winner).

This heuristic is intentionally simple and fully offline/deterministic (no LLM
call), so behaviour is stable and testable. It will occasionally misclassify a
genuine contradiction as an update or vice versa — that's why conflicts are
surfaced to the operator rather than resolved silently, and every supersede
keeps the prior row for audit rather than deleting it.
"""

from __future__ import annotations

import re
import uuid

import config
from services import rag_service

from . import store

_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "of", "to", "for", "and", "or",
    "in", "on", "with", "this", "that", "i", "my", "me", "it", "be", "as", "at",
    "by", "has", "have", "had", "will", "would", "should", "can", "could",
}


def _tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in words if w not in _STOPWORDS and len(w) > 1}


def jaccard(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


async def resolve_candidate(
    project_id: str, type_: str, subject: str, content: str, *,
    confidence: float = 0.8, source: str = "manual",
    origin_conversation_id: str | None = None, origin_message_id: str | None = None,
    target_status: str = "active",
) -> dict:
    """Persist ``content`` as a new/updated/conflicting/duplicate memory.

    ``target_status`` is applied to a genuinely new (non-conflicting) memory —
    'active' when auto-save is on, 'pending' when ask-before-saving is on.
    Returns ``{"action": "new"|"duplicate"|"update"|"conflict", "memory": {...}}``.
    """
    embed_text = f"{subject}: {content}"

    def _insert_new() -> dict:
        return store.insert_memory(
            project_id, type_, subject, content, status=target_status,
            confidence=confidence, source=source,
            origin_conversation_id=origin_conversation_id, origin_message_id=origin_message_id,
        )

    neighbors = await rag_service.nearest_memory_vectors_async(project_id, embed_text, top_k=3)
    best = neighbors[0] if neighbors else None

    if best is None or best["score"] < config.MEMORY_DEDUP_THRESHOLD:
        mem = _insert_new()
        await rag_service.upsert_memory_vector_async(mem["id"], project_id, type_, embed_text)
        return {"action": "new", "memory": mem}

    existing = store.get_memory(best["id"])
    if existing is None or existing["status"] not in ("active", "pending"):
        mem = _insert_new()
        await rag_service.upsert_memory_vector_async(mem["id"], project_id, type_, embed_text)
        return {"action": "new", "memory": mem}

    if existing["content"].strip().lower() == content.strip().lower():
        return {"action": "duplicate", "memory": existing}

    similarity = jaccard(existing["content"], content)

    if similarity >= 0.45:
        store.update_memory(existing["id"], status="superseded")
        mem = store.insert_memory(
            project_id, type_, subject, content, status=target_status,
            confidence=confidence, source=source,
            origin_conversation_id=origin_conversation_id, origin_message_id=origin_message_id,
            supersedes_id=existing["id"],
        )
        await rag_service.upsert_memory_vector_async(mem["id"], project_id, type_, embed_text)
        return {"action": "update", "memory": mem, "superseded": existing["id"]}

    group = uuid.uuid4().hex[:10]
    store.update_memory(existing["id"], status="conflicting", conflict_group=group)
    mem = store.insert_memory(
        project_id, type_, subject, content, status="conflicting",
        confidence=confidence, source=source,
        origin_conversation_id=origin_conversation_id, origin_message_id=origin_message_id,
        conflict_group=group,
    )
    await rag_service.upsert_memory_vector_async(mem["id"], project_id, type_, embed_text)
    return {"action": "conflict", "memory": mem, "conflict_with": existing["id"], "conflict_group": group}
