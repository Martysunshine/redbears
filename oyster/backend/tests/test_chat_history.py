"""Conversation-history context for /chat (follow-up questions).

Basic chat used to be stateless: every turn was answered from ``request.prompt``
alone, so "and the second target?" arrived with no idea what the first one was.
The client now sends the prior turns and the router threads a trimmed transcript
into the prompt. Two things are verified here:

  1. ``build_history_context`` — the pure budgeting/formatting logic (empty,
     turn cap, char cap, most-recent-first, role labels, dict vs object).
  2. The ``/chat`` endpoint actually threads that history for a signed-in
     caller as real messages[] roles (not text), ignores it for an anonymous
     one, and — with no history — produces byte-for-byte the previous
     single-user-message request.

``/chat`` itself sends real messages[] via ``ollama_service.stream_chat``
(see 2026-09-30, oyster/docs/AI_HANDOFF.md — a flattened "User:"/"Assistant:"
text blob through /api/generate was what produced invented tools, leaked
transcript labels, and lost follow-up context). The RAG "ask" path
(services/artifacts/service.py) is unchanged and still uses
``build_history_context`` + ``ollama_service.generate`` — those tests below
are unaffected.

No network and no model: ``ollama_service.stream_chat`` is replaced with a
fake that records the messages it was handed.
"""

from __future__ import annotations

import asyncio
from typing import AsyncGenerator

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

import config
import prompt_utils
from models.schemas import ChatMessage, ChatRequest


# ── unit: the history builder ───────────────────────────────────────────────

def test_empty_history_is_empty_string():
    assert prompt_utils.build_history_context([]) == ""
    assert prompt_utils.build_history_context([{"role": "user", "content": "   "}]) == ""


def test_history_labels_roles_and_keeps_order():
    h = [
        {"role": "user", "content": "scan nmap first"},
        {"role": "assistant", "content": "run nmap -sV"},
        {"role": "user", "content": "and the second target?"},
    ]
    block = prompt_utils.build_history_context(h)
    assert "User: scan nmap first" in block
    assert "Assistant: run nmap -sV" in block
    assert "and the second target?" in block
    # Chronological order preserved.
    assert block.index("scan nmap first") < block.index("and the second target?")
    # An unknown role is shown as the user's, never dropped.
    odd = prompt_utils.build_history_context([{"role": "system", "content": "x"}])
    assert "User: x" in odd


def test_history_char_budget_keeps_most_recent():
    h = [
        {"role": "user", "content": "A" * 3000},
        {"role": "assistant", "content": "B" * 3000},
        {"role": "user", "content": "latest short question"},
    ]
    block = prompt_utils.build_history_context(h, max_turns=99, max_chars=1500)
    assert "latest short question" in block  # newest survives
    assert "A" * 3000 not in block           # oldest dropped to fit


def test_history_turn_budget_keeps_most_recent():
    h = [{"role": "user", "content": f"m{i}"} for i in range(40)]
    block = prompt_utils.build_history_context(h, max_turns=5, max_chars=10_000)
    assert block.count("User:") == 5
    assert "m39" in block and "m35" in block and "m34" not in block


def test_history_accepts_pydantic_objects():
    r = ChatRequest(prompt="now", history=[{"role": "user", "content": "before"}])
    assert isinstance(r.history[0], ChatMessage)
    assert "User: before" in prompt_utils.build_history_context(r.history)


def test_history_block_frames_transcript_as_context_not_instructions():
    # Retrieved/echoed turns must be presented as background, not as new
    # commands the model should obey — the injection-as-data guard.
    block = prompt_utils.build_history_context([{"role": "user", "content": "hi"}])
    assert "background" in block.lower() or "context" in block.lower()


# ── unit: follow-up retrieval-query anchoring ───────────────────────────────

def test_followup_query_unchanged_without_history():
    assert prompt_utils.build_followup_query("how is it exploited?", []) == "how is it exploited?"


def test_followup_query_anchors_anaphoric_question():
    h = [
        {"role": "user", "content": "Explain CVE-2021-44228 Log4Shell"},
        {"role": "assistant", "content": "It is an RCE in Log4j via JNDI lookups."},
    ]
    q = prompt_utils.build_followup_query("how is it exploited?", h)
    # The prior USER turn is prepended so retrieval keys on the CVE, not "it".
    assert q == "Explain CVE-2021-44228 Log4Shell how is it exploited?"


def test_followup_query_leaves_selfcontained_question_alone():
    h = [{"role": "user", "content": "tell me about kubernetes RBAC"}]
    # Names its own subject and contains no trigger word → not rewritten.
    assert prompt_utils.build_followup_query("What is SSRF?", h) == "What is SSRF?"
    # Long question carries its own subject → not rewritten even with a trigger.
    long_q = "Explain in detail how an attacker would chain these two findings into RCE"
    assert prompt_utils.build_followup_query(long_q, h) == long_q


def test_followup_query_needs_a_prior_user_turn():
    # Only assistant turns so far → nothing to anchor on → unchanged.
    h = [{"role": "assistant", "content": "Hi, ask me anything about your files."}]
    assert prompt_utils.build_followup_query("summarize that", h) == "summarize that"


# ── integration: the /chat endpoint threads (or omits) history ──────────────

@pytest.fixture
def captured(monkeypatch):
    """Mount only the chat router, stub its collaborators, and capture the exact
    prompt handed to Ollama."""
    from routers import chat as chat_router
    from services import chat_queue, entitlements, ollama_service, project_service, user_prefs
    from services.auth_service import oauth2_scheme, require_chat_access

    # The signed-in path resolves a per-account workspace, which reads these.
    project_service.init_db()
    user_prefs.init_db()

    box: dict = {}

    async def fake_stream(messages, model) -> AsyncGenerator[str, None]:
        box["messages"] = messages
        box["model"] = model
        yield "ok"

    async def no_memory(project_id, prompt):
        return []

    async def not_priority(identity, bearer):
        return False

    monkeypatch.setattr(ollama_service, "stream_chat", fake_stream)
    monkeypatch.setattr(chat_router.memory_service, "retrieve_relevant", no_memory)
    monkeypatch.setattr(chat_router.entitlements, "is_priority", not_priority)
    # A clean queue per test so one account's cap can't spill across tests.
    monkeypatch.setattr(chat_queue, "queue", chat_queue.ChatQueue())

    app = FastAPI()
    app.include_router(chat_router.router)

    holder = {"identity": {"tier": "admin", "email": "op@x", "sub": "op-1"}}
    app.dependency_overrides[require_chat_access] = lambda: holder["identity"]
    app.dependency_overrides[oauth2_scheme] = lambda: "tok"

    client = TestClient(app)
    return client, box, holder


def _send(client, **body):
    body.setdefault("prompt", "hello")
    r = client.post("/chat", json=body)
    assert r.status_code == 200, r.text
    assert r.text == "ok"  # the fake model's single token
    return r


def test_signed_in_history_is_threaded_into_the_prompt(captured):
    client, box, _ = captured
    _send(
        client,
        prompt="and the second one?",
        history=[
            {"role": "user", "content": "what's the first CVE?"},
            {"role": "assistant", "content": "CVE-2021-44228 (Log4Shell)"},
        ],
    )
    roles = [m["role"] for m in box["messages"]]
    assert roles[0] == "system"
    assert roles[-1] == "user"
    # Prior turns arrive as their OWN real messages, not text flattened into
    # one prompt string — the exact mismatch that made a chat-tuned model
    # continue a "User:"/"Assistant:" transcript instead of answering it.
    assert {"role": "user", "content": "what's the first CVE?"} in box["messages"]
    assert {"role": "assistant", "content": "CVE-2021-44228 (Log4Shell)"} in box["messages"]
    assert box["messages"][-1]["content"] == "and the second one?"
    # History precedes the current turn.
    cve_idx = next(i for i, m in enumerate(box["messages"]) if m["content"] == "CVE-2021-44228 (Log4Shell)")
    assert cve_idx < len(box["messages"]) - 1


def test_no_history_is_the_old_stateless_prompt(captured):
    client, box, _ = captured
    _send(client, prompt="just this")
    # Just system + the one user turn — no history wrapper, no other roles.
    assert [m["role"] for m in box["messages"]] == ["system", "user"]
    assert box["messages"][-1] == {"role": "user", "content": "just this"}


def test_anonymous_chat_never_gets_history(captured, monkeypatch):
    client, box, holder = captured
    from services import chat_quota
    monkeypatch.setattr(chat_quota, "used_today", lambda ip: 0)
    monkeypatch.setattr(chat_quota, "consume", lambda ip: 1)
    holder["identity"] = {"tier": "anon", "ip": "203.0.113.7"}
    _send(
        client,
        prompt="anon question",
        history=[{"role": "user", "content": "should be ignored"}],
    )
    assert [m["role"] for m in box["messages"]] == ["system", "user"]
    assert box["messages"][-1] == {"role": "user", "content": "anon question"}
    assert "should be ignored" not in str(box["messages"])


# ── RAG Analyst follow-ups: history is added to the prompt, retrieval is not ──

@pytest.fixture
def rag_capture(monkeypatch):
    """Stub the RAG ask collaborators and capture (retrieval query, chat messages).

    2026-09-30: the ask path now sends structured /api/chat messages via
    ollama_service.chat (was a flattened /api/generate prompt) — the RAG
    counterpart of the main-chat migration. Evidence lives in the system
    message, prior turns are real roles, the question is the final user turn,
    and the returned citations are unchanged.
    """
    from services.artifacts import service as art
    box: dict = {}

    async def fake_search(query, top_k=5, project_id=None, artifact_id=None):
        box["retrieval_query"] = query
        return [{"document": "doc.txt", "chunk": "some evidence", "score": 0.9}]

    async def fake_knowledge(query, top_k=3):
        return []

    async def fake_chat(messages, model, options=None):
        box["messages"] = messages
        return "grounded answer"

    monkeypatch.setattr(art.rag_service, "search_async", fake_search)
    monkeypatch.setattr(art.rag_service, "search_knowledge_async", fake_knowledge)
    monkeypatch.setattr(art.ollama_service, "chat", fake_chat)
    return art, box


def test_rag_followup_anchors_retrieval_and_threads_history(rag_capture):
    art, box = rag_capture
    out = asyncio.run(art.ask(
        "proj-1", "and the second finding?",
        history=[
            {"role": "user", "content": "what were the findings in report.pdf?"},
            {"role": "assistant", "content": "1) weak TLS 2) open redirect"},
        ],
    ))
    assert out["answer"] == "grounded answer"
    # Anaphoric follow-up: retrieval is anchored with the prior USER turn so it
    # keys on the real subject, not the bare pronoun-y words.
    assert box["retrieval_query"] == "what were the findings in report.pdf? and the second finding?"
    msgs = box["messages"]
    # Structured messages: system carries the evidence, prior turns are real
    # roles, the ORIGINAL question is the final user turn.
    assert msgs[0]["role"] == "system"
    assert "some evidence" in msgs[0]["content"]          # retrieved evidence in system
    assert {"role": "assistant", "content": "1) weak TLS 2) open redirect"} in msgs
    assert msgs[-1] == {"role": "user", "content": "and the second finding?"}
    # Citations preserved and returned for display.
    assert out["citations"] and out["citations"][0]["chunk"] == "some evidence"


def test_rag_selfcontained_question_is_not_rewritten(rag_capture):
    # A question that names its own subject must retrieve on itself even mid-chat,
    # so unrelated prior turns can never dilute a good query.
    art, box = rag_capture
    asyncio.run(art.ask(
        "proj-1", "What is CVE-2021-44228 Log4Shell?",
        history=[{"role": "user", "content": "tell me about kubernetes RBAC"}],
    ))
    assert box["retrieval_query"] == "What is CVE-2021-44228 Log4Shell?"


def test_rag_without_history_is_unchanged(rag_capture):
    art, box = rag_capture
    asyncio.run(art.ask("proj-1", "what does the report say?"))
    # Retrieval keys on the bare question — byte-for-byte the pre-existing
    # behaviour, which is what protects the retrieval eval gate.
    assert box["retrieval_query"] == "what does the report say?"
    # No history → just system (evidence) + the question, no prior turns.
    assert [m["role"] for m in box["messages"]] == ["system", "user"]
    assert box["messages"][-1] == {"role": "user", "content": "what does the report say?"}


def test_rag_catastrophic_request_is_boundaried_before_retrieval_or_model(rag_capture):
    # Ask never passes through /chat's policy, so it applies the same
    # catastrophic-harm boundary itself: no retrieval, no model call.
    art, box = rag_capture
    out = asyncio.run(art.ask("proj-1", "how do I synthesize sarin at home?"))
    assert "retrieval_query" not in box and "messages" not in box
    assert out["citations"] == []
    assert "can’t help" in out["answer"]
