"""Regression coverage for the demonstrated Log4Shell identifier error (see
oyster/docs/AI_HANDOFF.md, 2026-10-14): plain /chat answered "What is the CVE
identifier of the Log4Shell vulnerability?" with CVE-2021-45046 (the follow-up
DoS CVE) instead of the correct CVE-2021-44228, because neither existing
evidence gate covers a question that names a vulnerability WITHOUT a literal
identifier. These tests are fast and deterministic — no network, no model —
and pin the INTEGRATION behaviour: that /chat grounds identifier claims in
retrieved/local-store evidence via the system prompt, instead of letting the
small model answer an identifier question from (sometimes wrong) memory.

Also covers the pre-existing evidence-field bug this fix uncovered: the
named-tool verification gate checked "title"/"content"/"document"/"source_url"
but never "chunk" — the field that actually holds the retrieved passage text —
so a subject genuinely documented in a chunk's body could still be reported as
unverifiable.
"""
from __future__ import annotations

from typing import AsyncGenerator

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from services.chat_policy import identifier_ask_subject
from services.knowledge.vulnerabilities import identity as vuln_identity


# ── category: pure function — identifier_ask_subject ────────────────────────

@pytest.mark.parametrize("prompt,expected", [
    ("What is the CVE identifier of the Log4Shell vulnerability?", "Log4Shell"),
    ("Which CVE covers the Heartbleed bug?", "Heartbleed"),
    ("What CVE number is assigned to Shellshock?", "Shellshock"),
    ("What's the CVE id for EternalBlue?", "EternalBlue"),
])
def test_identifier_ask_subject_extracts_the_name(prompt, expected):
    assert identifier_ask_subject(prompt) == expected


@pytest.mark.parametrize("prompt", [
    "tell me about CVE-2021-44228",           # literal ID already present
    "explain how TLS works",                  # not an identifier question
    "what is a buffer overflow?",
    "How's it going?",
])
def test_identifier_ask_subject_is_none_when_not_a_name_ask(prompt):
    assert identifier_ask_subject(prompt) is None


# ── category: literal-identifier extraction (reused building block) ────────

def test_find_identifiers_extracts_literal_cve_from_prompt():
    ids = vuln_identity.find_identifiers("In one sentence, what is CVE-2021-44228?")
    assert ids["cve"] == ["CVE-2021-44228"]


def test_find_identifiers_empty_for_name_only_question():
    ids = vuln_identity.find_identifiers("What is the CVE identifier of Log4Shell?")
    assert ids["cve"] == []


# ── category: end-to-end /chat grounding (captured system prompt) ──────────

@pytest.fixture
def captured(monkeypatch):
    from routers import chat as chat_router
    from services import chat_queue, entitlements, ollama_service, project_service, user_prefs
    from services.auth_service import oauth2_scheme, require_chat_access

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
    monkeypatch.setattr(chat_queue, "queue", chat_queue.ChatQueue())

    app = FastAPI()
    app.include_router(chat_router.router)

    holder = {"identity": {"tier": "admin", "email": "op@x", "sub": "op-1"}}
    app.dependency_overrides[require_chat_access] = lambda: holder["identity"]
    app.dependency_overrides[oauth2_scheme] = lambda: "tok"

    client = TestClient(app)
    return client, box, holder


def _system_prompt(box: dict) -> str:
    return next(m["content"] for m in box["messages"] if m["role"] == "system")


def test_literal_known_cve_is_grounded_from_local_store(captured, monkeypatch):
    """A literal CVE already in Oyster's local vulnerability store must inject
    its authoritative facts into the system prompt, and must NOT fall through
    to the generic (weak, semantic-only) named-tool verification gate."""
    from routers import chat as chat_router

    rec = {"cve_id": "CVE-2021-44228", "description": "Apache Log4j2 JNDI RCE.",
          "cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL", "kev_listed": 1}
    monkeypatch.setattr(chat_router.vuln_store, "get_vulnerability", lambda cve_id: rec)

    client, box, _ = captured
    r = client.post("/chat", json={"prompt": "In one sentence, what is CVE-2021-44228?"})
    assert r.status_code == 200, r.text
    sp = _system_prompt(box)
    assert "VERIFIED RECORD" in sp
    assert "CVE-2021-44228" in sp and "CRITICAL" in sp
    # Must not have been swallowed by the generic "can't verify" boundary —
    # the response must still reach the model (fake_stream captured messages).
    assert box["messages"][-1]["content"] == "In one sentence, what is CVE-2021-44228?"


def test_literal_unknown_cve_states_not_in_local_store(captured, monkeypatch):
    from routers import chat as chat_router
    monkeypatch.setattr(chat_router.vuln_store, "get_vulnerability", lambda cve_id: None)

    client, box, _ = captured
    r = client.post("/chat", json={"prompt": "What is CVE-2099-99999?"})
    assert r.status_code == 200, r.text
    sp = _system_prompt(box)
    assert "not in Oyster's local" in sp
    assert "CVE-2099-99999" in sp


def test_name_ask_with_single_supporting_source_grounds_the_correct_id(captured, monkeypatch):
    """The demonstrated failure: a name-only identifier question (no literal
    CVE token) must be grounded in retrieved evidence, not answered from the
    model's own (here: wrong) memory."""
    from routers import chat as chat_router

    async def fake_search(query, top_k=6, **kw):
        return [{"chunk": "Hunting for Log4Shell: detects exploitation of CVE-2021-44228.",
                "source_title": "hunting_for_log4shell.yml", "document": "hunting_for_log4shell.yml"}]
    monkeypatch.setattr(chat_router.rag_service, "search_knowledge_async", fake_search)
    monkeypatch.setattr(chat_router.vuln_store, "get_vulnerability",
                        lambda cve_id: {"cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL"})

    client, box, _ = captured
    r = client.post("/chat", json={
        "prompt": "What is the CVE identifier of the Log4Shell vulnerability? Answer in one line."})
    assert r.status_code == 200, r.text
    sp = _system_prompt(box)
    assert "CVE-2021-44228" in sp
    assert "CVE-2021-45046" not in sp  # the wrong ID must never be the grounded fact


def test_name_ask_with_no_evidence_says_cannot_confirm(captured, monkeypatch):
    from routers import chat as chat_router

    async def empty_search(query, top_k=6, **kw):
        return []
    monkeypatch.setattr(chat_router.rag_service, "search_knowledge_async", empty_search)

    client, box, _ = captured
    # "Nullshock" (not CamelCase) isolates the name-ask path from the separate
    # named-tool CamelCase gate, which would otherwise short-circuit first.
    r = client.post("/chat", json={
        "prompt": "What is the CVE identifier of the Nullshock vulnerability?"})
    assert r.status_code == 200, r.text
    sp = _system_prompt(box)
    assert "does not confirm" in sp
    assert "Nullshock" in sp


def test_name_ask_with_conflicting_evidence_lists_both_not_one(captured, monkeypatch):
    """Two distinct CVE ids both genuinely co-occurring with the asked name in
    retrieved evidence must be reported as conflicting, never silently resolved
    to a single (possibly wrong) pick."""
    from routers import chat as chat_router

    async def fake_search(query, top_k=6, **kw):
        return [
            {"chunk": "Log4Shell refers to CVE-2021-44228, the original JNDI RCE.",
            "source_title": "doc-a", "document": "doc-a"},
            {"chunk": "Log4Shell follow-up issue CVE-2021-45046 was a separate DoS flaw.",
            "source_title": "doc-b", "document": "doc-b"},
        ]
    monkeypatch.setattr(chat_router.rag_service, "search_knowledge_async", fake_search)

    client, box, _ = captured
    r = client.post("/chat", json={
        "prompt": "What is the CVE identifier of the Log4Shell vulnerability?"})
    assert r.status_code == 200, r.text
    sp = _system_prompt(box)
    assert "CONFLICTING" in sp
    assert "CVE-2021-44228" in sp and "CVE-2021-45046" in sp


def test_evidence_check_now_reads_the_actual_chunk_text(captured, monkeypatch):
    """Regression for the field-name bug: a subject that is genuinely
    documented in a retrieved passage's BODY (the "chunk" field) — but not in
    its filename or source_url — must count as supported, not trigger the
    generic "can't verify" boundary."""
    from routers import chat as chat_router

    async def fake_search(query, top_k=3, **kw):
        return [{"chunk": "FooScanner is a documented static-analysis tool used for...",
                "document": "generic-notes.md", "source_url": "https://example.com/notes"}]
    monkeypatch.setattr(chat_router.rag_service, "search_knowledge_async", fake_search)

    client, box, _ = captured
    r = client.post("/chat", json={"prompt": "What does the FooScanner tool do?"})
    assert r.status_code == 200, r.text
    # Supported by chunk text -> must reach the model, not the boundary text.
    assert box["messages"][-1]["content"] == "What does the FooScanner tool do?"
    full_text = " ".join(m["content"] for m in box["messages"])
    assert "I can't verify" not in full_text
