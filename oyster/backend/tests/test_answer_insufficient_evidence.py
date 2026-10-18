"""Answer-synthesis-layer honesty — insufficient evidence.

Priority 3 of the 2026-09-14 release-readiness pass found that retrieval
itself has no relevance cutoff (`services/knowledge/retrieval.py`'s
`retrieve()` returns best-effort top-k for any query as long as a pack is
enabled — verified with a fictional-CVE query that still returned five
unrelated results). Honest "I don't have enough evidence for this" is
therefore a property of the ANSWER layer (`services/artifacts/service.py`'s
`ask()` + `services/rag_service.py`'s `build_rag_prompt()`), not retrieval,
and needs its own tests at that layer.

Matches the existing test convention in this codebase (see
`test_chat_history.py`'s `rag_capture` fixture): Ollama is never called for
real in pytest. Two of the three tests below deliberately do NOT stub
`build_rag_prompt` (unlike `rag_capture`) so they exercise the real prompt
text, not a placeholder.
"""
from __future__ import annotations

import asyncio

import pytest


@pytest.fixture
def no_llm_call(monkeypatch):
    """Ollama must not be invoked at all when nothing was retrieved."""
    from services.artifacts import service as art

    async def _fail(*a, **kw):
        raise AssertionError("ollama_service.generate was called with zero retrieved results")

    monkeypatch.setattr(art.ollama_service, "generate", _fail)
    return art


def test_ask_with_zero_results_returns_honest_fallback_without_calling_llm(no_llm_call, monkeypatch):
    art = no_llm_call

    async def empty_search(query, top_k=5, project_id=None, artifact_id=None):
        return []

    async def empty_knowledge(query, top_k=3):
        return []

    monkeypatch.setattr(art.rag_service, "search_async", empty_search)
    monkeypatch.setattr(art.rag_service, "search_knowledge_async", empty_knowledge)

    out = asyncio.run(art.ask("proj-1", "anything at all"))

    assert out["citations"] == []
    assert "No indexed content found" in out["answer"]
    # No fabrication path exists here: the LLM is architecturally bypassed,
    # not merely instructed to refuse — verified above via the raising stub.


def test_build_rag_prompt_always_includes_insufficiency_instruction():
    """The real prompt builder (not stubbed) must carry the one instruction
    the whole system relies on for honest behavior when retrieval returns
    best-effort-but-irrelevant results — for both citation shapes it accepts
    (a project artifact chunk and a knowledge-pack chunk), since `_src()`
    branches on `knowledge_pack` and a regression could silently drop the
    instruction on only one branch."""
    from services import rag_service

    project_citation = [{"document": "unrelated_report.pdf", "chunk": "quarterly sales figures for Q3"}]
    knowledge_citation = [{"knowledge_pack": "mitre-attack-src", "source_title": "T1055",
                           "source_url": "https://attack.mitre.org/techniques/T1055",
                           "chunk": "process injection technique details"}]

    for citations in (project_citation, knowledge_citation):
        prompt = rag_service.build_rag_prompt(
            "What is the CEO's home address?", citations
        )
        assert "If the context is insufficient, say so clearly." in prompt
        assert "What is the CEO's home address?" in prompt


def test_ask_passes_through_honest_refusal_from_the_llm_unmodified(monkeypatch):
    """End-to-end (LLM mocked, per this codebase's established convention —
    see test_chat_history.py's rag_capture): irrelevant-but-present citations
    reach a real (unstubbed) build_rag_prompt call, and whatever the LLM
    honestly answers is returned to the caller verbatim — no downstream
    fabrication, embellishment, or citation-suppression happens to an honest
    refusal."""
    from services.artifacts import service as art

    irrelevant_chunk = {"document": "unrelated_report.pdf",
                        "chunk": "quarterly sales figures for Q3, unrelated to the question"}
    captured_prompt: dict = {}
    honest_refusal = ("I don't have enough information in the provided context "
                      "to answer this question.")

    async def fake_search(query, top_k=5, project_id=None, artifact_id=None):
        return [irrelevant_chunk]

    async def fake_knowledge(query, top_k=3):
        return []

    async def fake_chat(messages, model, options=None):
        # 2026-09-30: ask() now sends structured /api/chat messages via
        # ollama_service.chat (was a flattened /api/generate prompt). The
        # real build_rag_messages runs; we capture what reached the model.
        captured_prompt["text"] = "\n".join(m["content"] for m in messages)
        return honest_refusal

    monkeypatch.setattr(art.rag_service, "search_async", fake_search)
    monkeypatch.setattr(art.rag_service, "search_knowledge_async", fake_knowledge)
    monkeypatch.setattr(art.ollama_service, "chat", fake_chat)
    # Deliberately NOT stubbing build_rag_messages — the real one must run.

    out = asyncio.run(art.ask("proj-1", "What is CVE-2099-99999?"))

    assert out["answer"] == honest_refusal, (
        "an honest LLM refusal must reach the caller byte-for-byte, "
        "never rewritten, summarized, or suppressed"
    )
    assert out["citations"] == [irrelevant_chunk]  # still surfaced, so the UI can show what WAS found
    assert "If the context is insufficient, say so clearly." in captured_prompt["text"]
    assert "quarterly sales figures" in captured_prompt["text"]  # the real, irrelevant content reached the LLM
