"""Knowledge-pack follow-ups must carry conversation history into generation.

Regression guard for the 2026-10-07 gap: build_knowledge_messages dropped all
history, so a Knowledge-pack follow-up ("how do I detect that?") lost its
subject. Mirrors the artifact/RAG path's history wiring.
"""
from __future__ import annotations

from services import rag_service

CITES = [{"document": "Kerberoasting", "chunk": "SPN ticket cracking", "source_title": "AD",
          "knowledge_pack": "mitre-attack", "source_url": "https://x"}]


def test_knowledge_messages_without_history_is_system_then_user():
    msgs = rag_service.build_knowledge_messages("What is Kerberoasting?", CITES)
    assert [m["role"] for m in msgs] == ["system", "user"]
    assert msgs[-1]["content"] == "What is Kerberoasting?"
    assert "REFERENCES:" in msgs[0]["content"]


def test_knowledge_messages_inserts_prior_turns_as_real_roles():
    history = [
        {"role": "user", "content": "What is Kerberoasting in Active Directory?"},
        {"role": "assistant", "content": "It requests and cracks service-account SPN tickets."},
    ]
    msgs = rag_service.build_knowledge_messages(
        "How do I detect that technique?", CITES, history=history)
    roles = [m["role"] for m in msgs]
    # system, then the two prior turns in order, then the current question
    assert roles == ["system", "user", "assistant", "user"]
    assert "Kerberoasting" in msgs[1]["content"]          # subject reaches the model
    assert msgs[-1]["content"] == "How do I detect that technique?"


def test_knowledge_messages_history_empty_list_is_back_compatible():
    msgs = rag_service.build_knowledge_messages("Q?", CITES, history=[])
    assert [m["role"] for m in msgs] == ["system", "user"]
