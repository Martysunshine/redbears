"""LLM-based candidate-memory extraction from a single conversation exchange.

Best-effort and defensive: any failure (Ollama unreachable, malformed JSON,
model refusal) returns an empty list rather than raising, so extraction can
never break a chat response. Every candidate the model proposes is re-checked
against the sensitive-content gate before being returned — the prompt asks the
model not to propose secrets, but that instruction is not trusted alone.
"""

from __future__ import annotations

import json
import re

import config
from services import ollama_service

from . import sensitive

_VALID_TYPES = ("fact", "preference", "decision", "instruction", "project_detail")

_EXTRACTION_PROMPT = """You are a memory-extraction assistant for a security operator's AI copilot.
Read the exchange below and identify any LONG-TERM, reusable facts worth remembering for future
conversations: stated preferences, decisions, recurring instructions, project/engagement details,
or durable facts about the operator or their work.

Do NOT extract secrets, passwords, API keys, private keys, tokens, credit card numbers, bank
details, or other credentials, even if present in the text — never propose them as memories.
Do NOT extract one-off/ephemeral questions or trivia, or anything already obvious from context.
If nothing is worth remembering, return an empty array.

Return ONLY a JSON array, no prose, no markdown fences. Each item:
{{"type": "fact"|"preference"|"decision"|"instruction"|"project_detail",
 "subject": "short 3-6 word label", "content": "one self-contained sentence",
 "confidence": 0.0-1.0}}

EXCHANGE:
User: {user_msg}
Assistant: {assistant_msg}

JSON array:"""


def _parse(raw: str) -> list[dict]:
    match = re.search(r"\[.*\]", raw.strip(), re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        t = item.get("type")
        subject = (item.get("subject") or "").strip()
        content = (item.get("content") or "").strip()
        if t not in _VALID_TYPES or not subject or not content:
            continue
        try:
            confidence = float(item.get("confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        out.append({
            "type": t, "subject": subject[:120], "content": content[:500],
            "confidence": max(0.0, min(1.0, confidence)),
        })
    return out


async def extract_candidates(user_msg: str, assistant_msg: str, model: str | None = None) -> list[dict]:
    if not (user_msg or "").strip():
        return []
    prompt = _EXTRACTION_PROMPT.format(
        user_msg=(user_msg or "")[:2000], assistant_msg=(assistant_msg or "")[:2000],
    )
    try:
        raw = await ollama_service.generate(prompt, config.resolve_model(model or config.MEMORY_EXTRACTION_MODEL))
    except Exception:
        return []
    candidates = _parse(raw)
    safe: list[dict] = []
    for c in candidates:
        blocked, _indicators = sensitive.blocks_storage(f"{c['subject']} {c['content']}")
        if blocked:
            continue
        safe.append(c)
    return safe
