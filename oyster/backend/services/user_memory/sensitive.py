"""Hard gate: never persist a memory candidate that looks like a secret.

Reuses the shared indicator scanner (``services/media/redact.py``) so the same
patterns (AWS/GitHub/Slack/OpenAI/Google keys, JWTs, private keys, bearer
tokens, generic password assignments, credit-card numbers with a Luhn check,
SSNs, IBANs) are enforced everywhere content might be auto-persisted — memory,
knowledge connectors, dataset ingestion, and the training pipeline.

This is defense in depth, not the only line of defense: the extraction prompt
also instructs the model never to propose secrets as memories.
"""

from __future__ import annotations

from services.media.redact import contains_sensitive, scan


def blocks_storage(text: str) -> tuple[bool, list[dict]]:
    """Return (blocked, indicators). Blocked content must never be auto-saved."""
    indicators = scan(text)
    return (len(indicators) > 0, indicators)


def is_safe(text: str) -> bool:
    return not contains_sensitive(text)
