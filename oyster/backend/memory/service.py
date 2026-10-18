from __future__ import annotations

from . import store


def store_note(
    key: str,
    value: str,
    tags: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    return store.store_memory("note", key, value, tags, session_id)


def store_finding(key: str, detail: str, session_id: str | None = None) -> dict:
    return store.store_memory("finding", key, detail, session_id=session_id)


def recall(
    query: str | None = None,
    type: str | None = None,
    session_id: str | None = None,
    limit: int = 20,
) -> list[dict]:
    return store.recall_memories(query=query, type=type, session_id=session_id, limit=limit)


def log_scan(target: str, tool: str, result: dict, session_id: str | None = None) -> dict:
    return store.store_scan_result(target, tool, result, session_id)


def get_scan_history(target: str, limit: int = 10) -> list[dict]:
    return store.get_scan_history(target, limit)


def add_to_attack_surface(
    target: str,
    component_type: str,
    detail: str,
    severity: str = "info",
    session_id: str | None = None,
) -> dict:
    return store.store_attack_surface(target, component_type, detail, severity, session_id)


def get_attack_surface(target: str | None = None) -> list[dict]:
    return store.get_attack_surface(target)


def clear_session(session_id: str) -> int:
    return store.clear_session(session_id)


def stats() -> dict:
    return store.get_stats()


def summarize_context(target: str | None = None) -> str:
    surface = get_attack_surface(target)
    history = get_scan_history(target) if target else []
    notes = recall(query=target, limit=10) if target else recall(limit=10)

    parts: list[str] = []
    if target:
        parts.append(f"Context for target: {target}")

    if surface:
        parts.append(f"\nAttack Surface ({len(surface)} entries):")
        for s in surface[:10]:
            parts.append(f"  [{s['severity'].upper()}] {s['component_type']}: {s['detail'][:120]}")

    if history:
        parts.append(f"\nRecent Scans ({len(history)}):")
        for h in history[:5]:
            parts.append(f"  {h['created_at']}: {h['tool']} on {h['target']}")

    if notes:
        parts.append(f"\nStored Notes ({len(notes)}):")
        for n in notes[:5]:
            parts.append(f"  [{n['type']}] {n['key']}: {n['value'][:120]}")

    return "\n".join(parts) if parts else "No memory context found."
