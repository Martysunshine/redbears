"""MCP resources — read-only, source-backed context a client can subscribe to.

Resources never mutate and never cross the caller's boundary: the knowledge
resources expose the same indexed packs that back every answer, and the project
resource exposes only projects the authenticated caller may see. Each read is
authorized through the same identity/project machinery as a tool call.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .identity import Identity

_RESOURCES = [
    {
        "uri": "oyster://knowledge/sources",
        "name": "Indexed knowledge sources",
        "description": "The enabled, source-attributed knowledge packs that back every answer.",
        "mimeType": "application/json",
    },
    {
        "uri": "oyster://knowledge/stats",
        "name": "Knowledge base statistics",
        "description": "Counts of indexed knowledge chunks and packs (no content).",
        "mimeType": "application/json",
    },
    {
        "uri": "oyster://projects",
        "name": "My projects",
        "description": "Projects the authenticated caller is authorized to see.",
        "mimeType": "application/json",
    },
]


def list_resources() -> list[dict]:
    return list(_RESOURCES)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def read_resource(identity: Identity, uri: str) -> dict | None:
    """Return an MCP resource-contents dict, or None if unknown."""
    if uri == "oyster://knowledge/sources":
        from services.knowledge import store as k_store
        meta = k_store.pack_meta_map()
        enabled = set(k_store.enabled_pack_ids())
        payload = {
            "retrieved_at": _now(),
            "sources": [
                {"pack_id": pid, "title": m.get("title"), "publisher": m.get("security_domain"),
                 "licence": m.get("licence"), "trust_level": m.get("trust_level"),
                 "version": m.get("version"), "chunk_count": m.get("chunk_count")}
                for pid, m in sorted(meta.items()) if pid in enabled
            ],
        }
        return _text(uri, payload)
    if uri == "oyster://knowledge/stats":
        from services.knowledge import store as k_store
        meta = k_store.pack_meta_map()
        enabled = set(k_store.enabled_pack_ids())
        total_chunks = sum(int(m.get("chunk_count") or 0)
                           for pid, m in meta.items() if pid in enabled)
        payload = {"retrieved_at": _now(), "enabled_packs": len(enabled),
                   "indexed_chunks": total_chunks,
                   "note": "Indexed, searchable, source-attributed chunks — not model training data."}
        return _text(uri, payload)
    if uri == "oyster://projects":
        from services import project_service
        projects = project_service.list_projects_for(identity.oyster)
        payload = {"retrieved_at": _now(),
                   "projects": [{"id": p.get("id"), "name": p.get("name")} for p in projects]}
        return _text(uri, payload)
    return None


def _text(uri: str, payload: dict) -> dict:
    return {"contents": [{"uri": uri, "mimeType": "application/json",
                          "text": json.dumps(payload, ensure_ascii=False, indent=2)}]}
