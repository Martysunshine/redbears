"""Integrations settings — status, connection test, credential configure/clear
for Nemotron reasoning, Tavily and Devin. Admin-gated (mounted under
PROTECTED_ROUTERS in routers/__init__.py: shared, instance-wide credentials,
exactly like the rest of that tier).

Never returns a credential value — only a masked shape (see
services.integrations.base.mask_secret) or whether one is set at all.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.integrations import credential_store, registry

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("")
async def list_integrations():
    """Status snapshot for every integration (no network call) — what the
    settings panel renders on open."""
    return {"integrations": registry.all_status()}


@router.post("/{integration_id}/test")
async def test_connection(integration_id: str):
    """Make ONE real connection check now. Never returns "connected" without
    an actual successful provider response in this call."""
    adapter = registry.get(integration_id)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Unknown integration {integration_id!r}")
    result = await adapter.check_connection()
    return {"id": integration_id, "status": result.status.value, "detail": result.detail,
            "latency_ms": result.latency_ms, "checked_at": result.checked_at}


class SetCredentialsRequest(BaseModel):
    fields: dict[str, str] = Field(default_factory=dict)


@router.post("/{integration_id}/credentials")
async def set_credentials(integration_id: str, request: SetCredentialsRequest):
    """Runtime-only override (services/integrations/credential_store.py) — held
    in this process's memory, never written to disk, never echoed back."""
    if registry.get(integration_id) is None:
        raise HTTPException(status_code=404, detail=f"Unknown integration {integration_id!r}")
    try:
        credential_store.set_credentials(integration_id, request.fields)
    except credential_store.UnknownField as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": integration_id, **registry.get(integration_id).status_snapshot()}


@router.delete("/{integration_id}/credentials")
async def disconnect(integration_id: str):
    adapter = registry.get(integration_id)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Unknown integration {integration_id!r}")
    credential_store.clear_credentials(integration_id)
    adapter._last_check = None  # force a real re-check next time, never report stale "connected"
    return {"id": integration_id, **adapter.status_snapshot()}
