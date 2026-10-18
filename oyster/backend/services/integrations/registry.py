"""Singleton registry of integration adapters, for routers/integrations.py and
the investigation workflow to look up by id without importing each module."""
from __future__ import annotations

from services.integrations.base import IntegrationAdapter
from services.integrations.devin import adapter as devin_adapter
from services.integrations.nemotron_reasoning import adapter as nemotron_reasoning_adapter
from services.integrations.opencve import adapter as opencve_adapter
from services.integrations.tavily import adapter as tavily_adapter

ADAPTERS: dict[str, IntegrationAdapter] = {
    nemotron_reasoning_adapter.id: nemotron_reasoning_adapter,
    tavily_adapter.id: tavily_adapter,
    devin_adapter.id: devin_adapter,
    opencve_adapter.id: opencve_adapter,
}


def get(integration_id: str) -> IntegrationAdapter | None:
    return ADAPTERS.get(integration_id)


def all_status() -> list[dict]:
    return [a.status_snapshot() for a in ADAPTERS.values()]
