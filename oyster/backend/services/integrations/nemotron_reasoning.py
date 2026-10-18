"""Nemotron REASONING adapter — a generative chat model reached through
NVIDIA/Nebius Token Factory's OpenAI-compatible API, used for research
planning, evidence analysis and investigation coordination.

This is deliberately a different class/module from services/rerank_service.py
(the Nemotron cross-encoder RERANKER). They share a provider family name only;
nothing else is shared, and nothing here is ever described as a reranker, nor
is the reranker ever described as doing reasoning.

Verified against docs.tokenfactory.nebius.com (2026-10-18):
  Base URL   https://api.tokenfactory.nebius.com/v1
  Auth       Authorization: Bearer <NEBIUS_API_KEY>
  Models     GET  {base}/models                 -> {"data": [{"id": ...}]}
  Chat       POST {base}/chat/completions        (OpenAI-compatible)
  Structured output: response_format={"type": "json_schema", "json_schema": {...}}

No Nebius credential exists on this machine. This adapter is exercised in this
implementation ONLY against that real API shape via unit tests with a mocked
transport — there is no live-verified call. It must not be presented as
"connected" without a real 200 from GET /models.
"""
from __future__ import annotations

import json

import httpx

import config
from services.integrations.base import (ConnectionCheckResult, IntegrationAdapter,
                                        IntegrationError, IntegrationStatus, mask_secret, sanitize)


class NemotronReasoningAdapter(IntegrationAdapter):
    id = "nemotron_reasoning"
    label = "Nemotron Reasoning (Nebius Token Factory)"
    role = "Research planning, evidence analysis and investigation coordination — a generative chat model, not the evidence reranker."
    default_timeout_s = config.NEBIUS_TIMEOUT_S

    def is_configured(self) -> bool:
        return bool(config.NEBIUS_API_KEY and config.NEBIUS_TOKEN_FACTORY_BASE_URL)

    def _extra_summary(self) -> dict:
        return {
            "base_url": config.NEBIUS_TOKEN_FACTORY_BASE_URL,
            "model": config.NEMOTRON_REASONING_MODEL or None,
            "api_key_shape": mask_secret(config.NEBIUS_API_KEY) if config.NEBIUS_API_KEY else None,
        }

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {config.NEBIUS_API_KEY}", "Content-Type": "application/json"}

    async def _do_check_connection(self) -> ConnectionCheckResult:
        """GET /models — cheap, real, and tells us whether the configured
        NEMOTRON_REASONING_MODEL id actually exists for this account (if set),
        which a 200-but-wrong-model response from /chat/completions would not."""
        url = f"{config.NEBIUS_TOKEN_FACTORY_BASE_URL.rstrip('/')}/models"
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.get(url, headers=self._headers())
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Could not reach Nebius Token Factory ({type(exc).__name__}).")) from exc
        if resp.status_code == 401:
            raise IntegrationError("Nebius rejected the API key (401 Unauthorized).",
                                   status=IntegrationStatus.UNAVAILABLE)
        if resp.status_code != 200:
            raise IntegrationError(f"Nebius returned HTTP {resp.status_code}.")
        try:
            ids = {m.get("id") for m in resp.json().get("data", [])}
        except (ValueError, AttributeError):
            raise IntegrationError("Nebius /models returned an unexpected shape.")
        if config.NEMOTRON_REASONING_MODEL and config.NEMOTRON_REASONING_MODEL not in ids:
            return ConnectionCheckResult(
                IntegrationStatus.UNAVAILABLE,
                f"Connected to Nebius, but configured model {config.NEMOTRON_REASONING_MODEL!r} "
                "is not in this account's model list.")
        return ConnectionCheckResult(IntegrationStatus.CONNECTED,
                                     f"Connected. {len(ids)} model(s) available.",
                                     model=config.NEMOTRON_REASONING_MODEL or None)

    async def structured_completion(self, *, system: str, user: str, schema: dict,
                                    schema_name: str = "decision_summary") -> dict:
        """One chat completion constrained to `schema` via response_format
        json_schema. Raises IntegrationError on any failure — callers (the
        investigation workflow) must treat that as "step produced no decision
        summary", never fabricate one locally."""
        if not self.is_configured():
            raise IntegrationError("Nemotron reasoning is not configured.",
                                   status=IntegrationStatus.NOT_CONFIGURED)
        if not config.NEMOTRON_REASONING_MODEL:
            raise IntegrationError(
                "No NEMOTRON_REASONING_MODEL is set. Run a connection test to list this "
                "account's available models, then set it explicitly — this adapter never "
                "guesses a model id.")
        url = f"{config.NEBIUS_TOKEN_FACTORY_BASE_URL.rstrip('/')}/chat/completions"
        body = {
            "model": config.NEMOTRON_REASONING_MODEL,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": schema_name, "schema": schema, "strict": True}},
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.post(url, headers=self._headers(), json=body)
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Nebius request failed ({type(exc).__name__}).")) from exc
        if resp.status_code != 200:
            raise IntegrationError(sanitize(f"Nebius returned HTTP {resp.status_code}: {resp.text}"))
        try:
            msg = resp.json()["choices"][0]["message"]
        except (KeyError, IndexError, ValueError):
            raise IntegrationError("Nebius response did not contain a completion.")
        if msg.get("refusal"):
            raise IntegrationError(sanitize(f"Model refused: {msg['refusal']}"))
        try:
            return json.loads(msg["content"])
        except (KeyError, ValueError):
            raise IntegrationError("Nebius response content was not valid JSON for the requested schema.")


adapter = NemotronReasoningAdapter()
