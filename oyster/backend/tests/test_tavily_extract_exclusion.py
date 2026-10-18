"""Regression test: Tavily's extract() must never pass a Juice Shop
walkthrough URL to the provider, even though /extract takes explicit URLs
(no exclude_domains param) unlike search(). No live Tavily call — the
provider's own request is never reached once urls is filtered to empty."""
from __future__ import annotations

import pytest

import config
from services.integrations.base import IntegrationError
from services.integrations.tavily import TavilyAdapter


@pytest.mark.asyncio
async def test_extract_drops_excluded_domain_urls_before_calling_provider(monkeypatch):
    monkeypatch.setattr(config, "TAVILY_API_KEY", "tvly-test")
    monkeypatch.setattr(config, "TAVILY_EXCLUDE_DOMAINS", ("github.com/juice-shop", "owasp-juice.shop"))
    adapter = TavilyAdapter()

    async def _should_not_be_called(self, *a, **k):
        raise AssertionError("must not call Tavily once every URL was excluded")
    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "post", _should_not_be_called)

    with pytest.raises(IntegrationError):
        await adapter.extract(["https://github.com/juice-shop/juice-shop/wiki/solution"])
