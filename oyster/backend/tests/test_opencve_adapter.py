"""Mocked-transport unit tests for the OpenCVE adapter — no live network call,
no OPENCVE_API_TOKEN exists on this machine. These verify the adapter's
request shape and status handling against the real documented contract (see
services/integrations/opencve.py's docstring), not against OpenCVE itself.
"""
from __future__ import annotations

import httpx
import pytest

import config
from services.integrations.base import IntegrationError, IntegrationStatus
from services.integrations.opencve import OpenCVEAdapter


class _FakeResponse:
    def __init__(self, status_code: int, json_body: dict | None = None, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self._json = json_body or {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._json


@pytest.fixture(autouse=True)
def _reset_config(monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "opc_org.test.secret")
    monkeypatch.setattr(config, "OPENCVE_BASE_URL", "https://app.opencve.io/api/v2")


def test_is_configured_false_without_token(monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "")
    adapter = OpenCVEAdapter()
    assert adapter.is_configured() is False


@pytest.mark.asyncio
async def test_check_connection_not_configured_makes_no_call(monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "")
    adapter = OpenCVEAdapter()

    async def _should_not_be_called(*a, **k):
        raise AssertionError("must not make a network call when not configured")
    monkeypatch.setattr(httpx.AsyncClient, "get", _should_not_be_called)

    result = await adapter.check_connection()
    assert result.status == IntegrationStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_check_connection_success(monkeypatch):
    adapter = OpenCVEAdapter()

    async def _get(self, url, headers=None, params=None):
        assert headers["Authorization"] == "Bearer opc_org.test.secret"
        assert url.endswith("/cves")
        assert params == {"page": 1, "page_size": 1}
        return _FakeResponse(200, {"count": 42, "next": None, "previous": None, "results": []})
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    result = await adapter.check_connection()
    assert result.status == IntegrationStatus.CONNECTED
    assert "42" in result.detail


@pytest.mark.asyncio
async def test_check_connection_rejects_bad_token(monkeypatch):
    adapter = OpenCVEAdapter()

    async def _get(self, url, headers=None, params=None):
        return _FakeResponse(401, text="invalid_token")
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    result = await adapter.check_connection()
    assert result.status == IntegrationStatus.UNAVAILABLE
    assert "401" in result.detail
    # must never echo the token itself
    assert "test.secret" not in result.detail


@pytest.mark.asyncio
async def test_list_cves_uses_vendor_product_endpoint_when_both_given(monkeypatch):
    adapter = OpenCVEAdapter()
    seen = {}

    async def _get(self, url, headers=None, params=None):
        seen["url"] = url
        seen["params"] = params
        return _FakeResponse(200, {"count": 1, "next": None, "previous": None, "results": []})
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    await adapter.list_cves(vendor="acme", product="widget", page=2, page_size=10)
    assert seen["url"].endswith("/vendors/acme/products/widget/cves")
    assert seen["params"] == {"page": 2, "page_size": 10}


@pytest.mark.asyncio
async def test_list_cves_clamps_page_size_to_documented_max(monkeypatch):
    adapter = OpenCVEAdapter()
    seen = {}

    async def _get(self, url, headers=None, params=None):
        seen["params"] = params
        return _FakeResponse(200, {"count": 0, "next": None, "previous": None, "results": []})
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    await adapter.list_cves(page_size=500)
    assert seen["params"]["page_size"] == 100


@pytest.mark.asyncio
async def test_list_cves_rate_limited_raises_integration_error(monkeypatch):
    adapter = OpenCVEAdapter()

    async def _get(self, url, headers=None, params=None):
        return _FakeResponse(429, headers={"Retry-After": "30"})
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    with pytest.raises(IntegrationError, match="429"):
        await adapter.list_cves()


@pytest.mark.asyncio
async def test_get_cve_path(monkeypatch):
    adapter = OpenCVEAdapter()
    seen = {}

    async def _get(self, url, headers=None, params=None):
        seen["url"] = url
        return _FakeResponse(200, {"cve_id": "CVE-2024-0001"})
    monkeypatch.setattr(httpx.AsyncClient, "get", _get)

    data = await adapter.get_cve("CVE-2024-0001")
    assert seen["url"].endswith("/cves/CVE-2024-0001")
    assert data["cve_id"] == "CVE-2024-0001"
