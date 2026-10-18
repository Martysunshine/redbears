"""OpenCVE adapter — read-only CVE catalog lookups for the Security Intel
"Latest intelligence" feed and "Research this CVE" handoff into the
investigation workflow.

Verified against the live OpenAPI v2 schema (2026-10-18):
  GET https://app.opencve.io/api/v2/schema/?format=json
Confirmed paths used here (exact, from that schema — nothing guessed):
  GET /cves                                         ?page,page_size,q
  GET /cves/{cve_id}                                ?include
  GET /cves/{cve_id}/changes                        ?page,page_size
  GET /vendors/{vendor_name}/cves                   ?page,page_size
  GET /vendors/{vendor_name}/products/{product_name}/cves  ?page,page_size
Auth (securitySchemes.OrganizationBearerAuth in the schema):
  Authorization: Bearer opc_org.<token_id>.<secret>   (organisation API token)
Pagination contract (PaginatedApiCveListList): {count, next, previous, results}.
An out-of-range page returns 404 (per docs.opencve.io/api/).

API v1 is documented as deprecated (docs.opencve.io/api/) — not used here.

What the schema does NOT expose (checked, not assumed — documented here so the
feed code never pretends otherwise):
  - No vendor/product/severity query params on GET /cves itself — only `q`
    (free text) plus page/page_size. A true vendor/product filter must go
    through the dedicated /vendors/{..}/cves or /vendors/{..}/products/{..}/cves
    endpoints instead, which is what list_cves() below does when a vendor is
    given.
  - No separate NVD-style "publishedDate"/"lastModifiedDate" fields — ApiCveList
    and ApiCveDetail only define created_at/updated_at (OpenCVE's own catalog
    timestamps). The feed layer (services/intel/opencve_feed.py) derives
    "newly published" vs "recently modified" from those two fields and labels
    them as OpenCVE catalog timestamps, not NVD publication dates.
  - ApiCveDetail's `metrics`/`weaknesses`/`vendors` fields are untyped (`{}`) in
    the schema — drf-spectacular could not infer their shape statically, and no
    credential exists on this machine to observe a real response. The adapter
    passes them through as opaque dicts rather than guessing field names inside
    them; see docs/INVESTIGATION.md for what this means for severity display.

No OPENCVE_API_TOKEN exists on this machine. Exercised only against this real
shape via mocked-transport unit tests — no live call has been made.
"""
from __future__ import annotations

import httpx

import config
from services.integrations.base import (ConnectionCheckResult, IntegrationAdapter,
                                        IntegrationError, IntegrationStatus, mask_secret, sanitize)


class OpenCVEAdapter(IntegrationAdapter):
    id = "opencve"
    label = "OpenCVE"
    role = "Read-only CVE catalog: latest/changed CVEs, vendor/product lookups, change history."
    default_timeout_s = config.OPENCVE_TIMEOUT_S

    def is_configured(self) -> bool:
        return bool(config.OPENCVE_API_TOKEN)

    def _extra_summary(self) -> dict:
        return {
            "base_url": config.OPENCVE_BASE_URL,
            "api_token_shape": mask_secret(config.OPENCVE_API_TOKEN) if config.OPENCVE_API_TOKEN else None,
        }

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {config.OPENCVE_API_TOKEN}"}

    async def _request(self, path: str, params: dict | None = None) -> dict:
        if not self.is_configured():
            raise IntegrationError("OpenCVE is not configured.", status=IntegrationStatus.NOT_CONFIGURED)
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.get(f"{config.OPENCVE_BASE_URL}{path}", headers=self._headers(), params=params)
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"OpenCVE request failed ({type(exc).__name__}).")) from exc
        if resp.status_code == 401:
            raise IntegrationError("OpenCVE rejected the API token (401).", status=IntegrationStatus.UNAVAILABLE)
        if resp.status_code == 403:
            raise IntegrationError("OpenCVE denied access — token lacks the required scope (403).",
                                   status=IntegrationStatus.UNAVAILABLE)
        if resp.status_code == 404:
            raise IntegrationError("Not found.", status=IntegrationStatus.UNAVAILABLE)
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            raise IntegrationError(sanitize(f"OpenCVE rate limit reached (429){f', retry after {retry_after}s' if retry_after else ''}."))
        if resp.status_code != 200:
            raise IntegrationError(sanitize(f"OpenCVE returned HTTP {resp.status_code}: {resp.text}"))
        return resp.json()

    async def _do_check_connection(self) -> ConnectionCheckResult:
        """Cheapest real call that proves the token works: one CVE, page 1."""
        data = await self._request("/cves", params={"page": 1, "page_size": 1})
        count = data.get("count")
        return ConnectionCheckResult(IntegrationStatus.CONNECTED,
                                     f"Connected. Catalog reports {count} total CVE(s).")

    async def list_cves(self, *, q: str | None = None, vendor: str | None = None,
                        product: str | None = None, page: int = 1, page_size: int = 20) -> dict:
        """Bounded pagination: page_size is clamped to OpenCVE's documented
        max of 100. Vendor/product go through the dedicated endpoints — /cves
        itself has no such filter (see module docstring)."""
        page_size = max(1, min(page_size, 100))
        params = {"page": page, "page_size": page_size}
        if vendor and product:
            return await self._request(f"/vendors/{vendor}/products/{product}/cves", params=params)
        if vendor:
            return await self._request(f"/vendors/{vendor}/cves", params=params)
        if q:
            params["q"] = q
        return await self._request("/cves", params=params)

    async def get_cve(self, cve_id: str) -> dict:
        return await self._request(f"/cves/{cve_id}")

    async def get_changes(self, cve_id: str, *, page: int = 1, page_size: int = 20) -> dict:
        page_size = max(1, min(page_size, 100))
        return await self._request(f"/cves/{cve_id}/changes", params={"page": page, "page_size": page_size})


adapter = OpenCVEAdapter()
