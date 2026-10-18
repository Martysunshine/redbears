"""Tavily adapter — current web research, source extraction and follow-up
search for the investigation workflow's Research stage.

Verified against docs.tavily.com (2026-10-18):
  POST https://api.tavily.com/search   {query, max_results, include_raw_content,
                                        exclude_domains, time_range, ...}
                                        -> {results:[{url,title,content,score,
                                            raw_content,published_date}], ...}
  POST https://api.tavily.com/extract  {urls, extract_depth, format}
                                        -> {results:[{url,raw_content}], failed_results:[...]}
  Auth: Authorization: Bearer tvly-...

No Tavily credential exists on this machine. Exercised only against this real
shape via mocked-transport unit tests — no live call has been made.

Juice Shop walkthroughs/solutions are excluded from every search (brief §5):
`config.TAVILY_EXCLUDE_DOMAINS` is always merged into `exclude_domains`, never
optional. Oyster's own prior model knowledge of Juice Shop cannot be excluded
by this adapter — that caveat is surfaced in the investigation record, not
silently assumed away.
"""
from __future__ import annotations

import time

import httpx

import config
from services.integrations.base import (ConnectionCheckResult, IntegrationAdapter,
                                        IntegrationError, IntegrationStatus, mask_secret, sanitize)


class SearchResult:
    __slots__ = ("url", "title", "content", "score", "raw_content", "published_date", "retrieved_at")

    def __init__(self, url: str, title: str, content: str, score: float,
                raw_content: str | None, published_date: str | None):
        self.url = url
        self.title = title
        self.content = content          # retrieved passage (snippet)
        self.score = score
        self.raw_content = raw_content  # full page text, when requested
        self.published_date = published_date
        self.retrieved_at = time.time()  # retrieval timestamp — required by brief §3

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__slots__}


class TavilyAdapter(IntegrationAdapter):
    id = "tavily"
    label = "Tavily"
    role = "Current web research: search, source extraction and gap-directed follow-up searches."
    default_timeout_s = config.TAVILY_TIMEOUT_S

    def is_configured(self) -> bool:
        return bool(config.TAVILY_API_KEY)

    def _extra_summary(self) -> dict:
        return {
            "base_url": config.TAVILY_BASE_URL,
            "api_key_shape": mask_secret(config.TAVILY_API_KEY) if config.TAVILY_API_KEY else None,
            "excluded_domains": list(config.TAVILY_EXCLUDE_DOMAINS),
        }

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {config.TAVILY_API_KEY}", "Content-Type": "application/json"}

    async def _do_check_connection(self) -> ConnectionCheckResult:
        """A minimal real search (max_results=1) — Tavily has no bare health
        endpoint, so this is the cheapest real call that proves the key works."""
        try:
            results, meta = await self.search("tavily api connectivity check", max_results=1)
        except IntegrationError:
            raise
        return ConnectionCheckResult(IntegrationStatus.CONNECTED,
                                     f"Connected. Search returned {len(results)} result(s) "
                                     f"in {meta.get('response_time_s', '?')}s.")

    async def search(self, query: str, *, max_results: int = 5, search_depth: str = "basic",
                     include_raw_content: bool = False, time_range: str | None = None,
                     extra_exclude_domains: list[str] | None = None,
                     ) -> tuple[list[SearchResult], dict]:
        if not self.is_configured():
            raise IntegrationError("Tavily is not configured.", status=IntegrationStatus.NOT_CONFIGURED)
        exclude = list(config.TAVILY_EXCLUDE_DOMAINS) + list(extra_exclude_domains or [])
        body: dict = {"query": query, "max_results": max_results, "search_depth": search_depth,
                     "include_raw_content": include_raw_content, "exclude_domains": exclude}
        if time_range:
            body["time_range"] = time_range
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.post(f"{config.TAVILY_BASE_URL}/search", headers=self._headers(), json=body)
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Tavily search failed ({type(exc).__name__}).")) from exc
        if resp.status_code == 401:
            raise IntegrationError("Tavily rejected the API key (401).", status=IntegrationStatus.UNAVAILABLE)
        if resp.status_code == 429:
            raise IntegrationError("Tavily rate limit reached (429).")
        if resp.status_code != 200:
            raise IntegrationError(sanitize(f"Tavily returned HTTP {resp.status_code}: {resp.text}"))
        data = resp.json()
        results = [SearchResult(r.get("url", ""), r.get("title", ""), r.get("content", ""),
                                float(r.get("score", 0.0)), r.get("raw_content"), r.get("published_date"))
                  for r in data.get("results", [])]
        return results, {"response_time_s": data.get("response_time"), "request_id": data.get("request_id")}

    async def extract(self, urls: list[str], *, query: str | None = None) -> tuple[list[dict], list[dict]]:
        """Returns (results, failed_results); both are reported — a 200 can
        still carry per-URL failures."""
        if not self.is_configured():
            raise IntegrationError("Tavily is not configured.", status=IntegrationStatus.NOT_CONFIGURED)
        body: dict = {"urls": urls[:20], "extract_depth": "basic", "format": "markdown"}
        if query:
            body["query"] = query
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.post(f"{config.TAVILY_BASE_URL}/extract", headers=self._headers(), json=body)
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Tavily extract failed ({type(exc).__name__}).")) from exc
        if resp.status_code != 200:
            raise IntegrationError(sanitize(f"Tavily returned HTTP {resp.status_code}: {resp.text}"))
        data = resp.json()
        now = time.time()
        results = [{**r, "retrieved_at": now} for r in data.get("results", [])]
        return results, data.get("failed_results", [])


adapter = TavilyAdapter()
