"""Devin adapter — code investigation and proposed fixes for VERIFIED findings
only, via a human-reviewed handoff (routers/investigation.py "Investigate with
Devin"). This module never starts a session on its own; every call here is
invoked by an explicit user action on one specific finding.

Verified against docs.devin.ai (2026-10-18):
  Current API is v3 (legacy v1 apk_/apk_user_ keys are deprecated, NOT used):
    POST /v3/organizations/{org_id}/sessions         {prompt, title, tags, repos, ...}
      -> {session_id, status, url, pull_requests: [{pr_url, pr_state}], ...}
    GET  /v3/organizations/{org_id}/sessions/{id}     -> adds status_detail
  Auth: Authorization: Bearer <cog_... key>
  Base URL: https://api.devin.ai

No Devin credential, org id, or allowed repository exists on this machine.
DEVIN_ALLOWED_REPOS is empty by default, which disables session creation
regardless of credentials — there is no default repository Devin may touch.
Exercised only via mocked-transport unit tests.
"""
from __future__ import annotations

import httpx

import config
from services.integrations.base import (ConnectionCheckResult, IntegrationAdapter,
                                        IntegrationError, IntegrationStatus, mask_secret, sanitize)


class DevinAdapter(IntegrationAdapter):
    id = "devin"
    label = "Devin"
    role = "Investigates a verified finding's source and proposes a fix as a branch/PR in an explicitly allowed repository."
    default_timeout_s = config.DEVIN_TIMEOUT_S

    def is_configured(self) -> bool:
        return bool(config.DEVIN_API_KEY and config.DEVIN_ORG_ID)

    def _extra_summary(self) -> dict:
        return {
            "base_url": config.DEVIN_BASE_URL,
            "org_id_set": bool(config.DEVIN_ORG_ID),
            "api_key_shape": mask_secret(config.DEVIN_API_KEY) if config.DEVIN_API_KEY else None,
            "allowed_repos": list(config.DEVIN_ALLOWED_REPOS),
        }

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {config.DEVIN_API_KEY}", "Content-Type": "application/json"}

    async def _do_check_connection(self) -> ConnectionCheckResult:
        """Devin's API has no bare health/whoami route in the public docs
        reviewed for this implementation, so the connection check lists
        sessions (page_size=1) — a cheap, real, read-only v3 call that proves
        the key and org id are both valid without creating anything."""
        url = f"{config.DEVIN_BASE_URL}/v3/organizations/{config.DEVIN_ORG_ID}/sessions"
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.get(url, headers=self._headers(), params={"limit": 1})
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Could not reach Devin ({type(exc).__name__}).")) from exc
        if resp.status_code == 401:
            raise IntegrationError("Devin rejected the API key (401).", status=IntegrationStatus.UNAVAILABLE)
        if resp.status_code == 403:
            raise IntegrationError("Devin key is valid but lacks permission for this org (403).")
        if resp.status_code == 404:
            raise IntegrationError("Devin organization id was not found (404).")
        if resp.status_code != 200:
            raise IntegrationError(sanitize(f"Devin returned HTTP {resp.status_code}."))
        if not config.DEVIN_ALLOWED_REPOS:
            return ConnectionCheckResult(
                IntegrationStatus.UNAVAILABLE,
                "Devin credentials are valid, but no repository is in DEVIN_ALLOWED_REPOS — "
                "sessions cannot be created until one is explicitly configured.")
        return ConnectionCheckResult(IntegrationStatus.CONNECTED,
                                     f"Connected. {len(config.DEVIN_ALLOWED_REPOS)} repo(s) allowed.")

    def _check_repo_allowed(self, repo: str) -> None:
        if repo not in config.DEVIN_ALLOWED_REPOS:
            raise IntegrationError(
                f"Repository {repo!r} is not in DEVIN_ALLOWED_REPOS — refusing to create a session.",
                status=IntegrationStatus.UNAVAILABLE)

    async def create_investigation_session(self, *, repo: str, prompt: str, title: str,
                                            structured_output_schema: dict | None = None) -> dict:
        """Creates ONE Devin session scoped to `repo`. Never auto-merges —
        the response is a session id/URL/PR list for a human to review; this
        adapter has no code path that approves or merges anything."""
        if not self.is_configured():
            raise IntegrationError("Devin is not configured.", status=IntegrationStatus.NOT_CONFIGURED)
        self._check_repo_allowed(repo)
        body: dict = {
            "prompt": prompt, "title": title, "tags": ["red-bears", "verified-finding"],
            "repos": [repo], "bypass_approval": False, "resumable": True,
        }
        if structured_output_schema:
            body["structured_output_schema"] = structured_output_schema
            body["structured_output_required"] = True
        url = f"{config.DEVIN_BASE_URL}/v3/organizations/{config.DEVIN_ORG_ID}/sessions"
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.post(url, headers=self._headers(), json=body)
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Devin session create failed ({type(exc).__name__}).")) from exc
        if resp.status_code not in (200, 201):
            raise IntegrationError(sanitize(f"Devin returned HTTP {resp.status_code}: {resp.text}"))
        return resp.json()

    async def get_session(self, session_id: str) -> dict:
        if not self.is_configured():
            raise IntegrationError("Devin is not configured.", status=IntegrationStatus.NOT_CONFIGURED)
        url = f"{config.DEVIN_BASE_URL}/v3/organizations/{config.DEVIN_ORG_ID}/sessions/{session_id}"
        async with httpx.AsyncClient(timeout=self.default_timeout_s) as client:
            try:
                resp = await client.get(url, headers=self._headers())
            except httpx.HTTPError as exc:
                raise IntegrationError(sanitize(f"Devin session fetch failed ({type(exc).__name__}).")) from exc
        if resp.status_code != 200:
            raise IntegrationError(sanitize(f"Devin returned HTTP {resp.status_code}."))
        return resp.json()


adapter = DevinAdapter()
