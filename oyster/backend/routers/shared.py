"""Public read-only surface for shared findings — the ONLY unauthenticated
data route in Oyster.

A user can publish a single finding; anyone holding the unguessable token
(``secrets.token_urlsafe(32)``) may read it, no login. The response is a
minimal projection — title, content, citations, created_at — and NOTHING that
identifies the owner, project, conversation or message. There is no listing
endpoint, so tokens cannot be enumerated; revoking a finding (or regenerating
its token) makes the old link 404 immediately.

Kept in its own router so it can be mounted in PUBLIC_ROUTERS while the rest of
findings stays behind require_account.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from services import user_findings_service

router = APIRouter(tags=["shared"])


@router.get("/shared/findings/{token}")
async def get_shared_finding(token: str):
    finding = user_findings_service.get_by_token(token)
    if finding is None:
        # Unknown, revoked, or never shared — all indistinguishable on purpose.
        raise HTTPException(status_code=404, detail="This shared finding is not available.")
    return {"finding": finding}
