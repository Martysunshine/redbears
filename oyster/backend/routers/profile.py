"""The caller's public identity — a nickname, and nothing else.

Oyster keeps no user table, so this is the one place an account has a name of
its own. It exists because the public findings feed needs an author label that
is not an email address. See services/user_profiles.py.

Handlers are plain ``def`` on purpose: synchronous SQLite work belongs in
FastAPI's threadpool, not on the event loop (see routers/user_findings.py).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services import user_profiles
from services.auth_service import require_account

router = APIRouter(tags=["profile"])


class ProfileUpdateRequest(BaseModel):
    # None or "" clears the nickname and restores the generated "User N".
    display_name: str | None = None


def _sub(identity: dict) -> str:
    return identity.get("sub") or identity.get("email") or ""


def _public(profile: dict) -> dict:
    """Only what the owner needs — the handle they show up as, the nickname
    they set (if any), and their member number."""
    return {
        "handle": profile["handle"],
        "display_name": profile.get("display_name"),
        "member_no": profile["member_no"],
    }


@router.get("/profile")
def get_profile(identity: dict = Depends(require_account)):
    profile = user_profiles.ensure(_sub(identity))
    if profile is None:
        raise HTTPException(status_code=400, detail="Cannot resolve account identity.")
    return {"profile": _public(profile)}


@router.patch("/profile")
def update_profile(request: ProfileUpdateRequest,
                   identity: dict = Depends(require_account)):
    try:
        profile = user_profiles.set_display_name(_sub(identity), request.display_name)
    except user_profiles.NameRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if profile is None:
        raise HTTPException(status_code=400, detail="Cannot resolve account identity.")
    return {"status": "ok", "profile": _public(profile)}
