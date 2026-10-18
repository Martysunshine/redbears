"""Benign comparison traffic per scenario — ordinary requests that resemble
the scenario's own traffic shape but carry no injection/cross-user attempt,
run against the same lab instance so an improved rule's false-positive rate
can be checked on real telemetry rather than assumed (brief §6).
"""
from __future__ import annotations

from services.scenarios.base import ScenarioObservations, ScopedClient


async def sqli_login_bypass(client: ScopedClient, obs: ScenarioObservations) -> None:
    """A real person can have an apostrophe in their email handle with no SQL
    injection shape at all — this must not trip the improved rule."""
    resp = await client.request("POST", "/rest/user/login",
                                json={"email": "o'brien@example.com", "password": "wrong-password"})
    obs.notes.append(f"Benign traffic: login attempt for an apostrophe-containing email "
                     f"(no comment/boolean marker) returned HTTP {resp.status_code}.")


async def idor_basket_access(client: ScopedClient, obs: ScenarioObservations) -> None:
    """A user reading their OWN basket again — ordinary, repeated, legitimate
    traffic that must not trip the improved rule."""
    bid_owner: dict = obs.probes.get("bid_owner", {})
    bid_token: dict = obs.probes.get("bid_token", {})
    for bid, owner in bid_owner.items():
        headers = {"X-RedBears-Actor": owner}
        if bid_token.get(bid):
            headers["Authorization"] = f"Bearer {bid_token[bid]}"
        resp = await client.request("GET", f"/rest/basket/{bid}", headers=headers)
        obs.notes.append(f"Benign traffic: {owner} re-read their own basket ({bid}) -> HTTP {resp.status_code}.")


GENERATORS = {"sqli_login_bypass": sqli_login_bypass, "idor_basket_access": idor_basket_access}
