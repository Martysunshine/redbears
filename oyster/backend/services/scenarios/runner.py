"""Runs one scenario against one lab instance, inside the scope/budget
enforced by ``ScopedClient``. Confirms the outcome from telemetry (the
proxy's own JSONL record) alongside the scenario's own probe observations —
not the scenario code's unexamined return value.
"""
from __future__ import annotations

import time

import log_config
from services.lab.provisioner import LabInstance
from services.scenarios.base import (BudgetExceeded, Scenario, ScenarioObservations,
                                     ScenarioResult, ScopeViolation, ScopedClient)


async def run_scenario(scenario: Scenario, instance: LabInstance) -> ScenarioResult:
    if not scenario.available or scenario.run is None:
        raise ValueError(f"Scenario {scenario.id!r} is not available (unimplemented).")
    if instance.status != "ready":
        raise ValueError(f"Lab instance {instance.id!r} is not ready (status={instance.status!r}).")

    client = ScopedClient(base_url=instance.base_url, max_requests=scenario.max_requests,
                          deadline=time.time() + scenario.timeout_s)
    obs = ScenarioObservations()
    t0 = time.time()
    error: str | None = None
    try:
        await scenario.run(client, obs)
    except (ScopeViolation, BudgetExceeded) as exc:
        error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # a scenario bug must not look like "not reproduced"
        error = f"Scenario raised {type(exc).__name__}: {exc}"
    finally:
        await client.aclose()
    duration = time.time() - t0

    criteria_results = {c.name: bool(c.check(obs)) for c in scenario.success_criteria} if not error else {}
    if error:
        simulation = "inconclusive"
    elif criteria_results and all(criteria_results.values()):
        simulation = "reproduced"
    elif criteria_results:
        simulation = "not_reproduced"
    else:
        simulation = "inconclusive"

    log_config.audit("scenario_run", {
        "scenario_id": scenario.id, "instance_id": instance.id, "simulation": simulation,
        "requests_made": client.requests_made, "duration_s": round(duration, 2), "error": error,
    })
    return ScenarioResult(scenario_id=scenario.id, simulation=simulation, observations=obs,
                          success_criteria_results=criteria_results, requests_made=client.requests_made,
                          duration_s=duration, error=error)
