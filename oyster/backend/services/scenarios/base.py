"""Scenario catalogue contract.

Every scenario, available or not, declares the same fields up front (brief
§5): a lab template + prerequisites, the one target it is permitted to touch,
a bounded action budget/timeout, machine-checkable success criteria, the
telemetry it requires, and how it is cleaned up. An "unavailable" scenario has
every field except `run` — it exists so the catalogue is extensible without
silently claiming something works before it does.

Scope and budget are enforced HERE, in ``ScenarioRunner``, not left to each
scenario's own code: a scenario's `run()` is handed a client that refuses any
request to a host other than the lab instance's own proxy URL and raises once
its request/time budget is spent. This is the same "outside the model"
principle as the lab sandbox — a scenario cannot widen its own scope by
construction, regardless of what it tries to do.
"""
from __future__ import annotations

import dataclasses
import time
from typing import Awaitable, Callable

import httpx


class ScopeViolation(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class ScopedClient:
    """The ONLY HTTP client a scenario's run() ever receives. Every request is
    checked against the permitted target and the remaining budget before it is
    sent — a scenario cannot reach anything else no matter what it constructs."""

    def __init__(self, *, base_url: str, max_requests: int, deadline: float):
        self.base_url = base_url.rstrip("/")
        self.max_requests = max_requests
        self.deadline = deadline
        self.requests_made = 0
        self._client = httpx.AsyncClient(timeout=10)

    async def request(self, method: str, path: str, **kw) -> httpx.Response:
        if not path.startswith("/"):
            raise ScopeViolation(f"Scenario requested a non-relative path {path!r}; only the "
                                 "lab instance's own paths are permitted.")
        if time.time() > self.deadline:
            raise BudgetExceeded("Scenario exceeded its wall-clock timeout.")
        if self.requests_made >= self.max_requests:
            raise BudgetExceeded(f"Scenario exceeded its request budget ({self.max_requests}).")
        self.requests_made += 1
        return await self._client.request(method, self.base_url + path, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()


@dataclasses.dataclass
class SuccessCriterion:
    name: str
    description: str
    # Evaluated against ACTUAL observations (telemetry + explicit probe
    # results captured during run()), never the model's own narration.
    check: Callable[["ScenarioObservations"], bool]


@dataclasses.dataclass
class ScenarioObservations:
    """What a scenario's run() actually measured — the only input success
    criteria and detection validation are allowed to read."""
    probes: dict = dataclasses.field(default_factory=dict)
    notes: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ScenarioResult:
    scenario_id: str
    simulation: str  # "reproduced" | "not_reproduced" | "inconclusive"
    observations: ScenarioObservations
    success_criteria_results: dict[str, bool]
    requests_made: int
    duration_s: float
    error: str | None = None


@dataclasses.dataclass
class Scenario:
    id: str
    title: str
    description: str
    lab_template: str                 # which lab this needs (currently always "juice-shop")
    prerequisites: list[str]
    permitted_target: str             # human-readable statement of scope, enforced via ScopedClient
    max_requests: int
    timeout_s: float
    success_criteria: list[SuccessCriterion]
    required_telemetry: list[str]
    cleanup: str                      # human-readable; actual cleanup is provisioner.cleanup_instance/reset_instance
    available: bool
    run: Callable[[ScopedClient, ScenarioObservations], Awaitable[None]] | None = None

    def catalogue_entry(self) -> dict:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "available": self.available, "lab_template": self.lab_template,
            "prerequisites": self.prerequisites, "permitted_target": self.permitted_target,
            "max_requests": self.max_requests, "timeout_s": self.timeout_s,
            "success_criteria": [{"name": c.name, "description": c.description} for c in self.success_criteria],
            "required_telemetry": self.required_telemetry, "cleanup": self.cleanup,
        }
