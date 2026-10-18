"""Scenario catalogue. Two scenarios are implemented (available=True); the
rest are declared with their real field values but ``available=False`` and no
``run`` — the brief's "label unimplemented scenarios as unavailable" rather
than hiding what the catalogue is meant to grow into.
"""
from __future__ import annotations

from services.scenarios import idor_basket, sqli_login
from services.scenarios.base import Scenario

_PLACEHOLDERS = [
    Scenario(id="xss_reflected", title="Reflected XSS", description="Not implemented yet.",
            lab_template="juice-shop", prerequisites=[], permitted_target="Lab instance only.",
            max_requests=0, timeout_s=0, success_criteria=[], required_telemetry=[],
            cleanup="N/A", available=False),
    Scenario(id="auth_broken_session", title="Broken authentication / session handling",
            description="Not implemented yet.", lab_template="juice-shop", prerequisites=[],
            permitted_target="Lab instance only.", max_requests=0, timeout_s=0,
            success_criteria=[], required_telemetry=[], cleanup="N/A", available=False),
    Scenario(id="path_traversal", title="Path traversal", description="Not implemented yet.",
            lab_template="juice-shop", prerequisites=[], permitted_target="Lab instance only.",
            max_requests=0, timeout_s=0, success_criteria=[], required_telemetry=[],
            cleanup="N/A", available=False),
    Scenario(id="rate_limit_bypass", title="Rate-limit bypass", description="Not implemented yet.",
            lab_template="juice-shop", prerequisites=[], permitted_target="Lab instance only.",
            max_requests=0, timeout_s=0, success_criteria=[], required_telemetry=[],
            cleanup="N/A", available=False),
]

_CATALOG: dict[str, Scenario] = {s.id: s for s in [sqli_login.build(), idor_basket.build(), *_PLACEHOLDERS]}


def list_scenarios() -> list[dict]:
    return [s.catalogue_entry() for s in _CATALOG.values()]


def get(scenario_id: str) -> Scenario | None:
    return _CATALOG.get(scenario_id)
