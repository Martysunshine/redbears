"""Detection validation: run benign comparison traffic on the same lab
instance, then evaluate a named rule against ALL of that instance's real
telemetry (the scenario's own traffic plus the benign traffic) — never the
scenario's or model's narration of what happened.

Missing telemetry (empty events, or the instance's log file never appeared)
always reports "inconclusive" (brief §6), never "missed".
"""
from __future__ import annotations

import dataclasses

import log_config
from services.detection import benign_traffic
from services.detection.rules import RULES, DetectionRule
from services.lab.provisioner import LabInstance
from services.scenarios.base import ScenarioObservations, ScopedClient


@dataclasses.dataclass
class DetectionReport:
    scenario_id: str
    rule_id: str
    rule_label: str
    is_demo_baseline: bool
    detection: str  # "detected" | "missed" | "inconclusive"
    reasoning: str
    matched_events: list[dict]
    benign_events_checked: int
    false_positive_on_benign: bool | None
    total_events: int


async def run_benign_traffic(instance: LabInstance, scenario_id: str, context: dict) -> list[dict]:
    """Returns the subset of telemetry produced by this call only, for the
    false-positive check — not the whole instance's history."""
    gen = benign_traffic.GENERATORS.get(scenario_id)
    if gen is None:
        return []
    before = len(instance.telemetry.read_events()) if instance.telemetry else 0
    client = ScopedClient(base_url=instance.base_url, max_requests=10, deadline=__import__("time").time() + 20)
    obs = ScenarioObservations(probes=dict(context))
    try:
        await gen(client, obs)
    finally:
        await client.aclose()
    all_events = instance.telemetry.read_events() if instance.telemetry else []
    return all_events[before:]


async def validate_detection(instance: LabInstance, rule_id: str, *, scenario_context: dict,
                             include_benign_traffic: bool = True) -> DetectionReport:
    rule: DetectionRule | None = RULES.get(rule_id)
    if rule is None:
        raise ValueError(f"Unknown detection rule {rule_id!r}")

    benign_events: list[dict] = []
    if include_benign_traffic:
        benign_events = await run_benign_traffic(instance, rule.scenario_id, scenario_context)

    events = instance.telemetry.read_events() if instance.telemetry else []
    if not events:
        report = DetectionReport(rule.scenario_id, rule.id, rule.label, rule.is_demo_baseline,
                                 "inconclusive", "No telemetry was collected for this lab instance.",
                                 [], len(benign_events), None, 0)
        log_config.audit("detection_validate", dataclasses.asdict(report))
        return report

    match = rule.evaluate(events, scenario_context)
    detection = "detected" if match.matched else "missed"

    false_positive = None
    if include_benign_traffic and benign_events:
        benign_match = rule.evaluate(benign_events, scenario_context)
        false_positive = benign_match.matched

    report = DetectionReport(rule.scenario_id, rule.id, rule.label, rule.is_demo_baseline, detection,
                             match.reasoning, match.matched_events, len(benign_events),
                             false_positive, len(events))
    log_config.audit("detection_validate", {
        "scenario_id": report.scenario_id, "rule_id": report.rule_id, "detection": report.detection,
        "false_positive_on_benign": report.false_positive_on_benign, "total_events": report.total_events,
    })
    return report
