"""Deterministic policy decision — the gate between a proposal and execution.

Combines: tool availability + per-project enablement + parameter validation +
execution class (risk) + engagement-scope validation of every target. Produces
a :class:`PolicyDecision` recording exactly which scope rule matched (or why a
target was blocked), whether human approval is required, and the runtime /
output caps that will be enforced.

This is pure and side-effect free so it can be unit-tested and re-run at
execution time (scope is always re-validated immediately before a tool runs).
"""

from __future__ import annotations

from . import risk, scope_engine, store
from .command_guard import CommandValidationError
from .tool_registry import ToolAction, ToolProfile, validate_parameters

DECISION_ALLOW = "allow"                    # class 0/1 — no human approval
DECISION_REQUIRES_APPROVAL = "requires_approval"  # class 2/3 — approve first
DECISION_BLOCKED = "blocked"                # unavailable / out-of-scope / class 4


def decide(project_id: str, profile: ToolProfile, action: ToolAction,
           targets: list[str], params: dict, scope: dict,
           *, resolve_dns: bool = True) -> dict:
    reasons: list[str] = []
    matched: list[str] = []
    unmatched: list[str] = []
    prohibited: list[str] = []

    rp = risk.profile_for_class(action.execution_class)

    # 1. Tool availability (never fabricate a run against a missing binary)
    avail = profile.availability()
    if not avail.get("available"):
        return _decision(project_id, DECISION_BLOCKED,
                         reasons=[f"Tool '{profile.id}' is not available: {avail.get('reason')}"],
                         approval_required=False, rp=rp,
                         allowed_parameters={}, constraints=_constraints(action))

    # 2. Per-project enablement
    if not store.is_tool_enabled(project_id, profile.id):
        return _decision(project_id, DECISION_BLOCKED,
                         reasons=[f"Tool '{profile.id}' is disabled for this project."],
                         approval_required=False, rp=rp,
                         allowed_parameters={}, constraints=_constraints(action))

    # 3. Parameter validation (rejects injection / traversal / bad enums)
    try:
        clean = validate_parameters(action, params)
    except CommandValidationError as exc:
        return _decision(project_id, DECISION_BLOCKED, reasons=[str(exc)],
                         approval_required=False, rp=rp,
                         allowed_parameters={}, constraints=_constraints(action))

    # 4. Class 4 destructive is blocked by default
    if rp.blocked:
        return _decision(project_id, DECISION_BLOCKED,
                         reasons=[f"Execution class {action.execution_class} "
                                  f"({risk.CLASS_NAMES[risk.CLASS_DESTRUCTIVE]}) is blocked by default. "
                                  "Use a controlled simulation / local lab reproduction instead."],
                         approval_required=False, rp=rp,
                         allowed_parameters=clean, constraints=_constraints(action),
                         prohibited=["destructive"])

    # 5. Scope validation of every target (skipped only for class 0 non-network)
    needs_scope = rp.requires_scope or action.network_required
    if needs_scope:
        if not targets:
            return _decision(project_id, DECISION_BLOCKED,
                             reasons=["No target supplied for a scope-gated action."],
                             approval_required=False, rp=rp,
                             allowed_parameters=clean, constraints=_constraints(action))
        for t in targets:
            res = scope_engine.validate(t, scope, technique=profile.id, resolve_dns=resolve_dns)
            if res.allowed:
                matched.append(res.matched_rule or t)
                reasons.append(f"{t}: {res.reason}")
            else:
                unmatched.append(t)
                reasons.append(f"{t}: BLOCKED — {res.reason}")
                if res.prohibited:
                    prohibited.extend(res.prohibited)
        if unmatched:
            return _decision(project_id, DECISION_BLOCKED, reasons=reasons,
                             approval_required=False, rp=rp,
                             matched=matched, unmatched=unmatched, prohibited=prohibited,
                             allowed_parameters=clean, constraints=_constraints(action))
    else:
        reasons.append("Class 0 local read-only analysis — no external scope required.")

    # 6. Approval requirement by class
    if action.execution_class >= risk.CLASS_LOW_ACTIVE:
        decision = DECISION_REQUIRES_APPROVAL
        approval_required = True
        reasons.append(
            "Explicit human approval required immediately before execution."
            if action.execution_class >= risk.CLASS_INTRUSIVE
            else "Approval required (low-impact active testing)."
        )
    else:
        decision = DECISION_ALLOW
        approval_required = False

    return _decision(project_id, decision, reasons=reasons, approval_required=approval_required,
                     rp=rp, matched=matched, unmatched=unmatched, prohibited=prohibited,
                     allowed_parameters=clean, constraints=_constraints(action))


def _constraints(action: ToolAction) -> dict:
    return {name: {k: v for k, v in spec.items() if k in ("type", "enum", "min", "max", "default")}
            for name, spec in (action.param_schema or {}).items()}


def _decision(project_id: str, decision: str, *, reasons, approval_required, rp,
              matched=None, unmatched=None, prohibited=None,
              allowed_parameters=None, constraints=None) -> dict:
    return {
        "id": store.new_id("pol"),
        "project_id": project_id,
        "decision": decision,
        "reasons": reasons or [],
        "matched_scope_entries": matched or [],
        "unmatched_targets": unmatched or [],
        "prohibited_conditions": prohibited or [],
        "approval_required": approval_required,
        "allowed_parameters": allowed_parameters or {},
        "parameter_constraints": constraints or {},
        "maximum_runtime": rp.default_timeout,
        "maximum_output_size": rp.default_max_output,
        "created_at": store.now_ts(),
    }
