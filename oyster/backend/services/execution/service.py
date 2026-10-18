"""Execution Engine orchestration — the proposal → execution lifecycle.

This is the deterministic pipeline the spec calls for. The model may *propose*;
this module decides, gates on approval, re-validates scope immediately before
running, executes through the controlled runner, captures output, mints
evidence, and records an audit trail. Every transition is an explicit state.

Lifecycle states
-----------------
proposal:  proposed → validating → blocked | awaiting_approval | approved |
           rejected | expired → executing → completed
execution: queued → running → succeeded | failed | timed_out | cancelled →
           cleanup_required → completed
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import log_config
from services import project_service, scope_service

from . import parsers, policy, risk, runner, store
from .tool_registry import get_action, get_profile

PROPOSAL_TTL_MINUTES = 30
APPROVAL_TTL_MINUTES = 15


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _active_project_id() -> str:
    try:
        return project_service.get_active_project_id()
    except Exception:
        return "default"


def _scope_for(project_id: str) -> dict:
    """Scope for a project. The active project's scope is bridged into the
    global scope file; for a non-active project we read its stored scope."""
    try:
        active = project_service.get_active_project_id()
        if project_id == active:
            return scope_service.load_scope()
        proj = project_service.get_project(project_id)
        return (proj or {}).get("scope") or {}
    except Exception:
        return scope_service.load_scope()


def _hash_proposal(tool_id: str, action_id: str, targets: list[str], params: dict) -> str:
    canonical = json.dumps(
        {"tool": tool_id, "action": action_id, "targets": sorted(targets),
         "params": params},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _is_expired(iso: str) -> bool:
    try:
        return _now() > datetime.fromisoformat(iso)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Proposal creation + validation
# ---------------------------------------------------------------------------

def create_proposal(*, tool_id: str, action_id: str, targets: list[str],
                    parameters: dict | None = None, objective: str = "",
                    conversation_id: str | None = None, project_id: str | None = None,
                    requested_by: str = "local-user") -> dict:
    project_id = project_id or _active_project_id()
    parameters = parameters or {}
    pair = get_action(tool_id, action_id)
    if not pair:
        return {"error": f"Unknown tool/action '{tool_id}.{action_id}'.", "ok": False}
    profile, action = pair
    scope = _scope_for(project_id)

    decision = policy.decide(project_id, profile, action, targets, parameters, scope,
                             resolve_dns=True)
    clean_params = decision["allowed_parameters"] or parameters
    proposal_hash = _hash_proposal(tool_id, action_id, targets, clean_params)

    # generated (human-readable) command preview — never executed as a string
    generated = _preview_command(profile, action, targets, clean_params)

    status = {
        policy.DECISION_BLOCKED: "blocked",
        policy.DECISION_REQUIRES_APPROVAL: "awaiting_approval",
        policy.DECISION_ALLOW: "approved",
    }[decision["decision"]]

    now = store.now_ts()
    proposal = {
        "id": store.new_id("prop"),
        "project_id": project_id,
        "conversation_id": conversation_id,
        "requested_by": requested_by,
        "objective": objective,
        "tool_id": tool_id,
        "action_id": action_id,
        "targets": targets,
        "parameters": clean_params,
        "generated_command": generated,
        "sanitized_command": generated,
        "risk_level": risk.RISK_LABEL[action.execution_class],
        "execution_class": action.execution_class,
        "scope_decision": decision["decision"],
        "approval_requirement": risk.profile_for_class(action.execution_class).default_approval,
        "expected_outputs": action.target_types,
        "timeout_seconds": decision["maximum_runtime"],
        "network_required": action.network_required,
        "cleanup_required": action.cleanup_required,
        "proposal_hash": proposal_hash,
        "status": status,
        "created_at": now,
        "expires_at": (_now() + timedelta(minutes=PROPOSAL_TTL_MINUTES)).isoformat(),
    }
    store.insert_proposal(proposal)
    decision["proposal_id"] = proposal["id"]
    store.insert_policy(decision)

    store.audit(project_id, "proposal_created", actor=requested_by, proposal_id=proposal["id"],
                detail={"tool": tool_id, "action": action_id, "targets": targets,
                        "decision": decision["decision"], "risk": proposal["risk_level"]})
    log_config.audit("execution_proposal", {
        "project_id": project_id, "proposal_id": proposal["id"], "tool": tool_id,
        "action": action_id, "targets": targets, "decision": decision["decision"],
        "risk": proposal["risk_level"],
    })
    try:
        project_service.add_event(project_id, "execution_proposed", actor=requested_by,
                                  summary=f"{tool_id}.{action_id} → {decision['decision']}",
                                  ref_type="proposal", ref_id=proposal["id"])
    except Exception:
        pass
    return {"ok": True, "proposal": proposal, "policy": decision}


def _preview_command(profile, action, targets, params) -> str:
    if action.kind == "subprocess" and action.build_argv and targets:
        try:
            return " ".join(action.build_argv(targets[0], params))
        except Exception:
            return f"{profile.binary} <invalid params>"
    tgt = targets[0] if targets else ""
    return f"{profile.id}.{action.id}(target={tgt}, params={params})"


def validate_proposal(proposal_id: str, project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    prop = store.get_proposal(proposal_id)
    if not prop or prop["project_id"] != project_id:
        return {"ok": False, "error": "Proposal not found in this project."}
    pair = get_action(prop["tool_id"], prop["action_id"])
    if not pair:
        return {"ok": False, "error": "Tool/action no longer exists."}
    profile, action = pair
    scope = _scope_for(project_id)
    decision = policy.decide(project_id, profile, action, prop["targets"], prop["parameters"], scope)
    return {"ok": True, "proposal": prop, "policy": decision, "expired": _is_expired(prop["expires_at"])}


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

def approve_proposal(proposal_id: str, *, approved_by: str = "local-user", note: str = "",
                     project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    prop = store.get_proposal(proposal_id)
    if not prop or prop["project_id"] != project_id:
        return {"ok": False, "error": "Proposal not found in this project."}
    if _is_expired(prop["expires_at"]):
        store.update_proposal(proposal_id, {"status": "expired"})
        return {"ok": False, "error": "Proposal has expired; create a new one."}
    if prop["status"] in ("blocked", "rejected"):
        return {"ok": False, "error": f"Proposal is {prop['status']} and cannot be approved."}
    if prop["status"] in ("executing", "completed"):
        return {"ok": False, "error": "Proposal already executed."}

    approval = {
        "id": store.new_id("appr"),
        "proposal_id": proposal_id,
        "project_id": project_id,
        "decision": "approved",
        "approved_by": approved_by,
        "proposal_hash": prop["proposal_hash"],  # binds approval to THIS exact proposal
        "note": note,
        "created_at": store.now_ts(),
        "expires_at": (_now() + timedelta(minutes=APPROVAL_TTL_MINUTES)).isoformat(),
    }
    store.insert_approval(approval)
    store.update_proposal(proposal_id, {"status": "approved"})
    store.audit(project_id, "proposal_approved", actor=approved_by, proposal_id=proposal_id,
                detail={"note": note})
    log_config.audit("execution_approved", {"project_id": project_id, "proposal_id": proposal_id,
                                            "approved_by": approved_by})
    return {"ok": True, "approval": approval}


def reject_proposal(proposal_id: str, *, note: str = "", project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    prop = store.get_proposal(proposal_id)
    if not prop or prop["project_id"] != project_id:
        return {"ok": False, "error": "Proposal not found in this project."}
    store.update_proposal(proposal_id, {"status": "rejected"})
    store.insert_approval({
        "id": store.new_id("appr"), "proposal_id": proposal_id, "project_id": project_id,
        "decision": "rejected", "approved_by": "local-user", "proposal_hash": prop["proposal_hash"],
        "note": note, "created_at": store.now_ts(), "expires_at": store.now_ts(),
    })
    store.audit(project_id, "proposal_rejected", proposal_id=proposal_id, detail={"note": note})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

async def start_execution(proposal_id: str, project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    prop = store.get_proposal(proposal_id)
    if not prop or prop["project_id"] != project_id:
        return {"ok": False, "error": "Proposal not found in this project."}

    # expiry
    if _is_expired(prop["expires_at"]):
        store.update_proposal(proposal_id, {"status": "expired"})
        return {"ok": False, "error": "Proposal expired; create a new one."}

    # duplicate-execution prevention
    prior = store.executions_for_proposal(proposal_id)
    if any(e["status"] in ("queued", "running", "succeeded", "completed") for e in prior):
        return {"ok": False, "error": "This proposal has already been executed."}

    pair = get_action(prop["tool_id"], prop["action_id"])
    if not pair:
        return {"ok": False, "error": "Tool/action no longer exists."}
    profile, action = pair
    scope = _scope_for(project_id)

    # RE-VALIDATE scope immediately before execution (deterministic, fresh DNS)
    decision = policy.decide(project_id, profile, action, prop["targets"], prop["parameters"],
                             scope, resolve_dns=True)
    if decision["decision"] == policy.DECISION_BLOCKED:
        store.update_proposal(proposal_id, {"status": "blocked"})
        store.audit(project_id, "execution_blocked_revalidation", proposal_id=proposal_id,
                    detail={"reasons": decision["reasons"]})
        return {"ok": False, "error": "Blocked at pre-execution scope re-validation.",
                "policy": decision}

    # approval gate
    if decision["approval_required"]:
        appr = store.get_latest_approval(proposal_id)
        if not appr or appr["decision"] != "approved":
            return {"ok": False, "error": "Approval required before execution."}
        if _is_expired(appr["expires_at"]):
            return {"ok": False, "error": "Approval expired; re-approve the proposal."}
        # proposal-mutation guard: approval is bound to the exact proposal hash
        current_hash = _hash_proposal(prop["tool_id"], prop["action_id"], prop["targets"], prop["parameters"])
        if appr["proposal_hash"] != current_hash:
            return {"ok": False, "error": "Proposal changed after approval; re-approval required."}

    # create execution record
    target = prop["targets"][0] if prop["targets"] else ""
    eid = store.new_id("exec")
    execution = {
        "id": eid, "proposal_id": proposal_id, "project_id": project_id,
        "tool_id": prop["tool_id"], "action_id": prop["action_id"], "target": target,
        "sanitized_command": prop["sanitized_command"], "status": "running",
        "started_at": store.now_ts(), "created_at": store.now_ts(),
        "timeout_state": "none", "cancellation_state": "none", "cleanup_state": "none",
    }
    store.insert_execution(execution)
    store.update_proposal(proposal_id, {"status": "executing"})
    store.audit(project_id, "execution_started", proposal_id=proposal_id, execution_id=eid,
                detail={"tool": prop["tool_id"], "target": target,
                        "scope_rule": decision["matched_scope_entries"]})

    # RUN through the controlled runner
    outcome = await runner.run(
        eid, project_id, profile, action, target, prop["parameters"], scope,
        timeout=decision["maximum_runtime"], max_output=decision["maximum_output_size"],
    )

    # parse observations
    observations = parsers.parse(prop["tool_id"], prop["action_id"], outcome.parsed, outcome.stdout)

    # persist output
    store.insert_output({
        "id": store.new_id("out"), "execution_id": eid, "project_id": project_id,
        "stdout": outcome.stdout, "stderr": outcome.stderr, "stdout_hash": outcome.output_hash,
        "truncated": outcome.truncated, "parsed": {"observations": observations, "raw_parsed": outcome.parsed},
        "created_at": store.now_ts(),
    })

    # determine terminal status
    if outcome.cancellation_state == "cancelled":
        status = "cancelled"
    elif outcome.timeout_state == "timed_out":
        status = "timed_out"
    elif outcome.error_summary and outcome.exit_code not in (0,):
        status = "failed"
    else:
        status = "succeeded"

    store.update_execution(eid, {
        "status": status, "completed_at": store.now_ts(), "exit_code": outcome.exit_code,
        "tool_version": outcome.tool_version, "output_hash": outcome.output_hash,
        "timeout_state": outcome.timeout_state, "cancellation_state": outcome.cancellation_state,
        "error_summary": outcome.error_summary,
    })

    # auto-mint evidence from observations (chain of custody)
    evidence_ids: list[str] = []
    if status == "succeeded":
        for ob in observations:
            ev = store.insert_evidence({
                "id": store.new_id("ev"), "project_id": project_id, "execution_id": eid,
                "tool_id": prop["tool_id"], "target": target, "title": ob["title"],
                "observation": ob["detail"], "content_hash": outcome.output_hash,
                "metadata": {"type": ob["type"], "severity": ob["severity"],
                             "tool_version": outcome.tool_version,
                             "sanitized_command": outcome.sanitized_command,
                             "secret_indicators": outcome.secret_indicators},
                "created_at": store.now_ts(),
            })
            evidence_ids.append(ev["id"])

    # cleanup tracking
    cleanup = None
    if prop["cleanup_required"]:
        cleanup = store.insert_cleanup({
            "id": store.new_id("cln"), "execution_id": eid, "project_id": project_id,
            "state": "pending", "detail": "Execution requires manual cleanup confirmation.",
            "created_at": store.now_ts(), "completed_at": None,
        })
        store.update_execution(eid, {"cleanup_state": "pending"})

    store.update_proposal(proposal_id, {"status": "completed"})
    store.audit(project_id, "execution_completed", proposal_id=proposal_id, execution_id=eid,
                detail={"status": status, "exit_code": outcome.exit_code,
                        "output_hash": outcome.output_hash, "evidence": len(evidence_ids),
                        "secret_indicators_redacted": outcome.secret_indicators})
    log_config.audit("execution_completed", {
        "project_id": project_id, "execution_id": eid, "tool": prop["tool_id"],
        "target": target, "status": status, "exit_code": outcome.exit_code,
        "output_hash": outcome.output_hash,
    })
    try:
        project_service.add_event(project_id, "execution_completed",
                                  summary=f"{prop['tool_id']}.{prop['action_id']} on {target}: {status}",
                                  ref_type="execution", ref_id=eid)
    except Exception:
        pass

    return {"ok": True, "execution": store.get_execution(eid),
            "output": store.get_output_for_execution(eid),
            "observations": observations, "evidence_ids": evidence_ids,
            "cleanup": cleanup, "policy": decision}


def cancel_execution(execution_id: str, project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    ex = store.get_execution(execution_id)
    if not ex or ex["project_id"] != project_id:
        return {"ok": False, "error": "Execution not found in this project."}
    was_running = runner.request_cancel(execution_id)
    if ex["status"] in ("running", "queued"):
        store.update_execution(execution_id, {"status": "cancelling", "cancellation_state": "cancelled"})
    store.audit(project_id, "execution_cancel_requested", execution_id=execution_id,
                detail={"was_running": was_running})
    return {"ok": True, "was_running": was_running}


# ---------------------------------------------------------------------------
# Evidence + findings
# ---------------------------------------------------------------------------

def create_evidence(execution_id: str, title: str, observation: str,
                    project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    ex = store.get_execution(execution_id)
    if not ex or ex["project_id"] != project_id:
        return {"ok": False, "error": "Execution not found in this project."}
    out = store.get_output_for_execution(execution_id)
    ev = store.insert_evidence({
        "id": store.new_id("ev"), "project_id": project_id, "execution_id": execution_id,
        "tool_id": ex["tool_id"], "target": ex["target"], "title": title,
        "observation": observation, "content_hash": (out or {}).get("stdout_hash", ""),
        "metadata": {"manual": True}, "created_at": store.now_ts(),
    })
    store.audit(project_id, "evidence_created", execution_id=execution_id, detail={"evidence_id": ev["id"]})
    return {"ok": True, "evidence": ev}


def create_finding(title: str, severity: str, summary: str, evidence_ids: list[str],
                   recommendation: str = "", project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    # verify evidence belongs to this project (isolation)
    for eid in evidence_ids:
        ev = store.get_evidence(eid)
        if not ev or ev["project_id"] != project_id:
            return {"ok": False, "error": f"Evidence '{eid}' not found in this project."}
    f = store.insert_finding({
        "id": store.new_id("find"), "project_id": project_id, "title": title,
        "severity": severity, "summary": summary, "evidence_ids": evidence_ids,
        "recommendation": recommendation, "created_at": store.now_ts(),
    })
    store.audit(project_id, "finding_created", detail={"finding_id": f["id"], "severity": severity})
    try:
        project_service.add_event(project_id, "finding_created", summary=f"Finding: {title} ({severity})",
                                  ref_type="finding", ref_id=f["id"])
    except Exception:
        pass
    return {"ok": True, "finding": f}


def record_cleanup(execution_id: str, detail: str = "", project_id: str | None = None) -> dict:
    project_id = project_id or _active_project_id()
    ex = store.get_execution(execution_id)
    if not ex or ex["project_id"] != project_id:
        return {"ok": False, "error": "Execution not found in this project."}
    cln = store.get_cleanup_for_execution(execution_id)
    if cln:
        store.update_cleanup(cln["id"], {"state": "completed", "detail": detail or cln["detail"],
                                         "completed_at": store.now_ts()})
    store.update_execution(execution_id, {"cleanup_state": "completed"})
    store.audit(project_id, "cleanup_recorded", execution_id=execution_id, detail={"note": detail})
    return {"ok": True}


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def execution_view(execution_id: str, project_id: str | None = None) -> dict | None:
    project_id = project_id or _active_project_id()
    ex = store.get_execution(execution_id)
    if not ex or ex["project_id"] != project_id:
        return None
    out = store.get_output_for_execution(execution_id)
    return {
        "execution": ex,
        "output": out,
        "evidence": [e for e in store.list_evidence(project_id) if e["execution_id"] == execution_id],
        "cleanup": store.get_cleanup_for_execution(execution_id),
    }
