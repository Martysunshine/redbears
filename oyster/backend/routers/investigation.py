"""Investigation workflow, scenario catalogue, isolated lab, and the Devin
handoff for verified findings. Admin-gated (see routers/__init__.py) — same
tier as execution.router, since preparing a lab instance actually runs a
process, exactly like that router's tools.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.detection import evaluator as detection_evaluator
from services.integrations.base import IntegrationError
from services.integrations.devin import adapter as devin_adapter
from services.investigation import store
from services.investigation.workflow import CVE_SCENARIO_COMPAT, research_cve, run_pipeline
from services.lab import provisioner
from services.scenarios import catalog

router = APIRouter(prefix="/investigation", tags=["investigation"])


# --- Scenario catalogue -------------------------------------------------------

@router.get("/scenarios")
async def list_scenarios():
    return {"scenarios": catalog.list_scenarios()}


# --- Lab instance lifecycle ---------------------------------------------------

@router.get("/lab/instances")
async def list_lab_instances():
    return {"instances": provisioner.list_instances()}


@router.post("/lab/instances")
async def create_lab_instance(scenario_id: str | None = None):
    try:
        inst = provisioner.create_instance(scenario_id)
    except provisioner.LabDisabled as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except provisioner.LabCapacityReached as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    except provisioner.LabProvisionError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return inst.public_dict()


@router.post("/lab/instances/{instance_id}/reset")
async def reset_lab_instance(instance_id: str):
    try:
        inst = provisioner.reset_instance(instance_id)
    except provisioner.LabProvisionError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return inst.public_dict()


@router.delete("/lab/instances/{instance_id}")
async def cleanup_lab_instance(instance_id: str):
    provisioner.cleanup_instance(instance_id)
    return {"id": instance_id, "status": "stopped"}


# --- Full pipeline + single-stage re-runs -------------------------------------

class RunPipelineRequest(BaseModel):
    scenario_id: str
    research_question: str | None = None


@router.post("/run")
async def run_investigation(request: RunPipelineRequest):
    try:
        return await run_pipeline(request.scenario_id, research_question=request.research_question)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class ResearchCveRequest(BaseModel):
    cve_id: str
    summary: str | None = None
    source_url: str | None = None


@router.post("/research-cve")
async def research_cve_endpoint(request: ResearchCveRequest):
    """"Research this CVE" from Security Intel. Only runs an actual lab
    scenario if CVE_SCENARIO_COMPAT names one for this exact CVE id — never
    for an arbitrary CVE and never just because the vulnerability class
    matches; otherwise returns research-only, labelled as such."""
    return await research_cve(request.cve_id, summary=request.summary, source_url=request.source_url)


@router.get("/research-cve/{cve_id}/compatible-scenario")
async def compatible_scenario(cve_id: str):
    scenario_id = CVE_SCENARIO_COMPAT.get(cve_id.upper())
    scenario = catalog.get(scenario_id) if scenario_id else None
    return {
        "cve_id": cve_id,
        "compatible_scenario_id": scenario_id if scenario and scenario.available else None,
    }


class DetectRequest(BaseModel):
    instance_id: str
    rule_id: str
    context: dict = {}


@router.post("/detect")
async def detect(request: DetectRequest):
    inst = provisioner.get_instance(request.instance_id)
    if inst is None:
        raise HTTPException(status_code=404, detail=f"No such lab instance {request.instance_id!r}")
    try:
        report = await detection_evaluator.validate_detection(inst, request.rule_id, scenario_context=request.context)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    import dataclasses
    return dataclasses.asdict(report)


@router.get("/investigations")
async def list_investigations():
    return {"investigations": store.list_investigations()}


@router.get("/investigations/{investigation_id}")
async def get_investigation(investigation_id: str):
    rec = store.get_investigation(investigation_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="No such investigation")
    return rec


# --- Verified findings + Devin handoff -----------------------------------------

class PromoteFindingRequest(BaseModel):
    investigation_id: str
    title: str
    verified_by: str | None = None


@router.post("/findings")
async def promote_finding(request: PromoteFindingRequest):
    """Store a VERIFIED finding from a completed investigation record — source
    references, lab version/commit, scenario config, detection outcome and
    retest history all carried over (brief §8). Credentials/tokens were
    already redacted by services.investigation.store on the way in."""
    inv = store.get_investigation(request.investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="No such investigation")
    if inv.get("simulation") != "reproduced" or (inv.get("detection_improved_retest") or {}).get("retest_simulation") != "reproduced":
        raise HTTPException(status_code=409, detail="A reproduced scenario and reproduction retest are required before verification.")
    finding = {
        "title": request.title, "verified_by": request.verified_by,
        "investigation_id": request.investigation_id, "scenario_id": inv.get("scenario_id"),
        "simulation": inv.get("simulation"), "detection_baseline": inv.get("detection_baseline"),
        "detection_improved_retest": inv.get("detection_improved_retest"),
        "lab_version": inv.get("lab_version"), "lab_commit": inv.get("lab_commit"),
        "source_references": [s.get("url") for s in
                              next((st.get("data", {}).get("sources", []) for st in inv.get("stages", [])
                                   if st.get("stage") == "research"), [])],
        "devin_session": None, "retest_history": [],
    }
    finding_id = store.create_finding(finding)
    return store.get_finding(finding_id)


@router.get("/findings")
async def list_verified_findings():
    return {"findings": store.list_findings()}


def _evidence_package(finding: dict) -> dict:
    """Exactly what Devin's handoff shows the operator for review BEFORE
    anything is sent — the same object is returned by both the preview and
    create-session endpoints so there is no discrepancy between what was
    shown and what was sent."""
    return {
        "finding_id": finding["id"], "title": finding["title"], "scenario_id": finding.get("scenario_id"),
        "simulation": finding.get("simulation"), "detection_baseline": finding.get("detection_baseline"),
        "detection_improved_retest": finding.get("detection_improved_retest"),
        "lab_version": finding.get("lab_version"), "lab_commit": finding.get("lab_commit"),
        "source_references": finding.get("source_references", []),
    }


@router.get("/findings/{finding_id}/devin-preview")
async def devin_preview(finding_id: str, repo: str):
    """Sanitised evidence package + destination repo, for the operator to
    review before any session is created. Makes NO network call."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="No such finding")
    allowed = repo in __import__("config").DEVIN_ALLOWED_REPOS
    return {"evidence_package": _evidence_package(finding), "destination_repo": repo,
            "repo_allowed": allowed, "devin_configured": devin_adapter.is_configured()}


class DevinHandoffRequest(BaseModel):
    repo: str


@router.post("/findings/{finding_id}/devin-handoff")
async def devin_handoff(finding_id: str, request: DevinHandoffRequest):
    """Creates ONE Devin session scoped to `repo`, from the exact evidence
    package devin_preview showed. Never called automatically — only by this
    explicit, human-initiated request on one specific verified finding."""
    finding = store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="No such finding")
    package = _evidence_package(finding)
    prompt = (
        f"Investigate and propose a fix for a verified security finding from an isolated lab.\n\n"
        f"Finding: {package['title']}\n"
        f"Scenario: {package['scenario_id']}\n"
        f"Simulation: {package['simulation']}\n"
        f"Baseline detection: {(package['detection_baseline'] or {}).get('detection')}\n"
        f"Improved-rule retest detection: {(package['detection_improved_retest'] or {}).get('retest_detection', {}).get('detection')}\n"
        f"Lab: {package['lab_version']} @ {package['lab_commit']}\n\n"
        "Propose a code fix as a branch/PR. Do not merge. Do not touch anything outside this repository."
    )
    try:
        session = await devin_adapter.create_investigation_session(
            repo=request.repo, prompt=prompt, title=f"Red Bears: {package['title']}")
    except IntegrationError as exc:
        raise HTTPException(status_code=409 if exc.status.value == "not_configured" else 502, detail=exc.detail)
    store.update_finding(finding_id, {"devin_session": session})
    return session


@router.get("/findings/{finding_id}/devin-session")
async def devin_session_status(finding_id: str):
    finding = store.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="No such finding")
    session = (finding.get("devin_session") or {})
    if not session.get("session_id"):
        raise HTTPException(status_code=404, detail="No Devin session has been created for this finding yet.")
    try:
        live = await devin_adapter.get_session(session["session_id"])
    except IntegrationError as exc:
        raise HTTPException(status_code=502, detail=exc.detail)
    return live
