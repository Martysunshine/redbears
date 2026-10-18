"""Training pipeline API — disabled by default, project-scoped, consent-gated.

Completely separate from RAG/memory: nothing here changes what the live chat
model answers with. See ``services/training/`` module docstrings for the
honest scope (conversation-sourced examples only; LoRA execution needs torch/
transformers/peft, not installed by default; "activation" only updates
Oyster's own bookkeeping, not the Ollama serving path).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from models.schemas import (AdapterApproveRequest, TrainingConsentRequest,
                            TrainingDatasetBuildRequest, TrainingJobRequest)
from services import project_service
from services.training import lora_job, service as training_service

router = APIRouter(tags=["training"])


def _require_project(project_id: str) -> None:
    if project_service.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")


@router.get("/projects/{project_id}/training/consent")
async def get_consent(project_id: str):
    _require_project(project_id)
    return {"project_id": project_id, "allowed": training_service.get_consent(project_id)}


@router.put("/projects/{project_id}/training/consent")
async def set_consent(project_id: str, request: TrainingConsentRequest):
    _require_project(project_id)
    return training_service.set_consent(project_id, request.allow)


@router.get("/training/deps")
async def training_deps():
    """Whether the heavy ML stack (torch/transformers/peft) is installed."""
    return lora_job.check_deps()


@router.post("/projects/{project_id}/training/dataset")
async def build_dataset(project_id: str, request: TrainingDatasetBuildRequest):
    _require_project(project_id)
    result = training_service.build_dataset(project_id, notes=request.notes)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/projects/{project_id}/training/dataset")
async def list_datasets(project_id: str):
    _require_project(project_id)
    return {"datasets": training_service.list_datasets(project_id)}


@router.post("/projects/{project_id}/training/jobs")
async def start_job(project_id: str, request: TrainingJobRequest):
    _require_project(project_id)
    result = await training_service.start_job(
        project_id, request.dataset_version, request.base_model, request.epochs, request.learning_rate,
    )
    if not result.get("ok") and result.get("status") is None:
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/projects/{project_id}/training/jobs")
async def list_jobs(project_id: str):
    _require_project(project_id)
    return {"jobs": training_service.list_jobs(project_id)}


@router.get("/projects/{project_id}/training/jobs/{job_id}")
async def get_job(project_id: str, job_id: str):
    _require_project(project_id)
    job = training_service.get_job(job_id)
    if job is None or job["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job


@router.post("/projects/{project_id}/training/jobs/{job_id}/cancel")
async def cancel_job(project_id: str, job_id: str):
    """Stop a running job. Kills the isolated worker process if it is still up."""
    _require_project(project_id)
    result = training_service.cancel_job(project_id, job_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.get("/projects/{project_id}/training/adapters")
async def list_adapters(project_id: str):
    _require_project(project_id)
    return {"adapters": training_service.list_adapters(project_id),
            "active": training_service.get_active_adapter(project_id)}


@router.post("/projects/{project_id}/training/adapters/{adapter_id}/approve")
async def approve_adapter(project_id: str, adapter_id: str, request: AdapterApproveRequest):
    _require_project(project_id)
    result = training_service.approve_adapter(project_id, adapter_id, request.notes)
    if result is None:
        raise HTTPException(status_code=404, detail="Adapter not found for this project.")
    if result.get("blocked"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return {"ok": True, "adapter": result}


@router.post("/projects/{project_id}/training/adapters/{adapter_id}/activate")
async def activate_adapter(project_id: str, adapter_id: str):
    _require_project(project_id)
    result = training_service.activate_adapter(project_id, adapter_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/projects/{project_id}/training/adapters/{adapter_id}/rollback")
async def rollback_adapter(project_id: str, adapter_id: str):
    _require_project(project_id)
    result = training_service.rollback_adapter(project_id, adapter_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result
