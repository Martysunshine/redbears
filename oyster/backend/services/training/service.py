"""Training pipeline orchestration — disabled by default, consent-gated,
completely separate from RAG/memory. See module docstrings in
``dataset_builder.py`` and ``lora_job.py`` for the honest scope/limitations
(conversation-sourced examples only; LoRA execution requires torch/
transformers/peft, not installed by default; activation only updates
Oyster's own bookkeeping, not the live Ollama serving path).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import config
import log_config

from . import consent, dataset_builder, lora_job, store

init_db = store.init_db
get_consent = consent.is_allowed


def set_consent(project_id: str, allowed: bool) -> dict:
    result = consent.set_allowed(project_id, allowed)
    log_config.audit("training_consent_changed", {"project_id": project_id, "allowed": allowed})
    return result


def build_dataset(project_id: str, notes: str = "") -> dict:
    try:
        result = dataset_builder.build(project_id, notes=notes)
    except consent.ConsentRequired as e:
        return {"ok": False, "error": str(e)}
    log_config.audit("training_dataset_built", {"project_id": project_id,
                                                 "ok": result.get("ok"),
                                                 "example_count": result.get("example_count")})
    return result


def list_datasets(project_id: str) -> list[dict]:
    return store.list_datasets(project_id)


async def _run_and_record(job_id: str, project_id: str, dataset_dir: str, base_model: str,
                          epochs: int, learning_rate: float, adapter_id: str) -> None:
    """Await the isolated run and write its outcome to the job row.

    Runs as a detached task so the HTTP request that started it can return
    immediately — a training run is measured in hours, and holding a request
    open for that long previously tied the endpoint to the run's lifetime.
    """
    result = await lora_job.run_job(
        project_id, dataset_dir, base_model, epochs, learning_rate,
        str(config.TRAINING_ADAPTERS_DIR / project_id / adapter_id),
        job_id=job_id, timeout_s=config.TRAINING_MAX_RUNTIME_S,
        max_seq_len=config.TRAINING_MAX_SEQ_LEN,
    )

    if not result.get("ok"):
        store.update_job(job_id, status=result.get("status", "failed"),
                         error=result.get("error"), finished=True)
        log_config.audit("training_job_failed", {"project_id": project_id, "job_id": job_id,
                                                   "status": result.get("status"),
                                                   "error": result.get("error")})
        return

    store.update_job(job_id, status="succeeded", finished=True)
    store.create_adapter(
        project_id, job_id, adapter_id, base_model, result.get("adapter_path"),
        result.get("eval_metrics", {}), result.get("safety_eval", {}),
    )
    log_config.audit("training_job_succeeded", {"project_id": project_id, "job_id": job_id,
                                                  "adapter_id": adapter_id,
                                                  "safety_passed": result.get("safety_eval", {}).get("passed")})


async def start_job(project_id: str, dataset_version: str, base_model: str | None,
                    epochs: int, learning_rate: float) -> dict:
    """Validate, refuse anything impossible, then launch an isolated run.

    Every guard lives here rather than in the router because there are two entry
    points into training — the HTTP endpoint and ``scripts/daily_training.py`` —
    and a guard on only one of them protects nothing.
    """
    if not config.TRAINING_ENABLED:
        return {"ok": False, "status": "disabled",
                "error": "Training is switched off (OYSTER_TRAINING_ENABLED=false)."}
    if not consent.is_allowed(project_id):
        return {"ok": False, "error": "Project has not opted in to training data use "
                "('Allow my data for model improvement' is off)."}
    ds = store.get_dataset(project_id, dataset_version)
    if ds is None:
        return {"ok": False, "error": f"Dataset version '{dataset_version}' not found for this project. "
                "Build one first via POST .../training/dataset."}

    resolved_base_model = base_model or config.TRAINING_BASE_MODEL_HF_ID
    job_id = store.create_job(project_id, dataset_version, resolved_base_model,
                              {"epochs": epochs, "learning_rate": learning_rate})

    def _refuse(status: str, error: str, **extra) -> dict:
        store.update_job(job_id, status=status, error=error, finished=True)
        log_config.audit(f"training_job_{status}", {"project_id": project_id, "job_id": job_id,
                                                      "error": error})
        return {"ok": False, "status": status, "job_id": job_id, "error": error, **extra}

    # One run at a time. Checked AFTER creating the row so two interleaved starts
    # both compare against the same oldest-wins winner and exactly one proceeds.
    winner = store.active_job()
    if winner is not None and winner["id"] != job_id:
        return _refuse("rejected", f"Another training job ({winner['id']}) is already "
                                   f"{winner['status']}. Only one runs at a time — wait for it "
                                   f"to finish or cancel it.")

    deps = lora_job.check_deps()
    if not deps["available"]:
        return _refuse("unavailable",
                       f"Training dependencies not installed: {', '.join(deps['missing'])}.",
                       install_hint=deps["install_hint"])

    # The guard that matters: refuse an arithmetically impossible run before a
    # single byte of model is loaded, rather than discovering it via an OOM.
    pre = lora_job.preflight(
        resolved_base_model,
        adapters_dir=str(config.TRAINING_ADAPTERS_DIR),
        default_params=config.TRAINING_DEFAULT_PARAMS,
        max_model_bytes=config.TRAINING_MAX_MODEL_BYTES,
    )
    if not pre["ok"]:
        return _refuse("unavailable", pre["reason"])

    store.update_job(job_id, status="running")
    dataset_dir = str(Path(ds["manifest_path"]).parent)
    adapter_id = f"adapter-{job_id[5:]}"
    asyncio.create_task(_run_and_record(job_id, project_id, dataset_dir, resolved_base_model,
                                        epochs, learning_rate, adapter_id))
    log_config.audit("training_job_started", {"project_id": project_id, "job_id": job_id,
                                                "base_model": resolved_base_model})
    return {"ok": True, "status": "running", "job_id": job_id,
            "note": "Training runs in an isolated background process. Poll "
                    f"GET /projects/{project_id}/training/jobs/{job_id} for progress.",
            "preflight": pre}


def cancel_job(project_id: str, job_id: str) -> dict:
    job = store.get_job(job_id)
    if job is None or job["project_id"] != project_id:
        return {"ok": False, "error": "Job not found for this project."}
    if job["status"] not in ("queued", "running"):
        return {"ok": False, "error": f"Job is already '{job['status']}'."}
    killed = lora_job.cancel(job_id)
    store.update_job(job_id, status="cancelled",
                     error="Cancelled by operator.", finished=True)
    log_config.audit("training_job_cancelled", {"project_id": project_id, "job_id": job_id,
                                                  "worker_killed": killed})
    return {"ok": True, "job_id": job_id, "worker_killed": killed}


def get_job(job_id: str) -> dict | None:
    return store.get_job(job_id)


def list_jobs(project_id: str) -> list[dict]:
    return store.list_jobs(project_id)


def list_adapters(project_id: str) -> list[dict]:
    return store.list_adapters(project_id)


def approve_adapter(project_id: str, adapter_id: str, notes: str = "") -> dict | None:
    adapter = store.get_adapter(adapter_id)
    if adapter is None or adapter["project_id"] != project_id:
        return None

    # The refusal probe used to be computed, stored, and then ignored — an
    # adapter that failed every dangerous-prompt check could still be approved
    # and activated. Fail CLOSED: a missing or empty probe is also a refusal,
    # because "we never checked" is not evidence of safety.
    if config.TRAINING_REQUIRE_SAFETY_PASS:
        safety = adapter.get("safety_eval") or {}
        if safety.get("passed") is not True:
            flagged = safety.get("flagged") or []
            reason = ("no safety evaluation was recorded for this adapter"
                      if not safety else
                      f"{len(flagged)} of {safety.get('probe_count', '?')} refusal probes failed")
            log_config.audit("training_adapter_approval_blocked",
                             {"project_id": project_id, "adapter_id": adapter_id, "reason": reason})
            return {"ok": False, "blocked": True, "error": (
                f"Approval refused — {reason}. The adapter did not demonstrate that it still "
                f"refuses dangerous requests after fine-tuning. Set "
                f"OYSTER_TRAINING_REQUIRE_SAFETY_PASS=false to override deliberately.")}

    updated = store.approve_adapter(adapter_id, notes)
    log_config.audit("training_adapter_approved", {"project_id": project_id, "adapter_id": adapter_id})
    return updated


_DEPLOY_NOTE = (
    "Marked as the active adapter pointer in Oyster's own bookkeeping. This does NOT load "
    "the adapter into the live Ollama serving path — Oyster serves GGUF models via Ollama, "
    "and using this adapter there requires a manual merge + reconvert-to-GGUF step (llama.cpp) "
    "that is not wired up. Chat continues to use the configured Ollama model unchanged."
)


def activate_adapter(project_id: str, adapter_id: str) -> dict:
    adapter = store.get_adapter(adapter_id)
    if adapter is None or adapter["project_id"] != project_id:
        return {"ok": False, "error": "Adapter not found for this project."}
    if not adapter["approved_for_deploy"]:
        return {"ok": False, "error": "Adapter must be approved before activation."}
    store.set_active_adapter(project_id, adapter_id)
    log_config.audit("training_adapter_activated", {"project_id": project_id, "adapter_id": adapter_id})
    return {"ok": True, "adapter_id": adapter_id, "note": _DEPLOY_NOTE}


def rollback_adapter(project_id: str, adapter_id: str) -> dict:
    """Same mechanism as activation, framed for the rollback use case: point
    'active' back at a previously-approved adapter (e.g. after a regression)."""
    result = activate_adapter(project_id, adapter_id)
    if result.get("ok"):
        log_config.audit("training_adapter_rollback", {"project_id": project_id, "adapter_id": adapter_id})
    return result


def get_active_adapter(project_id: str) -> dict | None:
    return store.get_active_adapter(project_id)
