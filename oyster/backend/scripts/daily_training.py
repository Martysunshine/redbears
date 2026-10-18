#!/usr/bin/env python3
"""Daily LoRA training sweep — invoked by launchd, not by hand.

For every LOCAL project with training consent ON: builds a fresh dataset
snapshot from its conversation history and starts a real LoRA fine-tune IF
the resulting dataset version hasn't already been trained successfully.
Adapters are NOT wired into live chat (see services/training/service.py's
_DEPLOY_NOTE) — this exercises the pipeline for real and produces
inspectable adapters under config.TRAINING_ADAPTERS_DIR, nothing more.

Degrades gracefully by design: zero projects, zero consent, or fewer than
config.TRAINING_MIN_EXAMPLES examples are all expected, logged, non-error
outcomes. Missing `peft` is also a non-error outcome (logged once, exits 0).

Run directly for testing:
    cd oyster/backend && venv/bin/python3 scripts/daily_training.py
"""
from __future__ import annotations

import asyncio
import sys
import time

sys.path.insert(0, ".")

import log_config                                                    # noqa: E402
from memory import store as memory_store                             # noqa: E402
from services import conversation_service, db, project_service       # noqa: E402
from services.training import consent, lora_job                      # noqa: E402
from services.training import service as training_service            # noqa: E402
from services.training import store as training_store                # noqa: E402
from services.training import user_consent                           # noqa: E402


def _init_db() -> None:
    """Mirrors main.py's boot order for the subset this script touches.
    user_consent.init_db() is REQUIRED — conversation_service.list_for_training()
    joins user_training_consent, which only that module creates."""
    db.apply_startup_pragmas()
    memory_store.init_db()
    project_service.init_db()
    conversation_service.init_db()
    training_store.init_db()
    user_consent.init_db()


def _already_trained(project_id: str, dataset_version: str) -> bool:
    jobs = training_service.list_jobs(project_id)
    return any(j["dataset_version"] == dataset_version and j["status"] == "succeeded" for j in jobs)


async def _train_one(project: dict) -> dict:
    project_id = project["id"]
    if not consent.is_allowed(project_id):
        return {"project_id": project_id, "outcome": "consent_off"}

    try:
        ds_result = training_service.build_dataset(project_id)
    except Exception as e:  # noqa: BLE001
        log_config.error("daily_training", str(e), {"project_id": project_id, "stage": "build_dataset"})
        return {"project_id": project_id, "outcome": "dataset_build_failed", "error": str(e)}

    if not ds_result.get("ok"):
        # e.g. "Only 3 usable example(s) after filtering (need at least 20)."
        # The everyday outcome before real usage exists — not an error.
        return {"project_id": project_id, "outcome": "not_enough_examples", "detail": ds_result.get("error")}

    version = ds_result["version"]
    if _already_trained(project_id, version):
        return {"project_id": project_id, "outcome": "unchanged_since_last_success", "version": version}

    try:
        # base_model=None -> config.TRAINING_BASE_MODEL_HF_ID; epochs/lr = TrainingJobRequest schema defaults
        job_result = await training_service.start_job(project_id, version, None, 3, 2e-4)
    except Exception as e:  # noqa: BLE001
        log_config.error("daily_training", str(e),
                          {"project_id": project_id, "stage": "start_job", "version": version})
        return {"project_id": project_id, "outcome": "job_crashed", "error": str(e), "version": version}

    if not job_result.get("ok"):
        # Covers status "unavailable" (peft missing) and "failed" — start_job
        # already recorded + audited both via store.update_job / log_config.audit.
        return {"project_id": project_id, "outcome": job_result.get("status", "job_failed"),
                "error": job_result.get("error"), "version": version}

    return {"project_id": project_id, "outcome": "trained", "version": version,
            "adapter_id": job_result["adapter"]["id"]}


async def main() -> int:
    _init_db()
    started = time.monotonic()
    log_config.audit("daily_training_started", {})

    deps = lora_job.check_deps()
    if not deps["available"]:
        # Cheap early exit: avoids N pointless dataset builds when the one
        # missing dependency is the same for every project. start_job would
        # also catch this per-project, but there's no reason to pay for N
        # dataset builds just to discover the same thing N times.
        log_config.audit("daily_training_finished", {
            "project_count": 0, "trained": [], "failed": [],
            "note": f"training deps unavailable: {deps['install_hint']}",
        })
        print(f"daily training: skipped — {deps['install_hint']}")
        return 0

    try:
        projects = project_service.list_projects()
    except Exception as e:  # noqa: BLE001
        log_config.error("daily_training", str(e), {"stage": "list_projects"})
        log_config.audit("daily_training_aborted", {"error": str(e)})
        return 1

    results = [await _train_one(p) for p in projects]

    summary = {
        "project_count": len(projects),
        "trained": [r for r in results if r["outcome"] == "trained"],
        "unchanged": [r["project_id"] for r in results if r["outcome"] == "unchanged_since_last_success"],
        "consent_off": [r["project_id"] for r in results if r["outcome"] == "consent_off"],
        "not_enough_examples": [r["project_id"] for r in results if r["outcome"] == "not_enough_examples"],
        "failed": [r for r in results
                   if r["outcome"] in ("dataset_build_failed", "job_crashed", "failed", "unavailable")],
        "duration_s": round(time.monotonic() - started, 1),
    }
    log_config.audit("daily_training_finished", summary)
    print(f"daily training: {len(summary['trained'])} trained, {len(summary['failed'])} failed, "
          f"{len(projects)} project(s) total ({summary['duration_s']}s)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
