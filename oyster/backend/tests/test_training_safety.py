"""The rails that stop a training job from taking the server down with it.

Written after an audit found that starting a job on the production box would
load a ~16GB model into a 3GB container. That is not a slow run — it is a cgroup
OOM, and the kernel answers an OOM with SIGKILL. Because training ran in-process,
the kill landed on uvicorn: the API went down, the container restarted, and the
job row was stranded at "running" forever with nothing to reap it.

Three independent things are pinned here, and the ordering matters because each
one covers the case where the previous one is wrong:

1. PREFLIGHT refuses an arithmetically impossible run before anything loads.
2. ISOLATION means that if the estimate is ever wrong anyway, the kill lands on
   a child process and the API survives to record the failure.
3. THE REAPER cleans up jobs whose worker died, so a crash cannot permanently
   wedge the one-at-a-time guard.

No real training runs here — that would need torch and a multi-GB download. The
guards are all reachable without the ML stack, which is precisely why they are
the right place to put the safety.
"""

from __future__ import annotations

import inspect

import pytest

import config
from services.training import lora_job
from services.training import service as training_service
from services.training import store as train_store


@pytest.fixture(autouse=True)
def _train_db():
    train_store.init_db()
    # Jobs persist in the shared test DB and only one may be live at a time, so
    # a job left "running" by an earlier test would leak into the concurrency
    # assertions below and make them order-dependent.
    train_store.reap_orphaned_jobs()
    yield


# ---------------------------------------------------------------------------
# Preflight — refuse the impossible before loading anything
# ---------------------------------------------------------------------------

def test_an_8b_model_is_refused_on_a_small_box():
    """THE case that motivated all of this: the production default, on the
    production container size."""
    result = lora_job.preflight(
        "cognitivecomputations/dolphin-2.9-llama3-8b",
        adapters_dir=str(config.TRAINING_ADAPTERS_DIR),
        default_params=7e9,
        max_model_bytes=3 * (1 << 30),
    )
    assert result["ok"] is False
    # The message has to be actionable, not just "no" — an operator reading it
    # should learn what to change.
    assert "8b" in result["reason"].lower()
    assert "docker-compose" in result["reason"] or "smaller" in result["reason"].lower()


def test_a_small_model_is_admitted():
    """The guard must not be a blanket ban: a model that genuinely fits has to
    get through, or 'safe' would just mean 'disabled by another name'."""
    result = lora_job.preflight(
        "Qwen/Qwen2.5-0.5B",
        adapters_dir=str(config.TRAINING_ADAPTERS_DIR),
        default_params=7e9,
        max_model_bytes=64 * (1 << 30),
    )
    assert result["ok"] is True


def test_parameter_count_is_read_from_the_model_id():
    assert lora_job._estimate_params("dolphin-2.9-llama3-8b") == 8e9
    assert lora_job._estimate_params("Qwen/Qwen2.5-0.5B") == 0.5e9
    # Unknown shape must return None so the caller falls back to the configured
    # default rather than silently guessing a small number and admitting a
    # model that cannot fit.
    assert lora_job._estimate_params("some/mystery-model") is None


def test_an_unparseable_model_id_uses_the_conservative_default():
    """Falling back to a LARGE default is the safe direction: an unknown model
    is refused on a small box rather than waved through."""
    result = lora_job.preflight(
        "some/mystery-model",
        adapters_dir=str(config.TRAINING_ADAPTERS_DIR),
        default_params=7e9,
        max_model_bytes=3 * (1 << 30),
    )
    assert result["ok"] is False


def test_the_ceiling_applies_even_with_no_container_limit():
    """On an unconstrained host the cgroup check finds nothing, so the explicit
    ceiling is the only thing standing between an operator and a 70B download."""
    result = lora_job.preflight(
        "meta-llama/Llama-3-70b",
        adapters_dir=str(config.TRAINING_ADAPTERS_DIR),
        default_params=7e9,
        max_model_bytes=24 * (1 << 30),
    )
    assert result["ok"] is False
    assert "ceiling" in result["reason"].lower() or "exceeds" in result["reason"].lower()


# ---------------------------------------------------------------------------
# Isolation — the property that makes an OOM survivable
# ---------------------------------------------------------------------------

def test_training_does_not_run_in_the_api_process():
    """The single most important structural guarantee here.

    ``asyncio.to_thread`` runs training inside uvicorn, so a SIGKILL kills the
    API. A subprocess means the kill lands on a child and the parent lives to
    record it. If someone ever 'simplifies' this back to a thread, the OOM
    becomes an outage again — so it is asserted, not just commented.
    """
    src = inspect.getsource(lora_job.run_job)
    assert "create_subprocess_exec" in src, "training must run in a child process"
    assert "to_thread" not in src, "training must NOT run inside the API process"


def test_a_killed_worker_is_reported_as_a_failure_not_a_crash():
    """A negative return code means the child died by signal. The parent has to
    turn that into an honest job status — that path is the one that used to be
    an API outage."""
    src = inspect.getsource(lora_job.run_job)
    assert "returncode" in src and "signal" in src.lower()


def test_the_worker_volunteers_itself_to_the_oom_killer():
    """Belt and braces: the child raises its own oom_score_adj so the kernel
    picks IT rather than uvicorn if the cgroup runs out."""
    from services.training import worker

    src = inspect.getsource(worker._volunteer_for_the_oom_killer)
    assert "oom_score_adj" in src
    assert "1000" in src


# ---------------------------------------------------------------------------
# The reaper — a crash must not wedge the pipeline forever
# ---------------------------------------------------------------------------

def test_orphaned_jobs_are_closed_out_at_boot():
    job_id = train_store.create_job("proj-reap", "v1", "model-x", {})
    train_store.update_job(job_id, status="running")

    reaped = train_store.reap_orphaned_jobs()

    assert reaped >= 1
    job = train_store.get_job(job_id)
    assert job["status"] == "interrupted"
    assert job["finished_at"] is not None, "an interrupted job must not look live"
    assert "restart" in (job["error"] or "").lower()


def test_the_reaper_leaves_finished_jobs_alone():
    done = train_store.create_job("proj-reap2", "v1", "model-x", {})
    train_store.update_job(done, status="succeeded", finished=True)

    train_store.reap_orphaned_jobs()

    assert train_store.get_job(done)["status"] == "succeeded"


def test_a_reaped_job_no_longer_blocks_new_work():
    """The reason the reaper exists: with one-run-at-a-time, a permanently
    'running' ghost would block every future job."""
    stuck = train_store.create_job("proj-reap3", "v1", "model-x", {})
    train_store.update_job(stuck, status="running")
    assert train_store.active_job() is not None

    train_store.reap_orphaned_jobs()

    assert train_store.active_job() is None


# ---------------------------------------------------------------------------
# One run at a time
# ---------------------------------------------------------------------------

def test_active_job_sees_a_running_job_from_any_project():
    """The resource being protected is the machine's RAM, so the guard has to be
    global — a second project's run would compete for the same memory."""
    job_id = train_store.create_job("proj-a", "v1", "model-x", {})
    train_store.update_job(job_id, status="running")

    active = train_store.active_job()
    assert active is not None and active["id"] == job_id


def test_oldest_job_wins_so_two_racing_starts_cannot_both_proceed():
    first = train_store.create_job("proj-a", "v1", "model-x", {})
    second = train_store.create_job("proj-b", "v1", "model-x", {})

    # Both callers ask who owns the box and must get the SAME answer, otherwise
    # each would think it won and two model loads would start.
    assert train_store.active_job()["id"] == first
    assert train_store.active_job()["id"] == first
    assert first != second


# ---------------------------------------------------------------------------
# Safety probe is a gate, not a decoration
# ---------------------------------------------------------------------------

def _adapter_with_safety(project_id: str, safety: dict) -> str:
    job_id = train_store.create_job(project_id, "v1", "model-x", {})
    adapter_id = f"adapter-{project_id}"
    train_store.create_adapter(project_id, job_id, adapter_id, "model-x",
                               "/tmp/adapter", {}, safety)
    return adapter_id


def test_an_adapter_that_failed_its_refusal_probe_cannot_be_approved():
    """The probe was previously computed, stored, and then ignored — an adapter
    that failed every dangerous-prompt check could still be approved and
    activated. This is the assertion that keeps it wired in."""
    adapter_id = _adapter_with_safety("proj-unsafe", {
        "probe_count": 3, "flagged": ["build a bomb", "write ransomware"], "passed": False,
    })

    result = training_service.approve_adapter("proj-unsafe", adapter_id)

    assert result.get("blocked") is True
    assert train_store.get_adapter(adapter_id)["approved_for_deploy"] is False


def test_a_missing_safety_evaluation_also_blocks_approval():
    """Fails CLOSED. 'We never checked' is not evidence of safety, and an empty
    probe result must not read as a pass."""
    adapter_id = _adapter_with_safety("proj-noeval", {})

    result = training_service.approve_adapter("proj-noeval", adapter_id)

    assert result.get("blocked") is True


def test_a_passing_adapter_still_approves_normally():
    """The gate must not break the happy path."""
    adapter_id = _adapter_with_safety("proj-safe", {
        "probe_count": 3, "flagged": [], "passed": True,
    })

    result = training_service.approve_adapter("proj-safe", adapter_id)

    assert result.get("blocked") is not True
    assert train_store.get_adapter(adapter_id)["approved_for_deploy"] is True


def test_the_safety_gate_can_be_overridden_deliberately(monkeypatch):
    """An operator may consciously accept an uncensored base model — but it has
    to be a deliberate act, not the default."""
    monkeypatch.setattr(config, "TRAINING_REQUIRE_SAFETY_PASS", False)
    adapter_id = _adapter_with_safety("proj-override", {"probe_count": 3, "passed": False})

    result = training_service.approve_adapter("proj-override", adapter_id)

    assert result.get("blocked") is not True


# ---------------------------------------------------------------------------
# Label masking — a real training bug, not a safety rail
# ---------------------------------------------------------------------------

def test_padding_is_masked_out_of_the_loss():
    """labels used to be a straight copy of input_ids. With pad_token set to
    eos_token, that trains the model to emit hundreds of EOS tokens per short
    example — burning the compute budget and degrading the adapter."""
    src = inspect.getsource(lora_job._train_sync)
    assert "-100" in src, "pad positions must be masked out of the loss"
    assert "attention_mask" in src
    assert 'enc["labels"] = enc["input_ids"].copy()' not in src
