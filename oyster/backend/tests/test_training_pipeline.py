"""Training pipeline — consent gate, structural exclusion of registry datasets,
sensitive-content redaction, dedup, deterministic splits, adapter versioning/
approval/activation/rollback, and honest "unavailable" reporting when the
heavy ML deps aren't installed.

No real LoRA training ever runs in these tests (that would need torch/
transformers/peft + a real base model download) — ``lora_job.run_job`` is
exercised only through its dependency-check short-circuit, which is exactly
the path that matters here: Oyster must never fabricate a training run.
"""

from __future__ import annotations

import inspect
import json

import pytest

import config
from services import conversation_service
from services.training import consent, dataset_builder, lora_job
from services.training import service as training_service
from services.training import store as train_store


@pytest.fixture(autouse=True)
def _train_db():
    train_store.init_db()
    conversation_service.init_db()
    # Jobs persist in the shared test DB, and only one training job may be live
    # at a time — so a job left "running" by an earlier test would make every
    # later start_job refuse with "another job is already running", turning these
    # tests order-dependent. Clearing live jobs gives each test a clean slate.
    train_store.reap_orphaned_jobs()
    yield


# Adapters below are created to exercise approval/activation/rollback plumbing,
# not the safety gate — but approval now fails closed on a missing refusal probe
# (see test_training_safety.py). Passing a probe result keeps these tests about
# the thing they are actually testing.
_SAFETY_PASSED = {"probe_count": 3, "flagged": [], "passed": True}


def test_list_for_training_works_before_any_consent_table_initialization():
    """Regression test for a real bug: conversation_service.list_for_training()
    queried user_training_consent without ensuring it exists. In the real app
    main.py creates it at startup, but any OTHER caller — a script, a test, a
    future entrypoint — that reaches this function first must not crash just
    because the app's startup sequence hasn't run."""
    from services.training import user_consent

    with user_consent._conn() as con:
        con.execute("DROP TABLE IF EXISTS user_training_consent")
        con.commit()

    # Must not raise even though the table doesn't exist yet.
    result = conversation_service.list_for_training("proj-never-initialized")
    assert result == []


def _seed_conversation(project_id: str, exchanges: list[tuple[str, str]], conv_id_suffix: str = "") -> str:
    conv = conversation_service.create(project_id, "chat", f"conv{conv_id_suffix}")
    for user_msg, assistant_msg in exchanges:
        conversation_service.add_message(conv["id"], "user", user_msg)
        conversation_service.add_message(conv["id"], "assistant", assistant_msg)
    return conv["id"]


# ---------------------------------------------------------------------------
# Consent gate
# ---------------------------------------------------------------------------

def test_consent_defaults_to_false():
    assert consent.is_allowed("proj-new") is False


def test_consent_toggle_roundtrip():
    consent.set_allowed("proj-c", True)
    assert consent.is_allowed("proj-c") is True
    consent.set_allowed("proj-c", False)
    assert consent.is_allowed("proj-c") is False


def test_dataset_build_requires_consent():
    _seed_conversation("proj-noconsent", [("hi", "hello")])
    result = training_service.build_dataset("proj-noconsent")
    assert result["ok"] is False
    assert "opted in" in result["error"] or "consent" in result["error"].lower()


def test_assert_allowed_raises_when_not_consented():
    with pytest.raises(consent.ConsentRequired):
        consent.assert_allowed("proj-strict")


# ---------------------------------------------------------------------------
# Structural guarantee: registry datasets can never reach training
# ---------------------------------------------------------------------------

def test_dataset_builder_never_imports_dataset_registry():
    """Checks the module's actual import table (not prose in the docstring,
    which legitimately references these names when explaining the guarantee)."""
    for name, val in vars(dataset_builder).items():
        if inspect.ismodule(val):
            assert not val.__name__.startswith("services.knowledge.datasets"), \
                f"dataset_builder imports {val.__name__} — registry datasets could leak into training"
    source_lines = [l for l in inspect.getsource(dataset_builder).splitlines()
                    if l.strip().startswith(("import ", "from "))]
    joined = "\n".join(source_lines)
    assert "knowledge.datasets" not in joined
    assert "hf_source" not in joined


def test_global_evaluation_training_gate_still_forbids():
    from services.evaluation import datasets_gate
    with pytest.raises(datasets_gate.TrainingForbidden):
        datasets_gate.assert_training_forbidden()


# ---------------------------------------------------------------------------
# Dataset builder: redaction, dedup, min-examples, deterministic disjoint splits
# ---------------------------------------------------------------------------

def test_sensitive_examples_excluded_from_dataset(monkeypatch):
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 1)
    consent.set_allowed("proj-sens", True)
    _seed_conversation("proj-sens", [
        ("what's my aws key", "AKIAABCDEFGHIJKLMNOP is your key"),
        ("how do I scan a host", "use nmap -sV target"),
        ("what's my password", "password=hunter2xyz123"),
    ])
    result = training_service.build_dataset("proj-sens")
    assert result["ok"] is True
    assert result["excluded_sensitive"] == 2
    assert result["example_count"] == 1

    train_path = config.TRAINING_DATASETS_DIR / "proj-sens" / result["version"] / "train.jsonl"
    content = train_path.read_text()
    assert "AKIA" not in content
    assert "hunter2xyz123" not in content


def test_duplicate_examples_deduped(monkeypatch):
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 2)
    consent.set_allowed("proj-dedup", True)
    _seed_conversation("proj-dedup", [
        ("how do I scan a host", "use nmap -sV target"),
        ("how do I scan a host", "use nmap -sV target"),
        ("what is xss", "cross-site scripting is..."),
    ])
    result = training_service.build_dataset("proj-dedup")
    assert result["ok"] is True
    assert result["excluded_duplicate"] == 1
    assert result["example_count"] == 2


def test_insufficient_examples_reports_clearly(monkeypatch):
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 50)
    consent.set_allowed("proj-few", True)
    _seed_conversation("proj-few", [("hi", "hello")])
    result = training_service.build_dataset("proj-few")
    assert result["ok"] is False
    assert result["example_count"] == 1


def test_splits_are_deterministic_and_disjoint(monkeypatch):
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 5)
    monkeypatch.setattr(config, "TRAINING_VAL_SPLIT", 0.2)
    monkeypatch.setattr(config, "TRAINING_TEST_SPLIT", 0.2)
    consent.set_allowed("proj-split", True)
    exchanges = [(f"question number {i}", f"answer number {i}") for i in range(10)]
    _seed_conversation("proj-split", exchanges)

    r1 = training_service.build_dataset("proj-split")
    assert r1["ok"] is True
    assert r1["train_count"] + r1["val_count"] + r1["test_count"] == r1["example_count"]

    def _load(split):
        path = config.TRAINING_DATASETS_DIR / "proj-split" / r1["version"] / f"{split}.jsonl"
        return {json.loads(line)["prompt"] for line in path.read_text().splitlines() if line.strip()}

    train_prompts, val_prompts, test_prompts = _load("train"), _load("val"), _load("test")
    assert not (train_prompts & val_prompts)
    assert not (train_prompts & test_prompts)
    assert not (val_prompts & test_prompts)

    # deterministic: rebuilding from the same conversations yields the same version id
    r2 = training_service.build_dataset("proj-split")
    assert r2["version"] == r1["version"]


# ---------------------------------------------------------------------------
# LoRA execution: honest "unavailable" when deps are missing (never fabricated)
# ---------------------------------------------------------------------------

def test_check_deps_reports_missing_honestly(monkeypatch):
    monkeypatch.setattr(lora_job, "_REQUIRED", ("definitely_not_a_real_package",))
    deps = lora_job.check_deps()
    assert deps["available"] is False
    assert "definitely_not_a_real_package" in deps["missing"]
    assert "pip install" in deps["install_hint"]


@pytest.mark.asyncio
async def test_run_job_never_fabricates_when_deps_missing(monkeypatch):
    monkeypatch.setattr(lora_job, "check_deps",
                        lambda: {"available": False, "missing": ["torch"], "install_hint": "pip install torch"})
    result = await lora_job.run_job("proj-x", "/tmp/whatever", "some/base-model", 1, 1e-4,
                                    "/tmp/adapter", job_id="tjob-test", timeout_s=60)
    assert result["ok"] is False
    assert result["status"] == "unavailable"
    assert "torch" in result["error"]


@pytest.mark.asyncio
async def test_start_job_reports_unavailable_and_creates_no_adapter(monkeypatch):
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 2)
    consent.set_allowed("proj-job", True)
    _seed_conversation("proj-job", [
        ("q1", "a1"), ("q2", "a2"), ("q3", "a3"),
    ])
    built = training_service.build_dataset("proj-job")
    assert built["ok"] is True

    monkeypatch.setattr(
        lora_job, "check_deps",
        lambda: {"available": False, "missing": ["peft"], "install_hint": "pip install peft"},
    )
    result = await training_service.start_job("proj-job", built["version"], None, 1, 1e-4)
    assert result["ok"] is False
    assert result["status"] == "unavailable"
    assert training_service.list_adapters("proj-job") == []


@pytest.mark.asyncio
async def test_start_job_requires_consent_even_with_a_built_dataset(monkeypatch):
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 1)
    consent.set_allowed("proj-rug", True)
    _seed_conversation("proj-rug", [("q", "a"), ("q2", "a2")])
    built = training_service.build_dataset("proj-rug")
    assert built["ok"] is True

    consent.set_allowed("proj-rug", False)  # revoke after building
    result = await training_service.start_job("proj-rug", built["version"], None, 1, 1e-4)
    assert result["ok"] is False


# ---------------------------------------------------------------------------
# Adapter versioning / approval / activation / rollback
# ---------------------------------------------------------------------------

def test_adapter_versions_increment():
    a1 = train_store.create_adapter("proj-v", "job1", "adapter-v-1", "base-model", "/tmp/a1", {}, {})
    a2 = train_store.create_adapter("proj-v", "job2", "adapter-v-2", "base-model", "/tmp/a2", {}, {})
    assert a1["version"] == 1
    assert a2["version"] == 2


def test_activation_requires_approval_first():
    train_store.create_adapter("proj-act", "job1", "adapter-a", "base-model", "/tmp/a", {}, _SAFETY_PASSED)
    result = training_service.activate_adapter("proj-act", "adapter-a")
    assert result["ok"] is False

    training_service.approve_adapter("proj-act", "adapter-a", notes="looks fine")
    result2 = training_service.activate_adapter("proj-act", "adapter-a")
    assert result2["ok"] is True
    assert training_service.get_active_adapter("proj-act")["id"] == "adapter-a"


def test_activation_does_not_cross_projects():
    train_store.create_adapter("proj-iso1", "job1", "adapter-iso", "base-model", "/tmp/a", {}, _SAFETY_PASSED)
    approved = training_service.approve_adapter("proj-iso1", "adapter-iso")
    # Guard the guard: if approval were blocked, activation would fail for the
    # WRONG reason and this test would pass without ever testing isolation.
    assert approved.get("blocked") is not True
    result = training_service.activate_adapter("proj-iso2", "adapter-iso")
    assert result["ok"] is False


def test_rollback_reactivates_previous_adapter():
    train_store.create_adapter("proj-rb", "job1", "adapter-rb-1", "base-model", "/tmp/a1", {}, _SAFETY_PASSED)
    train_store.create_adapter("proj-rb", "job2", "adapter-rb-2", "base-model", "/tmp/a2", {}, _SAFETY_PASSED)
    training_service.approve_adapter("proj-rb", "adapter-rb-1")
    training_service.approve_adapter("proj-rb", "adapter-rb-2")

    training_service.activate_adapter("proj-rb", "adapter-rb-2")
    assert training_service.get_active_adapter("proj-rb")["id"] == "adapter-rb-2"

    rollback = training_service.rollback_adapter("proj-rb", "adapter-rb-1")
    assert rollback["ok"] is True
    assert training_service.get_active_adapter("proj-rb")["id"] == "adapter-rb-1"


def test_only_one_active_adapter_per_project():
    train_store.create_adapter("proj-single", "job1", "adapter-single-1", "base-model", "/tmp/a1", {}, _SAFETY_PASSED)
    train_store.create_adapter("proj-single", "job2", "adapter-single-2", "base-model", "/tmp/a2", {}, _SAFETY_PASSED)
    training_service.approve_adapter("proj-single", "adapter-single-1")
    training_service.approve_adapter("proj-single", "adapter-single-2")
    training_service.activate_adapter("proj-single", "adapter-single-1")
    training_service.activate_adapter("proj-single", "adapter-single-2")

    adapters = training_service.list_adapters("proj-single")
    active = [a for a in adapters if a["active"]]
    assert len(active) == 1
    assert active[0]["id"] == "adapter-single-2"
