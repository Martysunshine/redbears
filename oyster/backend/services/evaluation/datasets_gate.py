"""Deterministic governance gate for evaluation.

Two guarantees, enforced in code (not prose):

1. **Training is globally disabled.** ``assert_training_forbidden`` always raises;
   there is no code path in the harness that trains or fine-tunes.
2. A registry dataset may be used for evaluation only when its governance record
   says so (``evaluation_eligibility`` allows it) *and* it is not
   training-only. Dataset **content is never stored** as retrievable knowledge —
   the gate authorizes *scoring against* a dataset, never ingesting it.

The gate reads ``knowledge_registries/datasets.json`` (the same governed registry
surfaced read-only elsewhere).
"""

from __future__ import annotations

from services.knowledge import registries


class TrainingForbidden(RuntimeError):
    pass


class DatasetNotEvalEligible(RuntimeError):
    pass


def assert_training_forbidden() -> None:
    """There is no permitted training path. Always raises."""
    raise TrainingForbidden(
        "Model training/fine-tuning is globally disabled in Oyster. The evaluation "
        "harness only scores retrieval output; it never trains.")


def _find_dataset(dataset_id: str) -> dict | None:
    for item in registries.datasets().get("items", []):
        if item.get("id") == dataset_id:
            return item
    return None


def evaluate_dataset(dataset_id: str) -> dict:
    """Governance decision for using ``dataset_id`` in evaluation.

    Returns ``{dataset_id, found, eval_allowed, training_allowed(False),
    stored_as_knowledge(False), reasons}``. Never raises — callers decide.
    """
    item = _find_dataset(dataset_id)
    if item is None:
        return {"dataset_id": dataset_id, "found": False, "eval_allowed": False,
                "training_allowed": False, "stored_as_knowledge": False,
                "reasons": [f"dataset '{dataset_id}' is not in the governed registry"]}

    reasons: list[str] = []
    elig = (item.get("evaluation_eligibility") or "").lower()
    eval_allowed = elig.startswith("allowed")
    if not eval_allowed:
        reasons.append(f"evaluation_eligibility='{item.get('evaluation_eligibility')}' — not eval-eligible")
    if (item.get("training_eligibility") or "").lower().startswith("allowed"):
        # Even if a card said training-ok, Oyster's global disable overrides.
        reasons.append("training requested is ignored — training globally disabled")
    if item.get("review_status") == "not-reviewed":
        reasons.append("dataset not yet human-reviewed; eval requires manual provisioning "
                       "(auto_download is false)")
    return {
        "dataset_id": dataset_id,
        "found": True,
        "name": item.get("name"),
        "licence": item.get("licence"),
        "eval_allowed": eval_allowed,
        "training_allowed": False,
        "stored_as_knowledge": False,
        "auto_download_allowed": bool(item.get("auto_download_allowed", False)),
        "reasons": reasons or ["evaluation permitted (content is scored, never stored)"],
    }


def assert_dataset_eval_allowed(dataset_id: str) -> dict:
    decision = evaluate_dataset(dataset_id)
    if not decision["eval_allowed"]:
        raise DatasetNotEvalEligible("; ".join(decision["reasons"]))
    return decision
