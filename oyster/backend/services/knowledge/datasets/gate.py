"""Governance gate for Dataset RAG — a SEPARATE decision from evaluation-scoring
governance (``services/evaluation/datasets_gate.py``).

Storing dataset rows as retrievable RAG content is a stronger claim than
"score against this dataset": it means the content is fetched and persisted
(as an eval-only, clearly-labeled collection). A dataset is only ever fetched
here when its OWN registry record says ``rag_eligible: true`` AND
``review_status`` starts with ``reviewed`` — both fields are set by a human
operator reviewing the dataset's card, never inferred or flipped by this code.
Training eligibility is irrelevant here and is ignored either way: Oyster's
training pipeline never reads from this registry (see
``services/training/dataset_builder.py``).
"""

from __future__ import annotations

from services.knowledge import registries
from services.knowledge.connectors import licensing


def _find(dataset_id: str) -> dict | None:
    for item in registries.datasets().get("items", []):
        if item.get("id") == dataset_id:
            return item
    return None


def evaluate_for_rag(dataset_id: str) -> dict:
    """Returns ``{dataset_id, found, allowed, reasons, hf_dataset_id, ...}``.
    Never raises — callers decide what to do with ``allowed=False``."""
    item = _find(dataset_id)
    if item is None:
        return {"dataset_id": dataset_id, "found": False, "allowed": False,
                "reasons": [f"dataset '{dataset_id}' is not in the governed registry"]}

    reasons: list[str] = []
    rag_eligible = bool(item.get("rag_eligible", False))
    if not rag_eligible:
        reasons.append("rag_eligible is not set to true — requires explicit operator review "
                       "of the dataset card before any fetch")
    review_status = str(item.get("review_status", ""))
    if not review_status.startswith("reviewed"):
        reasons.append(f"review_status='{review_status}' — not yet human-reviewed")
    licence_token = licensing.normalize_licence(item.get("licence"))
    if licence_token is None:
        reasons.append(f"licence '{item.get('licence')}' is not recognized by the licensing policy")
    hf_dataset_id = item.get("hf_dataset_id")
    if not hf_dataset_id:
        reasons.append("no hf_dataset_id declared — nothing to fetch")

    allowed = rag_eligible and review_status.startswith("reviewed") and licence_token is not None and bool(hf_dataset_id)
    return {
        "dataset_id": dataset_id, "found": True, "name": item.get("name"),
        "licence": item.get("licence"), "licence_token": licence_token,
        "hf_dataset_id": hf_dataset_id, "hf_config": item.get("hf_config"),
        "hf_split": item.get("hf_split"),
        "allowed": allowed,
        "reasons": reasons or ["approved for evaluation-only Dataset RAG ingestion"],
        "training_note": "training_eligibility on this record is always ignored — Oyster's "
                         "training pipeline never reads from the dataset registry regardless "
                         "of this decision (see services/training/dataset_builder.py).",
    }


def list_all() -> list[dict]:
    return [evaluate_for_rag(item["id"]) for item in registries.datasets().get("items", [])]
