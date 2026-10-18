"""Builds a versioned, sanitized training dataset from ONE opted-in project's
conversations. This module intentionally imports nothing from
``services.knowledge.datasets`` or the dataset registry — registry datasets
structurally can never reach the training pipeline through this code path,
independent of the (also globally-disabled) training gate.

Pipeline: conversations → (user, assistant) exchange pairs → sensitive-content
gate (drop, don't redact-and-keep — a false negative in fine-tuning data is
far harder to undo than in a memory row) → exact-duplicate removal → seeded
deterministic shuffle → train/val/test split → JSONL snapshot on disk +
manifest row in SQLite.

Source scope today is conversation exchanges only ("user conversations" from
the request). Extending this to uploaded artifacts is a documented, not-yet-
built extension point — see the module docstring in ``services/training/service.py``.
"""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import config
from services import conversation_service
from services.media.redact import contains_sensitive

from . import consent, store


def _collect_examples(project_id: str) -> list[dict]:
    # Includes operator-owned conversations AND public users' chats where that
    # user accepted the CURRENT agreement version — see the consent join in
    # conversation_service.list_for_training. Because the join is evaluated live,
    # a withdrawal or a version bump drops those conversations from the next
    # build automatically.
    #
    # (This comment previously claimed public chats were excluded entirely. They
    # are not, and were not — a wrong privacy claim is worse than no comment, so
    # it is spelled out here rather than left to the SQL.)
    conversations = conversation_service.list_for_training(project_id, None)

    # What people actually thought of these answers. Without this the builder
    # treats every past reply as a good example — including the wrong ones — so
    # training would faithfully reproduce the model's own mistakes.
    feedback = conversation_service.feedback_map_for_project(project_id)

    examples: list[dict] = []
    rejected = 0
    corrected = 0
    for c in conversations:
        full = conversation_service.get(c["id"])
        if not full:
            continue
        messages = full["messages"]
        for i in range(1, len(messages)):
            if messages[i]["role"] == "assistant" and messages[i - 1]["role"] == "user":
                prompt = (messages[i - 1]["content"] or "").strip()
                response = (messages[i]["content"] or "").strip()
                if not (prompt and response):
                    continue

                verdict = feedback.get(messages[i]["id"])
                if verdict and verdict["rating"] == "down":
                    if verdict["correction"]:
                        # The valuable case, and the whole point of collecting
                        # corrections: train toward what the answer SHOULD have
                        # been rather than merely dropping the bad one. This is
                        # the only path by which a mistake improves the model.
                        response = verdict["correction"]
                        corrected += 1
                    else:
                        # Marked wrong with no correction offered — we know it is
                        # a bad target but not what a good one looks like.
                        rejected += 1
                        continue

                examples.append({"prompt": prompt, "response": response,
                                 "conversation_id": c["id"]})
    return examples, rejected, corrected


def _dedup(examples: list[dict]) -> tuple[list[dict], int]:
    seen: set[str] = set()
    out = []
    dupes = 0
    for ex in examples:
        h = hashlib.sha256(f"{ex['prompt']}\x00{ex['response']}".encode("utf-8")).hexdigest()
        if h in seen:
            dupes += 1
            continue
        seen.add(h)
        out.append(ex)
    return out, dupes


def build(project_id: str, notes: str = "") -> dict:
    """Raises ``consent.ConsentRequired`` if the project hasn't opted in."""
    consent.assert_allowed(project_id)

    raw, rejected_by_feedback, corrected_by_feedback = _collect_examples(project_id)
    sensitive_blocked = 0
    filtered = []
    for ex in raw:
        if contains_sensitive(ex["prompt"]) or contains_sensitive(ex["response"]):
            sensitive_blocked += 1
            continue
        filtered.append(ex)

    deduped, dup_count = _dedup(filtered)

    if len(deduped) < config.TRAINING_MIN_EXAMPLES:
        return {
            "ok": False,
            "error": f"Only {len(deduped)} usable example(s) after filtering "
                     f"(need at least {config.TRAINING_MIN_EXAMPLES}). "
                     f"Excluded {sensitive_blocked} for sensitive content, {dup_count} duplicates, "
                     f"{rejected_by_feedback} marked wrong without a correction.",
            "example_count": len(deduped),
            "excluded_sensitive": sensitive_blocked,
            "excluded_duplicate": dup_count,
            "excluded_by_feedback": rejected_by_feedback,
            "corrected_by_feedback": corrected_by_feedback,
        }

    rng = random.Random(project_id)  # deterministic per project
    shuffled = deduped[:]
    rng.shuffle(shuffled)

    n = len(shuffled)
    n_val = max(1, int(n * config.TRAINING_VAL_SPLIT))
    n_test = max(1, int(n * config.TRAINING_TEST_SPLIT))
    n_train = n - n_val - n_test
    if n_train < 1:
        n_train, n_val, n_test = n, 0, 0

    splits = {
        "train": shuffled[:n_train],
        "val": shuffled[n_train:n_train + n_val],
        "test": shuffled[n_train + n_val:],
    }

    version = hashlib.sha256(
        (project_id + str(len(shuffled)) + json.dumps([e["prompt"][:20] for e in shuffled[:5]])).encode()
    ).hexdigest()[:12]

    out_dir = config.TRAINING_DATASETS_DIR / project_id / version
    out_dir.mkdir(parents=True, exist_ok=True)
    for split_name, items in splits.items():
        path = out_dir / f"{split_name}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for ex in items:
                f.write(json.dumps({"prompt": ex["prompt"], "response": ex["response"]}) + "\n")

    manifest = {
        "project_id": project_id, "version": version,
        "example_count": len(shuffled), "train_count": len(splits["train"]),
        "val_count": len(splits["val"]), "test_count": len(splits["test"]),
        "excluded_sensitive": sensitive_blocked, "excluded_duplicate": dup_count,
        # Recorded so a dataset can be judged on more than its size: how much of
        # it was actively vetted, and how much came from a human correcting a
        # wrong answer rather than from the model imitating itself.
        "excluded_by_feedback": rejected_by_feedback,
        "corrected_by_feedback": corrected_by_feedback,
        "source": "conversation_exchanges", "notes": notes,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    record = store.create_dataset(
        project_id, version, example_count=len(shuffled), train_count=len(splits["train"]),
        val_count=len(splits["val"]), test_count=len(splits["test"]),
        excluded_sensitive=sensitive_blocked, excluded_duplicate=dup_count,
        manifest_path=str(out_dir / "manifest.json"), notes=notes,
    )
    # Surfaced on the response, not just in the manifest file, so a caller can
    # see how much of this dataset was human-vetted without reading it off disk.
    return {"ok": True, **record,
            "excluded_by_feedback": rejected_by_feedback,
            "corrected_by_feedback": corrected_by_feedback}
