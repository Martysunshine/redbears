"""The good/bad signal Oyster never had, and what the dataset builder does with it.

Before this existed, nothing anywhere distinguished a good answer from a bad
one. That is not a cosmetic gap. The training dataset was built from every past
(user, assistant) pair, so every hallucination, error and
"[local model unavailable: ...]" fallback was handed to the model as a positive
example to imitate. "Learning from mistakes" was, in practice, memorising them.

Two behaviours are pinned here, and the second is the one with the real value:

1. An answer marked wrong is EXCLUDED from training.
2. An answer marked wrong WITH a correction is not merely excluded — the
   correction replaces it as the training target. That is the only path by which
   a mistake actually improves the model rather than just being dropped.
"""

from __future__ import annotations

import pytest

import config
from services import conversation_service
from services.training import consent
from services.training import service as training_service
from services.training import store as train_store


@pytest.fixture(autouse=True)
def _db():
    conversation_service.init_db()
    train_store.init_db()
    train_store.reap_orphaned_jobs()
    yield


def _exchange(project_id: str, prompt: str, answer: str) -> tuple[str, str]:
    """Seed one user/assistant pair; return (conversation_id, assistant_msg_id)."""
    conv = conversation_service.create(project_id, "chat", "t")
    conversation_service.add_message(conv["id"], "user", prompt)
    msg = conversation_service.add_message(conv["id"], "assistant", answer)
    return conv["id"], msg["id"]


# ---------------------------------------------------------------------------
# Recording a verdict
# ---------------------------------------------------------------------------

def test_a_rating_round_trips():
    conv_id, msg_id = _exchange("proj-fb", "q", "a")
    result = conversation_service.set_feedback(conv_id, msg_id, "down", user_id="u1")
    assert result["rating"] == "down"

    stored = conversation_service.feedback_for_conversation(conv_id, "u1")
    assert stored[msg_id]["rating"] == "down"


def test_rating_the_same_message_twice_updates_rather_than_duplicates():
    """Changing your mind must replace your vote, not stack a second one — the
    UNIQUE(message_id, user_id) constraint is what enforces that."""
    conv_id, msg_id = _exchange("proj-fb2", "q", "a")
    conversation_service.set_feedback(conv_id, msg_id, "down", user_id="u1")
    conversation_service.set_feedback(conv_id, msg_id, "up", user_id="u1")

    stored = conversation_service.feedback_for_conversation(conv_id, "u1")
    assert stored[msg_id]["rating"] == "up"
    assert len(stored) == 1


def test_feedback_can_be_cleared():
    conv_id, msg_id = _exchange("proj-fb3", "q", "a")
    conversation_service.set_feedback(conv_id, msg_id, "up", user_id="u1")

    assert conversation_service.clear_feedback(msg_id, "u1") is True
    assert conversation_service.feedback_for_conversation(conv_id, "u1") == {}


def test_an_anonymous_vote_does_not_stack_duplicates():
    """user_id defaults to '' rather than NULL precisely because SQLite treats
    NULLs as distinct in a UNIQUE constraint — with NULL this would create a new
    row every click instead of updating one."""
    conv_id, msg_id = _exchange("proj-fb4", "q", "a")
    conversation_service.set_feedback(conv_id, msg_id, "down")
    conversation_service.set_feedback(conv_id, msg_id, "up")

    stored = conversation_service.feedback_for_conversation(conv_id)
    assert len(stored) == 1 and stored[msg_id]["rating"] == "up"


def test_an_invalid_rating_is_refused():
    conv_id, msg_id = _exchange("proj-fb5", "q", "a")
    assert conversation_service.set_feedback(conv_id, msg_id, "meh", user_id="u1") is None


def test_feedback_on_a_message_from_another_conversation_is_refused():
    """The message must genuinely belong to the conversation named in the URL,
    or one caller could rate rows in someone else's chat."""
    conv_a, _ = _exchange("proj-fb6", "q", "a")
    _, msg_b = _exchange("proj-fb6", "q2", "a2")

    assert conversation_service.set_feedback(conv_a, msg_b, "down", user_id="u1") is None


def test_one_persons_rating_is_not_shown_to_another():
    conv_id, msg_id = _exchange("proj-fb7", "q", "a")
    conversation_service.set_feedback(conv_id, msg_id, "down", user_id="u1")

    assert conversation_service.feedback_for_conversation(conv_id, "u2") == {}


# ---------------------------------------------------------------------------
# How the project-wide view resolves disagreement
# ---------------------------------------------------------------------------

def test_a_downvote_outranks_an_upvote_for_training():
    """If anyone flagged an answer as wrong, it is not a safe thing to teach —
    a single objection should win over a thumbs-up."""
    conv_id, msg_id = _exchange("proj-mix", "q", "a")
    conversation_service.set_feedback(conv_id, msg_id, "up", user_id="u1")
    conversation_service.set_feedback(conv_id, msg_id, "down", user_id="u2")

    assert conversation_service.feedback_map_for_project("proj-mix")[msg_id]["rating"] == "down"


def test_a_correction_is_preferred_over_a_bare_vote():
    conv_id, msg_id = _exchange("proj-mix2", "q", "a")
    conversation_service.set_feedback(conv_id, msg_id, "down", user_id="u1")
    conversation_service.set_feedback(conv_id, msg_id, "down",
                                      correction="The correct answer is X.", user_id="u2")

    resolved = conversation_service.feedback_map_for_project("proj-mix2")[msg_id]
    assert resolved["correction"] == "The correct answer is X."


# ---------------------------------------------------------------------------
# What the dataset builder does with it — the point of the whole feature
# ---------------------------------------------------------------------------

def _build(project_id: str, monkeypatch) -> dict:
    monkeypatch.setattr(config, "TRAINING_MIN_EXAMPLES", 1)
    consent.set_allowed(project_id, True)
    return training_service.build_dataset(project_id)


def _responses_in(result: dict, project_id: str) -> list[str]:
    import json
    from pathlib import Path

    out = []
    version_dir = Path(config.TRAINING_DATASETS_DIR) / project_id / result["version"]
    for split in ("train", "val", "test"):
        path = version_dir / f"{split}.jsonl"
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.append(json.loads(line)["response"])
    return out


def test_an_answer_marked_wrong_is_excluded_from_training(monkeypatch):
    """THE regression to fear: without this, training reproduces known-bad
    answers because nothing told it they were bad."""
    project = "proj-train-excl"
    conv_id, bad_msg = _exchange(project, "what is X?", "a wrong answer")
    _exchange(project, "what is Y?", "a fine answer")
    conversation_service.set_feedback(conv_id, bad_msg, "down", user_id="u1")

    result = _build(project, monkeypatch)

    assert result["ok"] is True
    assert result["excluded_by_feedback"] == 1
    responses = _responses_in(result, project)
    assert "a wrong answer" not in responses
    assert "a fine answer" in responses


def test_a_correction_replaces_the_wrong_answer_as_the_training_target(monkeypatch):
    """The whole point of collecting corrections. A thumbs-down alone only
    discards a bad example; a correction converts it into a good one, which is
    the only mechanism here by which a mistake actually improves the model."""
    project = "proj-train-corr"
    conv_id, bad_msg = _exchange(project, "what is X?", "X is purple")
    conversation_service.set_feedback(conv_id, bad_msg, "down",
                                      correction="X is green.", user_id="u1")

    result = _build(project, monkeypatch)

    assert result["ok"] is True
    assert result["corrected_by_feedback"] == 1
    assert result["excluded_by_feedback"] == 0, "a corrected example is kept, not dropped"
    responses = _responses_in(result, project)
    assert "X is green." in responses
    assert "X is purple" not in responses


def test_unrated_answers_are_still_used(monkeypatch):
    """Feedback must be opt-in enrichment, not a requirement — demanding a
    thumbs-up on every message before it counts would collect almost nothing."""
    project = "proj-train-unrated"
    _exchange(project, "q1", "a1")
    _exchange(project, "q2", "a2")

    result = _build(project, monkeypatch)

    assert result["ok"] is True
    assert result["excluded_by_feedback"] == 0
    assert set(_responses_in(result, project)) == {"a1", "a2"}


def test_the_manifest_records_how_much_was_vetted(monkeypatch):
    """A dataset should be judgeable on more than its size: how much was human
    corrected vs. how much is the model imitating itself."""
    project = "proj-train-manifest"
    conv_id, bad = _exchange(project, "q1", "bad")
    _exchange(project, "q2", "good")
    conversation_service.set_feedback(conv_id, bad, "down", correction="better", user_id="u1")

    result = _build(project, monkeypatch)

    import json
    from pathlib import Path
    manifest = json.loads(
        (Path(config.TRAINING_DATASETS_DIR) / project / result["version"] / "manifest.json")
        .read_text(encoding="utf-8"))
    assert manifest["corrected_by_feedback"] == 1
    assert "excluded_by_feedback" in manifest
