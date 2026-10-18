"""Editing a previous message = truncate from it, then resend.

The backend half is ``conversation_service.truncate_from``: it deletes the target
message and everything after it, so the client can resend the edited text as a
fresh turn (a clean regenerated continuation, not a spliced history). Verified
here directly against a temp DB — no HTTP, no model.
"""

from __future__ import annotations

import pytest

from services import conversation_service as cs


@pytest.fixture
def conv():
    cs.init_db()
    c = cs.create("proj-edit", mode="basic", title="t", user_id="owner-1", owner_tier="user")
    ids = []
    for role, text in [
        ("user", "first question"),
        ("assistant", "first answer"),
        ("user", "second question"),
        ("assistant", "second answer"),
        ("user", "third question"),
    ]:
        ids.append(cs.add_message(c["id"], role, text)["id"])
    return c["id"], ids


def test_truncate_removes_the_message_and_everything_after(conv):
    cid, ids = conv
    # Edit the SECOND user message (index 2): it and everything after it go.
    removed = cs.truncate_from(cid, ids[2])
    assert removed == 3  # second question + second answer + third question
    left = cs.get(cid)["messages"]
    assert [m["content"] for m in left] == ["first question", "first answer"]
    # ord stays contiguous for what remains, so a resend appends cleanly.
    assert [m["ord"] for m in left] == [0, 1]


def test_truncate_from_first_message_clears_the_conversation(conv):
    cid, ids = conv
    removed = cs.truncate_from(cid, ids[0])
    assert removed == 5
    assert cs.get(cid)["messages"] == []


def test_truncate_unknown_message_is_none(conv):
    cid, _ = conv
    assert cs.truncate_from(cid, "does-not-exist") is None
    # Nothing was deleted.
    assert len(cs.get(cid)["messages"]) == 5


def test_truncate_is_scoped_to_the_conversation(conv):
    cid, ids = conv
    other = cs.create("proj-edit", mode="basic", title="o", user_id="owner-1", owner_tier="user")
    cs.add_message(other["id"], "user", "unrelated")
    # A message id from another conversation must not match here.
    assert cs.truncate_from(other["id"], ids[0]) is None
    assert len(cs.get(cid)["messages"]) == 5
    assert len(cs.get(other["id"])["messages"]) == 1


def test_resend_after_truncate_appends_with_correct_order(conv):
    cid, ids = conv
    cs.truncate_from(cid, ids[2])  # back to [first q, first a]
    new_user = cs.add_message(cid, "user", "edited second question")
    new_asst = cs.add_message(cid, "assistant", "new answer")
    assert new_user["ord"] == 2 and new_asst["ord"] == 3
    contents = [m["content"] for m in cs.get(cid)["messages"]]
    assert contents == ["first question", "first answer", "edited second question", "new answer"]
