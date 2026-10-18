"""The public findings feed and the nicknames it shows.

Publishing is the one place Oyster shows one account's content to another, so
what the feed does and does NOT carry is worth pinning down: a handle, never an
email; no owner, project, conversation or message ids; and un-publishing takes
effect immediately.
"""

from __future__ import annotations

import sqlite3

import pytest

import config
from services import user_findings_service as uf
from services import user_profiles as up


@pytest.fixture(autouse=True)
def fresh():
    con = sqlite3.connect(str(config.MEMORY_DB))
    con.execute("DROP TABLE IF EXISTS user_findings")
    con.execute("DROP TABLE IF EXISTS user_profiles")
    # up.init_db() backfills member numbers from any existing conversations/
    # projects rows. The shared temp DB lives for the whole test session, so
    # without clearing those too, leftover rows from whichever test file
    # happened to run earlier leak into the numbering here and make these
    # tests order-dependent (e.g. "first" landing on member 2, not 1).
    # Emptying (not dropping — those tables' own fixtures own their schema)
    # keeps this file's expectations stable regardless of run order.
    for t in ("conversations", "projects"):
        try:
            con.execute(f"DELETE FROM {t}")
        except sqlite3.OperationalError:
            pass  # not created yet in this run order
    con.commit()
    con.close()
    uf.init_db()
    up.init_db()
    yield


# --- nicknames --------------------------------------------------------------

def test_members_are_numbered_in_order_and_default_to_user_n():
    assert up.ensure("first")["member_no"] == 1
    assert up.ensure("second")["member_no"] == 2
    assert up.handle("first") == "User 1"
    assert up.handle("second") == "User 2"
    # ensure() is idempotent — a second call must not burn a new number.
    assert up.ensure("first")["member_no"] == 1


def test_nickname_overrides_the_generated_handle_and_can_be_cleared():
    up.ensure("a")
    up.set_display_name("a", "  n0ctis  ")
    assert up.handle("a") == "n0ctis"
    up.set_display_name("a", "")
    assert up.handle("a") == "User 1"


@pytest.mark.parametrize("bad", ["User 4", "user7", "USER  12", "x" * 33, "bad\nname"])
def test_reserved_and_invalid_nicknames_are_refused(bad):
    """"User N" is generated, so nobody may claim someone else's; and a name
    must not be over-long or carry control characters that break the layout."""
    up.ensure("a")
    with pytest.raises(up.NameRejected):
        up.set_display_name("a", bad)
    assert up.handle("a") == "User 1"


def test_handle_is_never_an_email():
    up.ensure("sub-of-someone")
    assert "@" not in up.handle("sub-of-someone")


# --- the feed ---------------------------------------------------------------

def test_only_published_findings_appear():
    up.ensure("alice"); up.ensure("bob")
    private = uf.create("alice", "u_alice", "private body", title="Private")
    public = uf.create("bob", "u_bob", "public body", title="Public", severity="high")
    assert uf.list_public("alice")[0] == []
    uf.set_share(public["id"])
    feed, _total = uf.list_public("alice")
    assert [f["title"] for f in feed] == ["Public"]
    assert uf.count_public() == 1
    assert private["id"] not in [f["id"] for f in feed]


def test_feed_carries_a_handle_and_no_identifying_ids():
    up.ensure("alice"); up.ensure("bob")
    f = uf.create("bob", "u_bob", "body", title="Bob's")
    uf.set_share(f["id"])
    item = uf.list_public("alice")[0][0]
    assert item["author"] == "User 2"
    for leaked in ("user_id", "project_id", "conversation_id", "message_id", "share_token"):
        assert leaked not in item, f"feed leaked {leaked}"


def test_is_mine_marks_the_viewers_own_rows():
    up.ensure("alice"); up.ensure("bob")
    mine = uf.create("alice", "u_alice", "x", title="Mine")
    theirs = uf.create("bob", "u_bob", "y", title="Theirs")
    uf.set_share(mine["id"]); uf.set_share(theirs["id"])
    feed = {f["title"]: f["is_mine"] for f in uf.list_public("alice")[0]}
    assert feed == {"Mine": True, "Theirs": False}


def test_making_private_removes_it_from_the_feed_at_once():
    up.ensure("alice")
    f = uf.create("alice", "u_alice", "body", title="Published")
    uf.set_share(f["id"])
    assert uf.count_public() == 1
    uf.revoke_share(f["id"])
    assert uf.list_public("alice")[0] == []
    assert uf.count_public() == 0


def test_shared_page_shows_the_handle_but_not_the_owner():
    up.ensure("alice")
    f = uf.create("alice", "u_alice", "body", title="Published")
    tok = uf.set_share(f["id"])
    pub = uf.get_by_token(tok)
    assert pub["author"] == "User 1"
    assert "user_id" not in pub and "project_id" not in pub


def test_feed_is_newest_first_and_paginates():
    up.ensure("alice")
    ids = []
    for n in range(5):
        f = uf.create("alice", "u_alice", "body", title=f"F{n}")
        uf.set_share(f["id"])
        ids.append(f["id"])
    assert len(uf.list_public("alice", limit=2)[0]) == 2
    assert len(uf.list_public("alice", limit=2, offset=4)[0]) == 1
    assert uf.count_public() == 5


def test_total_comes_back_with_the_page_not_a_second_query():
    """The router needs page + total; fetching them separately meant scanning
    the table twice on every feed load."""
    up.ensure("alice")
    for n in range(7):
        uf.set_share(uf.create("alice", "u_alice", "b", title=f"F{n}")["id"])
    page, total = uf.list_public("alice", limit=3)
    assert len(page) == 3
    assert total == 7                      # the FULL count, not the page size
    assert uf.list_public("alice", limit=3, offset=6)[1] == 7
    assert uf.list_public("alice")[1] == uf.count_public()


def test_feed_query_uses_the_index_instead_of_sorting_everything():
    """Guards the reason idx_uf_feed exists: without it every feed load sorts
    the whole table in a temp B-tree."""
    up.ensure("alice")
    for n in range(20):
        uf.set_share(uf.create("alice", "u_alice", "b", title=f"F{n}")["id"])
    con = sqlite3.connect(str(config.MEMORY_DB))
    plan = " ".join(
        str(r) for r in con.execute(
            "EXPLAIN QUERY PLAN SELECT id FROM user_findings "
            "WHERE share_token IS NOT NULL ORDER BY shared_at DESC LIMIT 10"
        ).fetchall()
    )
    con.close()
    assert "idx_uf_feed" in plan, plan
    assert "TEMP B-TREE" not in plan.upper(), plan
