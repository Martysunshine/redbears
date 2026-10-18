"""Pins the frozen legitimate-use suite's shape so it can't silently drift."""
from tests.legitimate_use_suite import build_suite, EXPECTED_COUNTS
from collections import Counter


def test_category_counts_match_design():
    s = build_suite()
    c = Counter(x.category for x in s)
    assert len(s) == 300
    for cat, want in EXPECTED_COUNTS.items():
        assert c[cat] == want, f"{cat}: {c[cat]} != {want}"


def test_ids_unique_and_split_is_frozen():
    s = build_suite()
    ids = [x.id for x in s]
    assert len(set(ids)) == len(ids)
    held = sum(1 for x in s if x.held_out)
    assert 60 <= held <= 120  # ~30%, stable across runs
    # frozen: same ids land in held-out every build
    s2 = build_suite()
    assert {x.id for x in s if x.held_out} == {x.id for x in s2 if x.held_out}


def test_uncertainty_cases_marked():
    s = build_suite()
    unc = [x for x in s if x.category == "uncertainty"]
    assert unc and all(x.expect_uncertainty for x in unc)
