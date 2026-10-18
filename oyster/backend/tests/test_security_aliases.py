"""Security alias/nickname query expansion (2026-09-15 accuracy cycle)."""

from __future__ import annotations

from services.knowledge import security_aliases


def test_unrecognized_query_is_returned_unchanged():
    q = "how does a firewall filter inbound traffic"
    assert security_aliases.expand_query(q) == q


def test_acronym_alias_is_appended_not_replaced():
    out = security_aliases.expand_query("Entra multifactor authentication enforcement")
    assert out.startswith("Entra multifactor authentication enforcement")
    assert "azure ad" in out.lower()


def test_named_vulnerability_nickname_expands_to_cve_id():
    out = security_aliases.expand_query("Following up on Log4Shell — what CVE identifier applies?")
    assert "CVE-2021-44228" in out


def test_acronym_only_matches_whole_word_not_substring():
    # "ad" must not fire inside "add" or "adopted"
    out = security_aliases.expand_query("we added a new adopted policy")
    assert "active directory" not in out.lower()


def test_multiple_aliases_in_one_query_all_expand():
    out = security_aliases.expand_query("PTH attacks against AD domain controllers")
    low = out.lower()
    assert "pass the hash" in low
    assert "active directory" in low


def test_expansion_is_deterministic():
    q = "zerologon impact on domain controllers"
    assert security_aliases.expand_query(q) == security_aliases.expand_query(q)
