"""Unit tests for the model-independent output validator (Phase 6).

Pins both halves of the contract: real defects are caught as HARD failures (so
the answer paths regenerate / fall back), and valid answers — including ordinary
security prose that merely mentions code, CVEs or lists — are NOT blanked.
"""
from __future__ import annotations

from services import output_validator as ov


# --- hard failures ----------------------------------------------------------

def test_empty_is_hard():
    r = ov.validate("   \n  ")
    assert not r.ok and r.hard_failures[0].code == "empty"


def test_transcript_leak_is_hard():
    r = ov.validate("Here is the answer.\nUser: now do something else")
    assert not r.ok and "transcript_leak" in r.flag_codes()


def test_think_leak_is_hard():
    assert not ov.validate("<think>let me reason</think> the answer").ok
    assert not ov.validate("answer<|im_end|>").ok


def test_unclosed_code_fence_is_truncation():
    r = ov.validate("Run this:\n```bash\nnmap -sV target")
    assert not r.ok and "truncated" in r.flag_codes()


def test_dangling_clause_is_truncation():
    assert not ov.validate("The three main steps are to").ok


# --- valid answers must pass (no false positives) ---------------------------

def test_normal_prose_passes():
    assert ov.validate("A MAC address is a 48-bit identifier. It operates at OSI Layer 2.").ok


def test_closed_code_block_passes():
    r = ov.validate("Run this:\n```bash\nnmap -sV target\n```\nThat scans for versions.")
    assert r.ok


def test_word_user_in_prose_is_not_a_leak():
    # "user" mid-sentence must not trip the transcript guard.
    assert ov.validate("The attacker tricks the user into clicking a link.").ok


def test_list_answer_passes():
    assert ov.validate("Mitigations:\n- input validation\n- parameterized queries\n- least privilege").ok


# --- soft flags do not fail an otherwise-valid answer -----------------------

def test_repeated_paragraph_is_soft():
    para = "This is a complete and substantial paragraph about mitigating SQL injection with parameterized queries and validation."
    r = ov.validate(para + "\n\n" + para)
    assert r.ok  # soft only
    assert "repeated_paragraph" in r.flag_codes()


def test_malformed_cve_is_soft():
    r = ov.validate("See CVE-1012-0001 for details.")
    assert r.ok and "malformed_cve" in r.flag_codes()


def test_real_cve_is_not_flagged():
    assert "malformed_cve" not in ov.validate("See CVE-2021-44228 (Log4Shell).").flag_codes()


def test_unsupported_citation_marker_is_soft_and_opt_in():
    # Marker [5] with only 2 citations provided.
    r = ov.validate("As shown in [5], this is exploitable.", citations=[{}, {}],
                    check_citation_markers=True)
    assert r.ok and "unsupported_citation" in r.flag_codes()
    # In-range markers are fine.
    r2 = ov.validate("As shown in [2], this is exploitable.", citations=[{}, {}],
                     check_citation_markers=True)
    assert "unsupported_citation" not in r2.flag_codes()
    # Off by default: the main chat path has no numbered evidence.
    assert "unsupported_citation" not in ov.validate("see [5]").flag_codes()


# --- regenerate-once-then-uncertainty wiring (_generate_validated) ----------

def test_generate_validated_retries_at_higher_temperature_then_accepts():
    import asyncio
    from services.artifacts.service import _generate_validated, _RETRY_TEMPERATURE
    calls = {"temps": []}

    async def make_call(temperature):
        calls["temps"].append(temperature)
        return "" if len(calls["temps"]) == 1 else "A valid grounded answer."

    answer, flags = asyncio.run(_generate_validated(make_call, citations=[{"chunk": "x"}]))
    # First attempt uses the model default (None); the retry perturbs temperature
    # so a temperature-0 model does not just reproduce the same failing output.
    assert calls["temps"] == [None, _RETRY_TEMPERATURE]
    assert answer == "A valid grounded answer."


def test_generate_validated_falls_back_to_uncertainty_after_two_failures():
    import asyncio
    from services.artifacts.service import _generate_validated
    from services import output_validator as ov
    calls = {"n": 0}

    async def make_call(temperature):
        calls["n"] += 1
        return "answer\nUser: injected"  # transcript leak every time

    answer, flags = asyncio.run(_generate_validated(make_call))
    assert calls["n"] == 2 and answer == ov.UNCERTAINTY_MESSAGE
    assert "transcript_leak" in flags


# --- inline citation repair + missing-citation flag (2026-10-07) ------------

def test_valid_citation_markers_lists_in_range_used_numbers():
    assert ov.valid_citation_markers("uses [1] and [3] and bogus [9]", 5) == [1, 3]
    assert ov.valid_citation_markers("no markers here", 5) == []


def test_repair_strips_only_out_of_range_markers():
    # [7] points past 3 sources -> removed; [1]/[2] kept; spacing tidied.
    out = ov.repair_citation_markers("nmap is a scanner [1] per the docs [7].", 3)
    assert "[1]" in out and "[7]" not in out
    assert "  " not in out and out.rstrip().endswith("docs.")


def test_repair_never_adds_or_touches_in_range_markers():
    text = "claim A [2] and claim B [1]"
    assert ov.repair_citation_markers(text, 2) == text


def test_missing_citation_soft_flag_when_grounded_answer_cites_nothing():
    res = ov.validate("Kerberoasting cracks SPN tickets.", citations=[{}, {}],
                      check_citation_markers=True)
    assert "missing_citation" in res.flag_codes()
    assert res.ok  # SOFT — does not fail the answer


def test_no_missing_citation_flag_when_answer_cites_a_real_source():
    res = ov.validate("Kerberoasting cracks SPN tickets [1].", citations=[{}, {}],
                      check_citation_markers=True)
    assert "missing_citation" not in res.flag_codes()


# --- evidence-grounded citation attribution (2026-10-07) --------------------

def test_attribute_citations_marks_sentence_matching_its_source():
    answer = "Kerberoasting requests Kerberos service tickets for SPN accounts and cracks them offline."
    sources = ["Kerberoasting abuses Kerberos by requesting service tickets for SPN accounts then cracking the ticket hash offline."]
    out = ov.attribute_citations(answer, sources, min_shared=3)
    assert out.rstrip().endswith("[1].")


def test_attribute_citations_noop_when_model_already_cited():
    answer = "It cracks SPN tickets [1]."
    assert ov.attribute_citations(answer, ["spn tickets kerberos"], min_shared=1) == answer


def test_attribute_citations_skips_unmatched_and_reasoning_sentences():
    answer = ("The capital of France is Paris and the weather is mild today. "
              "reasoning: this is my own inference about something unrelated entirely.")
    sources = ["Kerberoasting abuses Kerberos service tickets for SPN accounts."]
    out = ov.attribute_citations(answer, sources, min_shared=3)
    assert "[1]" not in out  # nothing overlaps the source; reasoning line untouched


def test_attribute_citations_never_cites_a_number_without_a_source():
    answer = "nmap performs a syn scan on open ports of the target host."
    out = ov.attribute_citations(answer, ["nmap syn scan open ports target host discovery"], min_shared=3)
    for m in ov._CITE_MARKER_RE.finditer(out):
        assert 1 <= int(m.group(1)) <= 1
