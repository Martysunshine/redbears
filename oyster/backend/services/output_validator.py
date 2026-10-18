"""Model-independent output validator (Phase 6).

Oyster's selectable models include small and refusal-ablated weights, so answer
quality cannot be assumed from the model alone. This module inspects a finished
answer string for defects that are detectable WITHOUT another model call, and
splits them into two classes:

* **hard failures** — the answer is unusable as-is (empty, truncated mid-output,
  a leaked ``User:``/``Assistant:`` transcript turn, or leaked ``<think>``
  reasoning). The answer paths respond by regenerating ONCE and, if it still
  fails, returning an honest uncertainty message instead of invented content.
* **soft flags** — something worth surfacing but NOT worth discarding an
  otherwise-valid answer over (a verbatim-repeated paragraph, a citation marker
  with no matching source, a malformed CVE id). These are attached to the
  response for transparency; they never replace valid text with canned text.

Everything here is a pure function of its inputs: no network, no model, no
global state, fully unit-testable. It deliberately does NOT try to judge factual
accuracy or "does this tool exist" — that needs a model or an allowlist and
would produce false positives that blank good answers. The live quality eval
(tests/quality_eval_live.py) remains the factual-accuracy gate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# A model that ignores its stop tokens continues the chat as a fake transcript.
_TRANSCRIPT_LEAK_RE = re.compile(r"\n\s*(?:User|Assistant|Human|System)\s*:\s", re.IGNORECASE)
# Reasoning scaffolding that should never reach the user.
_THINK_LEAK_RE = re.compile(r"</?think>|</?reasoning>|<\|?(?:im_start|im_end)\|?>", re.IGNORECASE)
# CVE ids must be CVE-YYYY-NNNN+ with a plausible year; anything else is malformed.
_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
_CVE_MIN_YEAR = 1999
# Citation markers the answer refers to, e.g. "[3]".
_CITE_MARKER_RE = re.compile(r"\[(\d{1,3})\]")

HARD = "hard"
SOFT = "soft"


@dataclass
class Issue:
    code: str
    severity: str  # HARD | SOFT
    detail: str = ""


@dataclass
class ValidationResult:
    issues: list[Issue] = field(default_factory=list)

    @property
    def hard_failures(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == HARD]

    @property
    def soft_flags(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == SOFT]

    @property
    def ok(self) -> bool:
        """True when nothing HARD was found (soft flags do not fail an answer)."""
        return not self.hard_failures

    def flag_codes(self) -> list[str]:
        return [i.code for i in self.issues]


def is_empty(answer: str) -> bool:
    return not (answer or "").strip()


def leaked_transcript(answer: str) -> bool:
    return bool(_TRANSCRIPT_LEAK_RE.search(answer or ""))


def leaked_think(answer: str) -> bool:
    return bool(_THINK_LEAK_RE.search(answer or ""))


def looks_truncated(answer: str) -> bool:
    """Conservative: only flag structural truncation we are confident about, so
    a legitimately list- or sentence-ending answer is never falsely blanked."""
    text = (answer or "").strip()
    if not text:
        return False
    # An odd number of code fences means a code block was opened but never closed.
    if text.count("```") % 2 == 1:
        return True
    # A trailing opener strongly implies the stream was cut.
    if re.search(r"(?:\(|\[|\{|,|:|-|\bthe|\band|\bor|\bto|\bof|\bwith)\s*$", text, re.IGNORECASE):
        return True
    return False


def repeated_paragraphs(answer: str, *, min_len: int = 80) -> bool:
    """A substantial paragraph repeated verbatim (a common small-model failure)."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", answer or "") if len(p.strip()) >= min_len]
    seen: set[str] = set()
    for p in paras:
        key = re.sub(r"\s+", " ", p.lower())
        if key in seen:
            return True
        seen.add(key)
    return False


def malformed_cves(answer: str) -> list[str]:
    """CVE ids with an implausible year (format-level only — existence is not
    checked here; that needs the corpus/NVD, done by citation grounding)."""
    bad: list[str] = []
    from datetime import datetime, timezone
    this_year = datetime.now(timezone.utc).year
    for m in _CVE_RE.finditer(answer or ""):
        year = int(m.group(1))
        if year < _CVE_MIN_YEAR or year > this_year + 1:
            bad.append(m.group(0))
    return bad


def unsupported_citation_markers(answer: str, n_citations: int) -> list[str]:
    """Citation markers like ``[5]`` that point past the citations actually
    provided (0 => any numeric marker is unsupported)."""
    bad: list[str] = []
    for m in _CITE_MARKER_RE.finditer(answer or ""):
        idx = int(m.group(1))
        if idx < 1 or idx > n_citations:
            bad.append(m.group(0))
    return bad


def valid_citation_markers(answer: str, n_citations: int) -> list[int]:
    """The in-range citation numbers actually used in the answer (deduped)."""
    seen: list[int] = []
    for m in _CITE_MARKER_RE.finditer(answer or ""):
        idx = int(m.group(1))
        if 1 <= idx <= n_citations and idx not in seen:
            seen.append(idx)
    return seen


def repair_citation_markers(answer: str, n_citations: int) -> str:
    """Remove ONLY citation markers that point past the sources actually
    provided (e.g. ``[7]`` when 5 sources were returned) — markers that
    reference nothing. This never adds a marker and never touches an in-range
    one, so it cannot fabricate provenance; it only deletes a claim of support
    that does not exist, tidying the stray space/punctuation left behind."""
    if not answer:
        return answer

    def _sub(m: re.Match) -> str:
        return m.group(0) if 1 <= int(m.group(1)) <= n_citations else "\x00"

    cleaned = _CITE_MARKER_RE.sub(_sub, answer)
    cleaned = re.sub(r"[ \t]*\x00", "", cleaned)          # drop marker + leading space
    cleaned = re.sub(r"\x00", "", cleaned)
    cleaned = re.sub(r"[ \t]+([.,;:)])", r"\1", cleaned)  # tidy " ." left behind
    return cleaned


# Evidence-grounded citation attribution ------------------------------------
# The selectable refusal-ablated model reliably ignores the prompt's
# "cite inline [n]" instruction (verified 2026-10-07: 0 markers across grounded
# answers). Rather than leave grounded answers untraceable OR append arbitrary
# markers, attach [n] to a sentence ONLY when it shares enough distinct content
# terms with source n that the source demonstrably contains the claim's subject
# matter. This is a traceability aid grounded in real lexical overlap with a
# RETURNED source, not proof of correctness and not an arbitrary marker: a
# sentence that matches no source stays uncited (honest), and a marker is only
# ever a number that has a matching reference.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9`\"'(])")
_ATTR_STOP = frozenset(
    "that this these those with from into your their about which while would "
    "could should these there where when what will have been being also then "
    "used using uses such more most each other than they them then only over "
    "under within across between because however therefore example following".split()
)
_ATTR_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.\-_/]{3,}")


def _attr_terms(text: str) -> set[str]:
    return {w for w in _ATTR_WORD_RE.findall(text.lower()) if w not in _ATTR_STOP}


def attribute_citations(answer: str, citation_texts: list[str], *, min_shared: int = 3) -> str:
    """Append ``[n]`` to each claim-bearing sentence that shares at least
    ``min_shared`` distinct content terms with its best-matching source. No-op
    when the answer already uses valid markers (the model cited for itself) or
    when no source clears the bar for a sentence. Never renumbers, never cites a
    number without a source, never touches a ``reasoning:`` sentence."""
    n = len(citation_texts)
    if not answer or n == 0 or valid_citation_markers(answer, n):
        return answer
    src_terms = [_attr_terms(t or "") for t in citation_texts]
    out_sentences: list[str] = []
    attributed = False
    for sent in _SENTENCE_SPLIT_RE.split(answer):
        stripped = sent.rstrip()
        low = stripped.lower().lstrip("-*0123456789. )")
        if (not stripped or _CITE_MARKER_RE.search(stripped) or low.startswith("reasoning")):
            out_sentences.append(sent)
            continue
        sterms = _attr_terms(stripped)
        if len(sterms) < 4:  # too short to attribute with confidence
            out_sentences.append(sent)
            continue
        best_n, best_overlap = 0, 0
        for i, st in enumerate(src_terms, 1):
            ov_ct = len(sterms & st)
            if ov_ct > best_overlap:
                best_n, best_overlap = i, ov_ct
        if best_n and best_overlap >= min_shared:
            m = re.search(r"[.!?]+(\s*)$", sent)
            if m:
                sent = sent[:m.start()] + f" [{best_n}]" + sent[m.start():]
            else:
                sent = sent.rstrip() + f" [{best_n}]"
            attributed = True
        out_sentences.append(sent)
    return " ".join(out_sentences) if attributed else answer


def validate(answer: str, *, citations: list | None = None,
             check_citation_markers: bool = False) -> ValidationResult:
    """Inspect a finished answer. ``citations`` is the evidence actually passed
    to the model; ``check_citation_markers`` turns on ``[N]`` range-checking
    (only meaningful for the grounded RAG paths that number their evidence)."""
    res = ValidationResult()
    if is_empty(answer):
        res.issues.append(Issue("empty", HARD, "blank or whitespace-only answer"))
        return res  # nothing else is meaningful on an empty answer
    if leaked_transcript(answer):
        res.issues.append(Issue("transcript_leak", HARD, "answer continued a User:/Assistant: transcript"))
    if leaked_think(answer):
        res.issues.append(Issue("think_leak", HARD, "answer leaked <think>/chat-template tokens"))
    if looks_truncated(answer):
        res.issues.append(Issue("truncated", HARD, "answer appears cut off (unclosed code fence or dangling clause)"))
    if repeated_paragraphs(answer):
        res.issues.append(Issue("repeated_paragraph", SOFT, "a paragraph is repeated verbatim"))
    bad_cves = malformed_cves(answer)
    if bad_cves:
        res.issues.append(Issue("malformed_cve", SOFT, f"implausible CVE id(s): {', '.join(bad_cves[:5])}"))
    if check_citation_markers:
        n = len(citations or [])
        bad_markers = unsupported_citation_markers(answer, n)
        if bad_markers:
            res.issues.append(Issue("unsupported_citation", SOFT,
                                    f"citation marker(s) with no source: {', '.join(bad_markers[:5])}"))
        # Grounded answer that cites NOTHING: evidence was supplied and used to
        # generate, but the reader cannot trace any claim back to a source. Soft
        # (surfaced, never blanks a valid answer) — the fix is the prompt's
        # inline-citation instruction, not canned text.
        if n > 0 and not valid_citation_markers(answer, n):
            res.issues.append(Issue("missing_citation", SOFT,
                                    "grounded answer has no inline [n] citation markers"))
    return res


UNCERTAINTY_MESSAGE = (
    "I couldn't produce a reliable answer to that just now — the model's "
    "response failed Oyster's output checks twice (it came back empty, cut off, "
    "or malformed). Rather than show you something unreliable, I'm flagging it. "
    "Try rephrasing, narrowing the question, or selecting a different model in "
    "advanced settings."
)
