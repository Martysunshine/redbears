"""Prompt-injection & hostile-content inspection for imported source content.

Repositories, documentation and datasets are **untrusted**. A markdown file can
try to smuggle instructions to the agent ("ignore previous instructions",
"you are now...", fake ``system:`` turns, hidden HTML-comment directives,
``<tool_call>`` blocks) or use invisible Unicode (bidi overrides, zero-width
joiners) to hide payloads.

This module does two things at ingest time:

1. :func:`neutralize` — strips dangerous *invisible* control characters
   (bidirectional overrides, zero-width, BOM) so hidden text can't ride along
   unseen. Visible security content (commands, payloads-as-text) is preserved:
   it is knowledge, stored as inert data.
2. :func:`scan` — records findings (matched injection markers) so a chunk can be
   flagged and audited. Detection never changes agent behaviour on its own; the
   retrieval layer already treats every passage as data, so a flagged chunk is
   simply labelled, not obeyed.
"""

from __future__ import annotations

import re

# Invisible / direction-control characters that should never survive ingestion.
_BIDI_CONTROL = [
    "‪", "‫", "‬", "‭", "‮",  # LRE RLE PDF LRO RLO
    "⁦", "⁧", "⁨", "⁩",              # LRI RLI FSI PDI
    "‎", "‏",                                    # LRM RLM
]
_ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]

_STRIP_CHARS = {ord(c): None for c in (_BIDI_CONTROL + _ZERO_WIDTH)}

# Instruction-injection markers (case-insensitive). These flag content; they do
# not stop an import.
_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(the\s+)?(previous|above|prior|earlier)\s+"
                r"(instructions|prompts?|context)", re.I), "ignore-previous-instructions"),
    (re.compile(r"disregard\s+(all\s+)?(your|the|previous)\s+", re.I), "disregard-instructions"),
    (re.compile(r"\byou\s+are\s+now\b|\bpretend\s+to\s+be\b|\bact\s+as\s+(an?\s+)?"
                r"(unrestricted|jailbroken|dan)\b", re.I), "role-override"),
    (re.compile(r"^\s*(system|assistant|developer)\s*:", re.I | re.M), "fake-conversation-turn"),
    (re.compile(r"<\s*/?\s*(system|tool_call|function_call|tool)\s*>", re.I), "fake-tool-or-system-tag"),
    (re.compile(r"\{\{\s*system\s*\}\}|\[INST\]|<\|im_start\|>", re.I), "prompt-template-injection"),
    (re.compile(r"<!--.*?(ignore|instruction|system|execute|run this).*?-->",
                re.I | re.S), "hidden-html-comment-directive"),
    (re.compile(r"\bprint\s+your\s+(system\s+)?prompt\b|\breveal\s+your\s+instructions\b",
                re.I), "prompt-exfiltration"),
    (re.compile(r"\b(approve|authorize|mark)\s+(this\s+)?(target|execution|scope)\b",
                re.I), "authorization-override-attempt"),
]


def _count_bidi_zero_width(text: str) -> int:
    return sum(text.count(c) for c in (_BIDI_CONTROL + _ZERO_WIDTH))


def _homoglyph_density(text: str) -> float:
    """Fraction of alphabetic-looking characters that are non-ASCII (crude
    homoglyph signal). High density in otherwise-ASCII technical text is
    suspicious."""
    alpha = [c for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    non_ascii = sum(1 for c in alpha if ord(c) > 0x7F)
    return non_ascii / len(alpha)


def scan(text: str) -> list[dict]:
    """Return a list of injection findings ``{marker, snippet}`` for ``text``."""
    text = text or ""
    findings: list[dict] = []
    n_invisible = _count_bidi_zero_width(text)
    if n_invisible:
        findings.append({"marker": "invisible-control-characters",
                         "detail": f"{n_invisible} bidi/zero-width chars"})
    for pat, marker in _INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            snippet = m.group(0)
            findings.append({"marker": marker, "snippet": snippet[:160]})
    dens = _homoglyph_density(text)
    if dens > 0.30 and len(text) > 40:
        findings.append({"marker": "high-non-ascii-density",
                         "detail": f"{dens:.2f} non-ascii alpha ratio"})
    return findings


def neutralize(text: str) -> tuple[str, list[dict]]:
    """Strip invisible control characters and return ``(clean_text, findings)``.

    The findings are computed on the RAW text (before stripping) so we still
    record what was hidden. Visible content is preserved verbatim."""
    findings = scan(text or "")
    clean = (text or "").translate(_STRIP_CHARS)
    return clean, findings


def risk_from_findings(findings: list[dict]) -> str:
    """Map injection findings to a coarse risk flag for provenance labelling."""
    if not findings:
        return "clean"
    hard = {"fake-tool-or-system-tag", "authorization-override-attempt",
            "invisible-control-characters", "prompt-template-injection"}
    if any(f["marker"] in hard for f in findings):
        return "hostile"
    return "suspicious"
