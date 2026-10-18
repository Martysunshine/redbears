"""Text cleaning: strip HTML, normalize markdown, deduplicate lines."""

from __future__ import annotations

import re
import unicodedata
from bs4 import BeautifulSoup


_BLANK_LINE_RE = re.compile(r"\n{3,}")
_TRAILING_RE = re.compile(r"[ \t]+$", re.MULTILINE)
_CODE_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def strip_html(text: str) -> str:
    soup = BeautifulSoup(text, "lxml")
    # preserve <code> and <pre> as literal text
    for tag in soup.find_all(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return soup.get_text(separator="\n")


def normalize_unicode(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def collapse_whitespace(text: str) -> str:
    text = _TRAILING_RE.sub("", text)
    text = _BLANK_LINE_RE.sub("\n\n", text)
    return text.strip()


def remove_license_headers(text: str) -> str:
    """Strip common open-source license preambles from the top of files."""
    lines = text.splitlines()
    skip_patterns = (
        "MIT License", "Apache License", "GNU General", "Copyright (c)",
        "Permission is hereby granted", "Licensed under",
    )
    cut = 0
    for i, line in enumerate(lines[:30]):
        if any(p in line for p in skip_patterns):
            cut = i + 1
    return "\n".join(lines[cut:]) if cut else text


def deduplicate_lines(text: str) -> str:
    seen: set[str] = set()
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and stripped in seen:
            continue
        if stripped:
            seen.add(stripped)
        out.append(line)
    return "\n".join(out)


def clean(text: str, *, is_html: bool = False) -> str:
    if is_html:
        text = strip_html(text)
    text = normalize_unicode(text)
    text = remove_license_headers(text)
    text = collapse_whitespace(text)
    # drop extremely short results (likely nav menus / table-of-contents stubs)
    if len(text) < 80:
        return ""
    return text
