"""Structural Markdown normalization.

Parses a Markdown document into sections while **preserving fenced code blocks
verbatim** (security commands and payloads must never be mangled). Tracks the
heading hierarchy so each section carries a ``heading_path`` and a stable anchor
slug — used for citation section anchors.

This is deterministic: the same input always yields the same sections, titles
and anchors, which keeps document/chunk IDs stable across imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE_RE = re.compile(r"^(\s*)(```+|~~~+)")
_ANCHOR_STRIP = re.compile(r"[^a-z0-9\- ]+")


@dataclass
class Section:
    heading_path: tuple[str, ...]
    title: str
    anchor: str
    body: str


def slugify(text: str) -> str:
    s = _ANCHOR_STRIP.sub("", (text or "").lower()).strip()
    return re.sub(r"[\s]+", "-", s)[:80] or "section"


def _title_of(text: str) -> str | None:
    for line in (text or "").splitlines():
        m = _HEADING_RE.match(line)
        if m:
            return m.group(2).strip()
    return None


def document_title(text: str, fallback: str) -> str:
    return _title_of(text) or fallback


def parse_sections(text: str) -> list[Section]:
    """Split ``text`` into heading-delimited sections, keeping code fences intact.

    Content before the first heading becomes a leading "Overview" section so no
    text is dropped.
    """
    text = text or ""
    lines = text.splitlines()

    sections: list[Section] = []
    heading_stack: list[tuple[int, str]] = []   # (level, title)
    buf: list[str] = []
    cur_path: tuple[str, ...] = ()
    cur_title = "Overview"
    in_fence = False
    fence_marker = ""

    def flush():
        body = "\n".join(buf).strip()
        if body:
            sections.append(Section(
                heading_path=cur_path or (cur_title,),
                title=cur_title,
                anchor=slugify(cur_title),
                body=body,
            ))

    for line in lines:
        fence = _FENCE_RE.match(line)
        if fence:
            marker = fence.group(2)
            if not in_fence:
                in_fence, fence_marker = True, marker[:3]
            elif marker[:3] == fence_marker:
                in_fence = False
            buf.append(line)
            continue

        if in_fence:
            buf.append(line)
            continue

        m = _HEADING_RE.match(line)
        if m:
            flush()
            buf = []
            level = len(m.group(1))
            title = m.group(2).strip() or "Section"
            # maintain a heading stack to build the full path
            while heading_stack and heading_stack[-1][0] >= level:
                heading_stack.pop()
            heading_stack.append((level, title))
            cur_path = tuple(t for _, t in heading_stack)
            cur_title = title
        else:
            buf.append(line)

    flush()
    return sections
