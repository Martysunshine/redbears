"""Recursive character text splitter — preserves semantic boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator


@dataclass
class Chunk:
    text: str
    index: int          # chunk number within document
    char_start: int     # character offset in original text


_SEPARATORS = ["\n\n", "\n", ". ", "! ", "? ", "; ", ", ", " ", ""]


def _split_on(text: str, sep: str) -> list[str]:
    if sep == "":
        return list(text)
    return text.split(sep)


def _recursive_split(
    text: str,
    chunk_size: int,
    overlap: int,
    sep_index: int = 0,
) -> list[str]:
    """Split text recursively using progressively finer separators."""
    if len(text) <= chunk_size:
        return [text]

    sep = _SEPARATORS[sep_index] if sep_index < len(_SEPARATORS) else ""
    parts = _split_on(text, sep)

    chunks: list[str] = []
    current = ""
    for part in parts:
        candidate = (current + sep + part).lstrip(sep) if current else part
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(current)
            if len(part) > chunk_size:
                # recurse with next separator
                next_sep = sep_index + 1
                chunks.extend(_recursive_split(part, chunk_size, overlap, next_sep))
                current = ""
            else:
                current = part
    if current:
        chunks.append(current)

    return chunks


def _add_overlap(chunks: list[str], overlap: int, sep: str = " ") -> list[str]:
    if overlap <= 0 or len(chunks) < 2:
        return chunks
    result = [chunks[0]]
    for i in range(1, len(chunks)):
        prev_tail = chunks[i - 1][-overlap:]
        result.append(prev_tail + sep + chunks[i])
    return result


def split_text(
    text: str,
    chunk_size: int = 1000,
    overlap: int = 200,
) -> list[Chunk]:
    """Return a list of Chunk objects with position metadata."""
    raw = _recursive_split(text, chunk_size, overlap)
    raw = _add_overlap(raw, overlap)

    result: list[Chunk] = []
    pos = 0
    for i, chunk_text in enumerate(raw):
        chunk_text = chunk_text.strip()
        if not chunk_text:
            continue
        offset = text.find(chunk_text, pos)
        char_start = offset if offset != -1 else pos
        result.append(Chunk(text=chunk_text, index=i, char_start=char_start))
        pos = char_start + len(chunk_text)

    return result
