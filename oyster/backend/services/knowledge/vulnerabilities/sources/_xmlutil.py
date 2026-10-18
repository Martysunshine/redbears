"""Shared safe-XML helpers for the CWE/CAPEC bulk-catalog parsers.

Uses ``defusedxml`` (already a project dependency) so parsing MITRE's XML
never resolves external entities or expands billion-laughs-style bombs. This
module only ever reads text out of the tree — it never executes anything
found in it.
"""

from __future__ import annotations

from defusedxml import ElementTree as DET


def parse(xml_bytes: bytes):
    return DET.fromstring(xml_bytes)


def local_tag(elem) -> str:
    """Strip the XML namespace off a tag, e.g. '{http://...}Weakness' -> 'Weakness'."""
    tag = elem.tag
    return tag.split("}", 1)[1] if "}" in tag else tag


def children(elem, name: str):
    return [c for c in elem if local_tag(c) == name]


def child(elem, name: str):
    cs = children(elem, name)
    return cs[0] if cs else None


def text_of(elem) -> str:
    """All descendant text, mixed-content-safe (handles nested <xhtml:p> etc.)."""
    if elem is None:
        return ""
    return " ".join(t.strip() for t in elem.itertext() if t.strip())
