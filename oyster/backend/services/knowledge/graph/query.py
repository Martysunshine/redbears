"""Read-side queries over the built knowledge graph."""

from __future__ import annotations

from . import store

_ROLE_LABELS = {
    "mapped_by": "mapping",
    "emulated_by": "emulation",
    "detected_by": "detection",
    "countered_by": "mitigation",
}


def _norm_tid(tid: str) -> str:
    return tid.strip().upper()


def technique_coverage(tid: str) -> dict | None:
    """Cross-source coverage for one ATT&CK technique: which packs provide
    mapping / emulation / detection, with sample citations, plus parent/children."""
    tid = _norm_tid(tid)
    node = store.get_node(f"technique:{tid}")
    if node is None:
        return None
    coverage: dict[str, list[dict]] = {"mapping": [], "emulation": [], "detection": [], "mitigation": []}
    for e in store.edges_from(f"technique:{tid}"):
        label = _ROLE_LABELS.get(e["edge_type"])
        if label:
            pack = e["dst"].split(":", 1)[-1]
            coverage[label].append({
                "pack_id": pack,
                "count": e["attrs"].get("count"),
                "sample_url": e["attrs"].get("sample_url"),
                "sample_title": e["attrs"].get("sample_title"),
            })
    parent = None
    children: list[str] = []
    for e in store.edges_from(f"technique:{tid}"):
        if e["edge_type"] == "child_of":
            parent = e["dst"].split(":", 1)[-1]
    for e in store.edges_to(f"technique:{tid}"):
        if e["edge_type"] == "child_of":
            children.append(e["src"].split(":", 1)[-1])
    attrs = node.get("attrs", {})
    return {
        "technique_id": tid,
        "label": node.get("label"),
        "mapped": attrs.get("mapped", False),
        "is_subtechnique": attrs.get("is_subtechnique", False),
        "source_url": attrs.get("source_url"),
        "parent": parent,
        "children": sorted(children),
        "coverage": coverage,
        "gap": _gap_summary(coverage, attrs.get("mapped", False)),
    }


def _gap_summary(coverage: dict, mapped: bool) -> str:
    has_det = bool(coverage["detection"])
    has_emu = bool(coverage["emulation"])
    if not mapped:
        return "dangling: referenced but not defined in imported ATT&CK"
    if has_det and has_emu:
        return "full: mapping + detection + emulation"
    if has_det and not has_emu:
        return "detection without emulation"
    if has_emu and not has_det:
        return "emulation without detection"
    return "mapping only"


def stats() -> dict:
    run = store.latest_run()
    return {
        "built": run is not None,
        "last_build": (run or {}).get("finished_at"),
        "nodes_by_type": store.counts_by_type(),
        "edges_by_type": store.edge_counts_by_type(),
        "inconsistencies_by_kind": store.inconsistency_counts(),
        "summary": (run or {}).get("stats", {}),
    }


def inconsistencies(kind: str | None = None, limit: int = 500) -> list[dict]:
    return store.list_inconsistencies(kind, limit)
