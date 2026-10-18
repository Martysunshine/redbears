"""Generic NIST OSCAL catalog parser.

Pure functions, no I/O. Walks the real ``catalog.groups[]`` / nested
``controls[]`` tree that every NIST OSCAL catalog (CSF 2.0, SP 800-53 rev5,
SP 800-218 SSDF, SP 800-53 privacy baseline) shares, and flattens it into
records matching ``controls.store``'s schema. Never invents a relationship or
a control field — everything returned traces back to a real key in the source
JSON; missing data stays ``None``/empty rather than being guessed.
"""

from __future__ import annotations

import re

_INSERT_RE = re.compile(r"\{\{\s*insert:\s*param,\s*([\w.\-]+)\s*\}\}")


def _param_display(p: dict) -> str:
    if p.get("label"):
        return p["label"]
    sel = p.get("select")
    if sel and sel.get("choice"):
        return " | ".join(sel["choice"])
    return p.get("id", "")


def _resolve_params(text: str | None, params: list[dict]) -> str | None:
    if not text:
        return text
    pmap = {p["id"]: _param_display(p) for p in params if p.get("id")}
    return _INSERT_RE.sub(lambda m: f"[{pmap.get(m.group(1), m.group(1))}]", text)


def _render_item_tree(part: dict, depth: int) -> list[str]:
    lines: list[str] = []
    prose = part.get("prose")
    if prose:
        indent = "  " * max(depth - 1, 0)
        lines.append(f"{indent}- {prose}")
    for sub in part.get("parts", []) or []:
        if sub.get("name") in ("item", "part"):
            lines.extend(_render_item_tree(sub, depth + 1))
    return lines


def _find_part(parts: list[dict], name: str) -> dict | None:
    for p in parts or []:
        if p.get("name") == name:
            return p
    return None


def statement_text(parts: list[dict], params: list[dict]) -> str | None:
    stmt = _find_part(parts, "statement")
    if stmt is None:
        return None
    lines: list[str] = []
    if stmt.get("prose"):
        lines.append(stmt["prose"])
    for child in stmt.get("parts", []) or []:
        if child.get("name") in ("item", "part"):
            lines.extend(_render_item_tree(child, 1))
    text = "\n".join(lines) if lines else None
    return _resolve_params(text, params)


def guidance_text(parts: list[dict], params: list[dict], part_name: str = "guidance") -> str | None:
    part = _find_part(parts, part_name)
    if part is None:
        return None
    lines: list[str] = []
    if part.get("prose"):
        lines.append(part["prose"])
    for child in part.get("parts", []) or []:
        if child.get("prose"):
            lines.append(child["prose"])
    text = "\n".join(lines) if lines else None
    return _resolve_params(text, params)


def examples(parts: list[dict], params: list[dict], part_name: str = "example") -> list[str]:
    out = []
    for p in parts or []:
        if p.get("name") == part_name and p.get("prose"):
            out.append(_resolve_params(p["prose"], params) or p["prose"])
    return out


def related_links(links: list[dict], framework: str) -> list[dict]:
    out = []
    for link in links or []:
        if link.get("rel") == "related" and link.get("href", "").startswith("#"):
            out.append({
                "rel": "related",
                "target_framework": framework,
                "target_control_id": link["href"][1:].upper(),
                "note": None,
            })
    return out


def external_reference_links(links: list[dict], resource_titles: dict[str, str]) -> list[dict]:
    """SSDF-style cross-framework references: ``href`` points at a back-matter
    resource (identifying which OTHER framework/document) and ``text`` carries
    the raw referenced-identifier string (e.g. ``"SM.3, DE.1, IA.1, IA.2"``).
    We tag the resource title (real, from the doc's own back-matter) rather
    than guessing individual target control ids out of the free-text list."""
    out = []
    for link in links or []:
        if link.get("rel") != "external_reference":
            continue
        href = link.get("href", "")
        title = resource_titles.get(href[1:]) if href.startswith("#") else None
        note = link.get("text") or ""
        if title:
            note = f"{title}: {note}" if note else title
        out.append({"rel": "external_reference", "target_framework": None,
                    "target_control_id": None, "note": note or None})
    return out


def display_id(raw_id: str, framework: str) -> str:
    """Normalize an OSCAL node id into the conventional display form.

    SP 800-53 ids are lowercase (``ac-1``, ``ac-2.1``); the convention is
    ``AC-1`` / ``AC-2(1)`` for enhancements. CSF / SSDF ids are already in
    their conventional display form (``GV.OC-01`` / ``PO.1.1``) and pass
    through unchanged.
    """
    if framework.startswith("sp800-53"):
        m = re.match(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$", raw_id)
        if m:
            fam, num, enh = m.groups()
            base = f"{fam.upper()}-{int(num)}"
            return f"{base}({int(enh)})" if enh else base
        return raw_id.upper()
    return raw_id


def _class_of(node: dict, is_group: bool, depth: int, framework: str) -> str:
    cls = node.get("class")
    if cls == "SP800-53-enhancement":
        return "enhancement"
    if cls and cls != "SP800-53":
        return cls
    if is_group:
        return {"csf": "function", "sp800-53": "family", "sp800-53-privacy": "family",
                "ssdf": "group"}.get(framework, "group")
    return "control" if depth == 1 else "enhancement"


def build_resource_title_map(back_matter: dict) -> dict[str, str]:
    out = {}
    for r in (back_matter or {}).get("resources", []) or []:
        uuid = r.get("uuid")
        title = r.get("title")
        if uuid and title:
            out[uuid] = title
    return out


def walk_catalog(catalog: dict, framework: str, guidance_part_name: str = "guidance",
                 example_part_name: str = "example") -> tuple[list[dict], dict[str, list[dict]]]:
    """Flatten one OSCAL catalog into (records, links_by_control_id).

    ``records`` match ``controls.store.upsert_control``'s expected dict shape
    (minus source/publisher/version, filled in by the caller). ``links``
    groups every ``control_links`` row by the owning control id.
    """
    resource_titles = build_resource_title_map(catalog.get("back-matter"))
    records: list[dict] = []
    links: dict[str, list[dict]] = {}

    def visit(node: dict, is_group: bool, depth: int, parent_display: str | None):
        raw_id = node.get("id")
        if not raw_id:
            # Some OSCAL groups omit an id; skip walking further into it.
            for child in node.get("controls", []) or []:
                visit(child, False, depth, parent_display)
            return
        disp = display_id(raw_id, framework)
        params = node.get("params", []) or []
        parts = node.get("parts", []) or []
        rec = {
            "framework": framework,
            "control_id": disp,
            "parent_id": parent_display,
            "class": _class_of(node, is_group, depth, framework),
            "title": node.get("title"),
            "statement": statement_text(parts, params),
            "guidance": guidance_text(parts, params, guidance_part_name),
            "examples_json": None,
            "external_refs_json": None,
        }
        ex = examples(parts, params, example_part_name)
        if ex:
            import json as _json
            rec["examples_json"] = _json.dumps(ex)
        node_links = related_links(node.get("links"), framework)
        node_links += external_reference_links(node.get("links"), resource_titles)
        ext_only = [l for l in node_links if l["rel"] == "external_reference"]
        if ext_only:
            import json as _json
            rec["external_refs_json"] = _json.dumps([l["note"] for l in ext_only if l["note"]])
        records.append(rec)
        if node_links:
            links[disp] = node_links

        for child in node.get("controls", []) or []:
            visit(child, False, depth + 1, disp)

    for group in catalog.get("groups", []) or []:
        visit(group, True, 0, None)

    return records, links
