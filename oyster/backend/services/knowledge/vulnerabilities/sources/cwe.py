"""MITRE CWE — single bulk XML catalog (zipped).

https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

Parsed with defusedxml (no external entity resolution, no code execution).
Refreshed as a whole catalog on each sync, but ``store.sync_cwe_records``
diffs per-record by content hash so an unchanged weakness costs nothing.
"""

from __future__ import annotations

import io
import zipfile

import httpx

import config
from services.knowledge.connectors import injection_scan

from .. import identity
from ..models import CweRecord
from ..rate_limit import get_capped
from ._xmlutil import child, children, local_tag, parse, text_of

SOURCE_ID = "mitre-cwe"
LICENCE = "mitre-cwe-terms"
ATTRIBUTION = "Common Weakness Enumeration (CWE), © The MITRE Corporation. Used under the CWE Terms of Use with attribution."


async def fetch_raw() -> bytes:
    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        return await get_capped(client, config.CWE_CATALOG_URL)


def _clean(text: str, findings_counter: list[int]) -> str:
    if not text:
        return text
    clean, f = injection_scan.neutralize(text)
    findings_counter[0] += len(f)
    return clean


def _build_ref_map(root) -> dict[str, dict]:
    """Resolve External_Reference_ID -> {title, url, author} from the
    catalog-level <External_References> bibliography."""
    ref_map: dict[str, dict] = {}
    ext_refs = None
    for c in root:
        if local_tag(c) == "External_References":
            ext_refs = c
            break
    if ext_refs is None:
        return ref_map
    for ref in ext_refs:
        if local_tag(ref) != "External_Reference":
            continue
        rid = ref.get("Reference_ID")
        if not rid:
            continue
        url_el = child(ref, "URL")
        title_el = child(ref, "Title")
        author_el = child(ref, "Author")
        ref_map[rid] = {
            "url": text_of(url_el) if url_el is not None else None,
            "title": text_of(title_el) if title_el is not None else None,
            "author": text_of(author_el) if author_el is not None else None,
        }
    return ref_map


def _resolve_refs(weakness_elem, ref_map: dict[str, dict]) -> list[dict]:
    refs_el = child(weakness_elem, "References")
    if refs_el is None:
        return []
    out = []
    for r in children(refs_el, "Reference"):
        rid = r.get("External_Reference_ID")
        meta = ref_map.get(rid, {})
        out.append({"ref_id": rid, "section": r.get("Section"), **meta})
    return out


def normalize(raw_zip: bytes) -> tuple[list[CweRecord], str, int]:
    """Returns (records, catalog_version, injection_findings_count)."""
    zf = zipfile.ZipFile(io.BytesIO(raw_zip))
    xml_name = next((n for n in zf.namelist() if n.lower().endswith(".xml")), None)
    if xml_name is None:
        return [], "", 0
    root = parse(zf.read(xml_name))
    version = root.get("Version") or ""
    findings = [0]

    ref_map = _build_ref_map(root)

    weaknesses_el = None
    for c in root:
        if local_tag(c) == "Weaknesses":
            weaknesses_el = c
            break
    if weaknesses_el is None:
        return [], version, findings[0]

    records: list[CweRecord] = []
    for w in weaknesses_el:
        if local_tag(w) != "Weakness":
            continue
        cwe_id = identity.normalize_cwe(w.get("ID"))
        if cwe_id is None:
            continue

        desc_el = child(w, "Description")
        ext_desc_el = child(w, "Extended_Description")
        loe_el = child(w, "Likelihood_Of_Exploit")

        consequences = []
        cc_el = child(w, "Common_Consequences")
        if cc_el is not None:
            for cons in children(cc_el, "Consequence"):
                scopes = [text_of(s) for s in children(cons, "Scope")]
                impacts = [text_of(s) for s in children(cons, "Impact")]
                note_el = child(cons, "Note")
                consequences.append({"scope": scopes, "impact": impacts,
                                     "note": _clean(text_of(note_el), findings) if note_el is not None else None})

        related = []
        rw_el = child(w, "Related_Weaknesses")
        if rw_el is not None:
            for rel in children(rw_el, "Related_Weakness"):
                rel_id = identity.normalize_cwe(rel.get("CWE_ID"))
                if rel_id:
                    related.append({"nature": rel.get("Nature"), "cwe_id": rel_id})

        mitigations = []
        pm_el = child(w, "Potential_Mitigations")
        if pm_el is not None:
            for m in children(pm_el, "Mitigation"):
                phases = [text_of(p) for p in children(m, "Phase")]
                desc_m = child(m, "Description")
                mitigations.append({"phase": phases,
                                    "description": _clean(text_of(desc_m), findings) if desc_m is not None else None})

        detections = []
        dm_el = child(w, "Detection_Methods")
        if dm_el is not None:
            for d in children(dm_el, "Detection_Method"):
                method_el = child(d, "Method")
                desc_d = child(d, "Description")
                detections.append({
                    "method": text_of(method_el) if method_el is not None else None,
                    "description": _clean(text_of(desc_d), findings) if desc_d is not None else None,
                })

        records.append(CweRecord(
            cwe_id=cwe_id,
            name=w.get("Name"),
            abstraction=w.get("Abstraction"),
            status=w.get("Status"),
            description=_clean(text_of(desc_el), findings) if desc_el is not None else None,
            extended_description=_clean(text_of(ext_desc_el), findings) if ext_desc_el is not None else None,
            likelihood_of_exploit=text_of(loe_el) if loe_el is not None else None,
            common_consequences=consequences,
            related_weaknesses=related,
            mitigations=mitigations,
            detection_methods=detections,
            references=_resolve_refs(w, ref_map)[:config.VULN_MAX_REFERENCES_STORED],
            version=version,
        ))
    return records, version, findings[0]
