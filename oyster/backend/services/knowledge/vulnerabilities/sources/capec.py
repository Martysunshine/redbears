"""MITRE CAPEC — single bulk XML catalog (plain, not zipped).

https://capec.mitre.org/data/xml/capec_latest.xml

Same safe-parse / whole-catalog-refresh-diffed-by-content-hash approach as
``cwe.py``.
"""

from __future__ import annotations

import httpx

import config
from services.knowledge.connectors import injection_scan

from .. import identity
from ..models import CapecRecord
from ..rate_limit import get_capped
from ._xmlutil import child, children, local_tag, parse, text_of

SOURCE_ID = "mitre-capec"
LICENCE = "mitre-capec-terms"
ATTRIBUTION = "Common Attack Pattern Enumeration and Classification (CAPEC), © The MITRE Corporation. Used under the CAPEC Terms of Use with attribution."


async def fetch_raw() -> bytes:
    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        return await get_capped(client, config.CAPEC_CATALOG_URL)


def _clean(text: str, findings_counter: list[int]) -> str:
    if not text:
        return text
    clean, f = injection_scan.neutralize(text)
    findings_counter[0] += len(f)
    return clean


def _build_ref_map(root) -> dict[str, dict]:
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
        ref_map[rid] = {
            "url": text_of(url_el) if url_el is not None else None,
            "title": text_of(title_el) if title_el is not None else None,
        }
    return ref_map


def _resolve_refs(pattern_elem, ref_map: dict[str, dict]) -> list[dict]:
    refs_el = child(pattern_elem, "References")
    if refs_el is None:
        return []
    out = []
    for r in children(refs_el, "Reference"):
        rid = r.get("External_Reference_ID") or r.get("Reference_ID")
        meta = ref_map.get(rid, {})
        out.append({"ref_id": rid, "section": r.get("Section"), **meta})
    return out


def normalize(raw_xml: bytes) -> tuple[list[CapecRecord], str, int]:
    """Returns (records, catalog_version, injection_findings_count)."""
    root = parse(raw_xml)
    version = root.get("Version") or ""
    findings = [0]
    ref_map = _build_ref_map(root)

    patterns_el = None
    for c in root:
        if local_tag(c) == "Attack_Patterns":
            patterns_el = c
            break
    if patterns_el is None:
        return [], version, findings[0]

    records: list[CapecRecord] = []
    for p in patterns_el:
        if local_tag(p) != "Attack_Pattern":
            continue
        capec_id = identity.normalize_capec(p.get("ID"))
        if capec_id is None:
            continue

        desc_el = child(p, "Description")
        loa_el = child(p, "Likelihood_Of_Attack")
        sev_el = child(p, "Typical_Severity")

        execution_flow = []
        ef_el = child(p, "Execution_Flow")
        if ef_el is not None:
            for step in children(ef_el, "Attack_Step"):
                phase_el = child(step, "Phase")
                desc_step = child(step, "Description")
                execution_flow.append({
                    "step": text_of(child(step, "Step")) if child(step, "Step") is not None else None,
                    "phase": text_of(phase_el) if phase_el is not None else None,
                    "description": _clean(text_of(desc_step), findings) if desc_step is not None else None,
                })

        prerequisites = []
        pre_el = child(p, "Prerequisites")
        if pre_el is not None:
            prerequisites = [_clean(text_of(pr), findings) for pr in children(pre_el, "Prerequisite")]

        skills = []
        sk_el = child(p, "Skills_Required")
        if sk_el is not None:
            for s in children(sk_el, "Skill"):
                skills.append({"level": s.get("Level"), "description": _clean(text_of(s), findings)})

        related_weaknesses = []
        rw_el = child(p, "Related_Weaknesses")
        if rw_el is not None:
            for rel in children(rw_el, "Related_Weakness"):
                cwe_id = identity.normalize_cwe(rel.get("CWE_ID"))
                if cwe_id:
                    related_weaknesses.append(cwe_id)

        related_patterns = []
        rap_el = child(p, "Related_Attack_Patterns")
        if rap_el is not None:
            for rel in children(rap_el, "Related_Attack_Pattern"):
                rel_id = identity.normalize_capec(rel.get("CAPEC_ID"))
                if rel_id:
                    related_patterns.append({"nature": rel.get("Nature"), "capec_id": rel_id})

        mitigations = []
        mit_el = child(p, "Mitigations")
        if mit_el is not None:
            for m in children(mit_el, "Mitigation"):
                mitigations.append({"description": _clean(text_of(m), findings)})

        records.append(CapecRecord(
            capec_id=capec_id,
            name=p.get("Name"),
            abstraction=p.get("Abstraction"),
            status=p.get("Status"),
            description=_clean(text_of(desc_el), findings) if desc_el is not None else None,
            likelihood_of_attack=text_of(loa_el) if loa_el is not None else None,
            typical_severity=text_of(sev_el) if sev_el is not None else None,
            execution_flow=execution_flow,
            prerequisites=prerequisites,
            skills_required=skills,
            related_weaknesses=related_weaknesses,
            related_attack_patterns=related_patterns,
            mitigations=mitigations,
            references=_resolve_refs(p, ref_map)[:config.VULN_MAX_REFERENCES_STORED],
            version=version,
        ))
    return records, version, findings[0]
