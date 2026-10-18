"""Grounded security-answer formatting (routes ``security_router`` output into
a fixed 7-part shape):

    1. direct_answer
    2. severity_and_exploitation
    3. affected_systems
    4. defensive_actions
    5. detection_guidance
    6. sources                 (each with a source date + retrieval date)
    7. confidence               (+ a data-gap warning when nothing was found)

For an exact-identifier lookup every field is built directly from stored
fields — never phrased by an LLM — so a CVE's score, KEV status or a CWE's
mitigations can never be invented. For topic/general routes the retrieved
citations are the grounding; if a local model is reachable its output is used
only for ``direct_answer`` prose, always followed by the real citation list,
and is skipped (not guessed) when no model responds.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import security_router as router
from .. import ollama_service
from .. import rag_service

_NOT_FOUND = "not found in local knowledge base"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_entries(entries, label_key: str = "phase") -> str | None:
    """Render a list of CWE/CAPEC-style ``{description, phase|method|step}``
    dicts (already JSON-decoded by the vulnerabilities store) into readable
    text. Returns None for an empty/missing list — never a raw JSON blob."""
    if not entries:
        return None
    parts = []
    for e in entries:
        if not isinstance(e, dict):
            parts.append(str(e))
            continue
        desc = e.get("description") or ""
        label = e.get(label_key)
        if isinstance(label, list):
            label = ", ".join(str(x) for x in label)
        parts.append(f"[{label}] {desc}" if label else desc)
    return " | ".join(p for p in parts if p) or None


def _format_strings(entries) -> str | None:
    if not entries:
        return None
    return " | ".join(str(e) for e in entries if e)


def _format_products(entries) -> str | None:
    """CVE ``affected_products`` entries are ``{vendor, product, version, cpe}``
    dicts (from NVD CPE matches) — never plain strings."""
    if not entries:
        return None
    parts = []
    for e in entries:
        if not isinstance(e, dict):
            parts.append(str(e))
            continue
        vendor, product, version = e.get("vendor"), e.get("product"), e.get("version")
        label = " ".join(p for p in (vendor, product) if p) or e.get("cpe") or ""
        if version and version != "*":
            label = f"{label} {version}".strip()
        if label:
            parts.append(label)
    return ", ".join(parts) or None


def _confidence(has_data: bool, identifiers_absent: list[str]) -> dict:
    if not has_data:
        return {"level": "none", "data_gap_warning": _NOT_FOUND}
    if identifiers_absent:
        return {"level": "partial",
                "data_gap_warning": f"not found in local knowledge base: {', '.join(identifiers_absent)}"}
    return {"level": "grounded", "data_gap_warning": None}


# ---------------------------------------------------------------------------
# Exact-identifier answers — deterministic, field-driven, no LLM.
# ---------------------------------------------------------------------------

def _answer_cve(rec: dict) -> dict | None:
    if rec.get("found") is False:
        return None
    cvss = rec.get("cvss") or {}
    v4, v3, v2 = cvss.get("v4"), cvss.get("v3"), cvss.get("v2")
    kev = rec.get("kev") or {}
    epss = rec.get("epss")
    severity_lines = []
    if v4:
        severity_lines.append(f"CVSS v4: {v4['score']} ({v4['severity']}) — {v4.get('vector') or 'no vector recorded'}")
    if v3:
        severity_lines.append(f"CVSS v3: {v3['score']} ({v3['severity']}) — {v3.get('vector') or 'no vector recorded'}")
    if v2 and not (v3 or v4):
        severity_lines.append(f"CVSS v2: {v2['score']} ({v2['severity']}) — {v2.get('vector') or 'no vector recorded'}")
    if epss:
        severity_lines.append(f"EPSS: {epss['score']} (percentile {epss['percentile']}) as of {epss.get('as_of') or 'unknown date'}")
    if kev.get("listed"):
        severity_lines.append(
            f"Listed in CISA KEV since {kev.get('date_added') or 'unknown date'}"
            + (f" — required action: {kev['required_action']}" if kev.get("required_action") else "")
            + (" — known ransomware use" if kev.get("known_ransomware") == "Known" else "")
        )
    # Source-specific disagreement: only surfaced when two sources actually
    # disagree on the score, never fabricated when they agree or when only
    # one source has published a score.
    by_source = rec.get("cvss_by_source") or []
    distinct_scores = {s["score"] for s in by_source if s.get("score") is not None}
    disagreement = None
    if len(distinct_scores) > 1:
        parts = [f"{s['source'] or 'unknown'} (CVSS v{s['cvss_version']}): {s['score']}"
                for s in by_source if s.get("score") is not None]
        disagreement = "Sources disagree on CVSS score — " + "; ".join(parts)
        severity_lines.append(disagreement)
    affected = _format_products(rec.get("affected_products"))
    advisories = rec.get("vendor_advisories") or []
    defensive_actions = kev.get("required_action") or "no CISA-required action on file."
    fixed_versions = [a["fixed_version"] for a in advisories if a.get("fixed_version")]
    if fixed_versions:
        defensive_actions += " Fixed version(s): " + " | ".join(dict.fromkeys(fixed_versions))
    if advisories:
        remediations = [a["remediation"] for a in advisories if a.get("remediation")]
        if remediations:
            defensive_actions += " Vendor remediation (CISA CSAF): " + " | ".join(remediations[:3])
    distro_fixes = [d for d in (rec.get("distro_fixes") or []) if not d.get("withdrawn")]
    if distro_fixes:
        parts = []
        for d in distro_fixes[:6]:
            if d.get("fixed"):
                parts.append(f"{d['distro']} {d.get('package') or '?'}: fixed in {d['fixed']}")
            else:
                parts.append(f"{d['distro']} {d.get('package') or '?'}: no fixed version listed yet")
        defensive_actions += " Distro packages (OSV): " + " | ".join(parts)
    sources = [rec.get("citation")] + [
        {"source_url": a.get("source_url"), "title": a.get("title"), "publisher": a.get("publisher")}
        for a in advisories
    ]
    return {
        "identifier": rec.get("cve_id"),
        "direct_answer": rec.get("description") or f"{rec.get('cve_id')}: no description stored.",
        "severity_and_exploitation": "; ".join(severity_lines) or "no CVSS/EPSS/KEV data stored for this CVE.",
        "affected_systems": affected or "no affected-product data stored for this CVE.",
        "defensive_actions": defensive_actions,
        "detection_guidance": "see the cross-source knowledge graph for any ATT&CK techniques and Sigma/YARA "
                              "detections linked to this CVE's CWE classification.",
        "source_disagreement": disagreement,
        "sources": sources,
        "last_modified": rec.get("last_modified_date"),
        "retrieved_at": _now(),
    }


def _format_affected_ranges(affected: list[dict] | None) -> str | None:
    if not affected:
        return None
    parts = []
    for a in affected[:8]:
        pkg = f"{a.get('ecosystem') or '?'}/{a.get('package') or '?'}"
        rng = []
        if a.get("introduced") is not None:
            rng.append(f"introduced {a['introduced']}")
        if a.get("fixed"):
            rng.append(f"fixed in {a['fixed']}")
        if a.get("last_affected"):
            rng.append(f"last known affected {a['last_affected']}")
        parts.append(f"{pkg} ({'; '.join(rng)})" if rng else pkg)
    return "; ".join(parts)


def _answer_ghsa_osv(rec: dict, *, kind: str) -> dict | None:
    if rec.get("found") is False:
        return None
    if rec.get("is_withdrawn"):
        withdrawn_at = rec.get("withdrawn")
        when = f" on {withdrawn_at}" if withdrawn_at else ""
        direct = (f"{rec.get('ghsa_id') or rec.get('osv_id')} was WITHDRAWN{when}. "
                 + (rec.get("summary") or rec.get("details") or ""))
    else:
        direct = rec.get("summary") or rec.get("details") or "no summary stored."
    severity = []
    if rec.get("severity_vector"):
        severity.append(f"{rec.get('severity_type') or 'CVSS'}: {rec['severity_vector']}")
    if rec.get("database_severity"):
        severity.append(f"database severity: {rec['database_severity']}")
    cve_aliases = [a for a in (rec.get("aliases") or []) if a.startswith("CVE-")]
    if cve_aliases:
        severity.append(f"tracked as: {', '.join(cve_aliases)}")
    affected_text = _format_affected_ranges(rec.get("affected"))
    fixed_versions = [a["fixed"] for a in (rec.get("affected") or []) if a.get("fixed")]
    defensive = ("Upgrade to a fixed version: " + " | ".join(dict.fromkeys(fixed_versions))
                if fixed_versions else "no fixed-version data stored for this advisory.")
    identifier = rec.get("ghsa_id") if kind == "ghsa" else rec.get("osv_id")
    return {
        "identifier": identifier,
        "direct_answer": direct,
        "severity_and_exploitation": "; ".join(severity) or "no severity data stored.",
        "affected_systems": affected_text or "no affected-package data stored.",
        "defensive_actions": defensive,
        "detection_guidance": "see the cross-referenced CVE (if any) for CWE/ATT&CK-linked detection coverage.",
        "sources": [rec.get("citation")],
        "is_withdrawn": bool(rec.get("is_withdrawn")),
        "retrieved_at": _now(),
    }


def _answer_ghsa(rec: dict) -> dict | None:
    return _answer_ghsa_osv(rec, kind="ghsa")


def _answer_osv(rec: dict) -> dict | None:
    return _answer_ghsa_osv(rec, kind="osv")


def _answer_cwe(rec: dict) -> dict | None:
    if rec.get("found") is False:
        return None
    return {
        "identifier": rec.get("cwe_id"),
        "direct_answer": rec.get("description") or rec.get("name") or "",
        "severity_and_exploitation": rec.get("likelihood_of_exploit") or "not recorded.",
        "affected_systems": "applies wherever this weakness pattern occurs — not tied to a specific CVE.",
        "defensive_actions": _format_entries(rec.get("mitigations")) or "no mitigations recorded.",
        "detection_guidance": _format_entries(rec.get("detection_methods"), label_key="method")
                              or "no detection methods recorded.",
        "sources": [rec.get("citation")],
        "retrieved_at": _now(),
    }


def _answer_capec(rec: dict) -> dict | None:
    if rec.get("found") is False:
        return None
    return {
        "identifier": rec.get("capec_id"),
        "direct_answer": rec.get("description") or rec.get("name") or "",
        "severity_and_exploitation": rec.get("typical_severity") or rec.get("likelihood_of_attack") or "not recorded.",
        "affected_systems": _format_strings(rec.get("prerequisites")) or "not recorded.",
        "defensive_actions": _format_entries(rec.get("mitigations")) or "no mitigations recorded.",
        "detection_guidance": "see linked CWE weaknesses for detection methods.",
        "sources": [rec.get("citation")],
        "retrieved_at": _now(),
    }


def _format_coverage(entries: list[dict], unit: str) -> str | None:
    """``technique_coverage()`` mixes two edge shapes under one role: a
    pack-level aggregate (``count`` set, e.g. ``sigma-src`` with N rules) and,
    for D3FEND, a per-countermeasure edge (``count`` is None, ``pack_id`` holds
    the countermeasure's own name instead of a pack id). Render each shape
    correctly rather than printing a literal "(None sources)"."""
    if not entries:
        return None
    named = sorted({e["pack_id"] for e in entries if e.get("count") is None})
    counted = [f"{e['pack_id']} ({e['count']} {unit})" for e in entries if e.get("count") is not None]
    parts = counted + (["D3FEND: " + ", ".join(named)] if named else [])
    return "; ".join(parts) or None


def _answer_attack(rec: dict) -> dict | None:
    if rec.get("found") is False:
        return None
    cov = rec.get("coverage") or {}
    detections = cov.get("detection") or []
    mitigations = cov.get("mitigation") or []
    return {
        "identifier": rec.get("technique_id"),
        "direct_answer": rec.get("label") or rec.get("technique_id"),
        "severity_and_exploitation": rec.get("gap") or "not assessed.",
        "affected_systems": "see the technique's platforms on attack.mitre.org (linked below).",
        "defensive_actions": _format_coverage(mitigations, "sources")
                             or "no D3FEND/mitigation coverage found in the imported set.",
        "detection_guidance": _format_coverage(detections, "rules")
                              or "no Sigma/YARA detection coverage found in the imported set.",
        "sources": [{"source_url": rec.get("source_url"), "title": rec.get("technique_id")}],
        "retrieved_at": _now(),
    }


def _answer_d3fend(rec: dict) -> dict | None:
    if rec.get("found") is False:
        return None
    return {
        "identifier": rec.get("label"),
        "direct_answer": f"D3FEND countermeasure: {rec.get('label')}",
        "severity_and_exploitation": "not applicable — this is a defensive technique, not a vulnerability.",
        "affected_systems": "applies wherever the countered ATT&CK techniques apply.",
        "defensive_actions": f"Implements: {rec.get('label')}. Counters ATT&CK techniques: "
                             + (", ".join(rec.get("counters_techniques") or []) or "none recorded."),
        "detection_guidance": "cross-reference the countered ATT&CK technique ids against installed "
                              "Sigma/YARA detection coverage.",
        "sources": [{"source_url": rec.get("source_url"), "title": rec.get("label")}],
        "retrieved_at": _now(),
    }


_FRAMEWORK_LABELS = {
    "csf": "NIST Cybersecurity Framework (CSF) 2.0",
    "sp800-53": "NIST SP 800-53 Rev. 5",
    "sp800-53-privacy": "NIST SP 800-53 Rev. 5 Privacy Control Baseline",
    "ssdf": "NIST SP 800-218 Secure Software Development Framework (SSDF)",
}


def _answer_control(rec: dict) -> dict | None:
    if rec.get("found") is False:
        return None
    fw_label = _FRAMEWORK_LABELS.get(rec.get("framework"), rec.get("framework"))
    parent = f" (part of {rec['parent_id']})" if rec.get("parent_id") else ""
    examples = _format_strings(rec.get("examples"))
    related = rec.get("related") or []
    related_ids = sorted({l["target_control_id"] for l in related
                          if l.get("rel") == "related" and l.get("target_control_id")})
    cross_refs = [l["note"] for l in related if l.get("rel") == "external_reference" and l.get("note")]
    children = rec.get("children") or []
    return {
        "identifier": rec.get("identifier"),
        "direct_answer": rec.get("statement") or rec.get("title") or "",
        "severity_and_exploitation": "not applicable — this is a compliance control, not a vulnerability.",
        "affected_systems": f"{fw_label} — {rec.get('class')} {rec.get('control_id')}{parent}"
                            + (f"; title: {rec['title']}" if rec.get("title") and rec["title"] != rec.get("control_id") else ""),
        "defensive_actions": rec.get("guidance") or examples or "no separate implementation guidance recorded for this element.",
        "detection_guidance": (
            (f"Related controls: {', '.join(related_ids)}. " if related_ids else "")
            + (f"Cross-framework mappings: {'; '.join(cross_refs)}. " if cross_refs else "")
            + (f"Contains {len(children)} sub-element(s): {', '.join(c['control_id'] for c in children[:15])}"
               f"{'…' if len(children) > 15 else ''}." if children else "")
        ).strip() or "no related-control or cross-framework mapping recorded.",
        "sources": [{"source_url": rec.get("source_url"), "title": rec.get("source_title"),
                    "version": rec.get("version"), "publisher": rec.get("publisher")}],
        "retrieved_at": _now(),
    }


def _exact_lookup_answer(resolved: dict) -> dict:
    items: list[dict] = []
    absent: list[str] = []
    for cve in resolved.get("cve", []):
        a = _answer_cve(cve)
        if a:
            items.append(a)
        else:
            absent.append(cve.get("cve_id", "?"))
    for cwe in resolved.get("cwe", []):
        a = _answer_cwe(cwe)
        if a:
            items.append(a)
        else:
            absent.append(cwe.get("cwe_id", "?"))
    for capec in resolved.get("capec", []):
        a = _answer_capec(capec)
        if a:
            items.append(a)
        else:
            absent.append(capec.get("capec_id", "?"))
    for attack in resolved.get("attack", []):
        a = _answer_attack(attack)
        if a:
            items.append(a)
        else:
            absent.append(attack.get("technique_id", "?"))
    for d3fend in resolved.get("d3fend", []):
        a = _answer_d3fend(d3fend)
        if a:
            items.append(a)
        else:
            absent.append(d3fend.get("local_name", "?"))
    for control in resolved.get("nist_control", []):
        a = _answer_control(control)
        if a:
            items.append(a)
        else:
            absent.append(control.get("control_id", "?"))
    for ghsa in resolved.get("ghsa", []):
        a = _answer_ghsa(ghsa)
        if a:
            items.append(a)
        else:
            absent.append(ghsa.get("ghsa_id", "?"))
    for osv in resolved.get("osv", []):
        a = _answer_osv(osv)
        if a:
            items.append(a)
        else:
            absent.append(osv.get("osv_id", "?"))

    return {
        "route": router.ROUTE_EXACT_LOOKUP,
        "items": items,
        "confidence": _confidence(bool(items), absent),
    }


# ---------------------------------------------------------------------------
# Topic / general routes — citation-grounded, LLM prose is optional.
# ---------------------------------------------------------------------------

async def _topic_answer(question: str, route: str, citations: list[dict],
                        model: str | None) -> dict:
    sources = [{
        "chunk_id": c.get("chunk_id"),
        "title": c.get("source_title") or c.get("document"),
        "source_url": c.get("source_url"),
        "publisher": c.get("publisher"),
        "trust_level": c.get("trust_level"),
        "retrieved_at": _now(),
    } for c in citations]

    direct_answer = None
    llm_available = False
    if citations and model:
        try:
            prompt = rag_service.build_knowledge_prompt(question, citations)
            direct_answer = await ollama_service.generate(prompt, model=model)
            llm_available = True
        except Exception:  # noqa: BLE001 — degrade to citations-only, never fabricate
            direct_answer = None
            llm_available = False

    if direct_answer is None:
        if citations:
            direct_answer = (f"{len(citations)} source(s) found for this {route.replace('_', ' ')} "
                             f"question — see sources below (no local model was reachable to "
                             f"synthesize prose).")
        else:
            direct_answer = _NOT_FOUND

    return {
        "route": route,
        "direct_answer": direct_answer,
        "llm_available": llm_available,
        "detection_guidance": [s["title"] for s in sources] if route == "detection" else None,
        "defensive_actions": [s["title"] for s in sources] if route == "mitigation" else None,
        "sources": sources,
        "confidence": _confidence(bool(citations), []),
    }


def _answer_for_exact_match(rec: dict) -> dict | None:
    if "cve_id" in rec:
        return _answer_cve(rec)
    if "cwe_id" in rec:
        return _answer_cwe(rec)
    if "capec_id" in rec:
        return _answer_capec(rec)
    return None


async def _vuln_filter_answer(question: str, search_result: dict) -> dict:
    exact = search_result.get("exact_matches") or []
    listing = search_result.get("listing") or []
    items = [a for a in (_answer_for_exact_match(r) for r in exact) if a]
    return {
        "route": router.ROUTE_VULN_FILTER,
        "items": items,
        "listing": listing,
        "confidence": _confidence(bool(items or listing), []),
    }


def _package_answer(search_result: dict) -> dict:
    ghsa_items = [a for a in (_answer_ghsa(r) for r in search_result.get("ghsa") or []) if a]
    osv_items = [a for a in (_answer_osv(r) for r in search_result.get("osv") or []) if a]
    items = ghsa_items + osv_items
    eco, pkg = search_result.get("ecosystem"), search_result.get("package")
    if items:
        direct = f"{len(items)} advisory(ies) found for {eco} package \"{pkg}\"."
    else:
        direct = f"{_NOT_FOUND} No GHSA or OSV advisory on file for {eco} package \"{pkg}\"."
    return {
        "route": router.ROUTE_PACKAGE,
        "direct_answer": direct,
        "ecosystem": eco, "package": pkg,
        "items": items,
        "confidence": _confidence(bool(items), []),
    }


_STATUS_TEXT = {
    "not_found": "No installed GHSA/OSV advisory names this package — this is not evidence "
                "the version is safe, only that nothing about it is installed locally.",
    "vulnerable": "This version falls inside at least one installed advisory's affected range.",
    "not_affected_by_installed_advisories": "No installed advisory's affected range covers this "
                                            "version — this reflects only what's installed "
                                            "locally, not a guarantee of safety.",
    "indeterminate": "The version string or an advisory's range could not be confidently "
                     "compared — reporting every matching advisory instead of guessing.",
}


def _answer_version_check(result: dict) -> dict:
    status = result["status"]
    direct = (f"{result['package']}@{result['version']} ({result['ecosystem']}): "
             f"{_STATUS_TEXT.get(status, status)}")
    if result.get("fixed_versions"):
        direct += f" Fixed in: {', '.join(result['fixed_versions'])}."
    return {
        "route": router.ROUTE_VERSION_CHECK,
        "direct_answer": direct,
        "ecosystem": result["ecosystem"], "package": result["package"], "version": result["version"],
        "status": status,
        "fixed_versions": result.get("fixed_versions", []),
        "matches": result.get("matches", []),
        "confidence": _confidence(status not in ("not_found", "indeterminate"), []),
        "retrieved_at": _now(),
    }


def _answer_prioritization(ranked: list[dict]) -> dict:
    found = [r for r in ranked if r.get("found")]
    not_found = [r["cve_id"] for r in ranked if not r.get("found")]
    if not ranked:
        direct = ("No CVE identifiers were found in the question to prioritize — name one or "
                  "more CVE ids (e.g. \"what should I patch first: CVE-2024-1234, CVE-2024-5678\").")
    else:
        direct = f"Ranked {len(found)} of {len(ranked)} named CVE(s) by installed KEV/EPSS/CVSS data."
    return {
        "route": router.ROUTE_PRIORITIZATION,
        "direct_answer": direct,
        "ranked": ranked,
        "not_found": not_found,
        "note": "A defensive patch-triage heuristic over installed data — not a universal risk score.",
        "confidence": _confidence(bool(found), not_found),
        "retrieved_at": _now(),
    }


async def answer(question: str, *, model: str | None = None, top_k: int = 8) -> dict:
    """Full Part-5 grounded answer for ``question``: classify, retrieve, format."""
    routed = await router.route_and_retrieve(question, top_k=top_k)
    route = routed["route"]
    payload: dict
    if route == router.ROUTE_EXACT_LOOKUP:
        payload = _exact_lookup_answer(routed["results"])
    elif route == router.ROUTE_PACKAGE:
        payload = _package_answer(routed["results"])
    elif route == router.ROUTE_VERSION_CHECK:
        payload = _answer_version_check(routed["results"])
    elif route == router.ROUTE_PRIORITIZATION:
        payload = _answer_prioritization(routed["results"])
    elif route == router.ROUTE_VULN_FILTER:
        payload = await _vuln_filter_answer(question, routed["results"])
    else:
        payload = await _topic_answer(question, route, routed["results"], model)

    payload["question"] = question
    payload["matched_keywords"] = routed.get("matched_keywords", [])
    payload["platforms"] = routed.get("platforms", [])
    return payload
