"""Builds the retrieval-compatible text representation for a vulnerability
record — the paragraph that actually gets chunked/embedded into the
``oyster_vulnerabilities`` collection and stored in ``knowledge_chunks``.

CVSS, EPSS and KEV are always rendered as clearly separate, labeled lines —
never merged into one figure — so the distinction survives into anything a
retrieval consumer (the LLM, a citation card) reads back out.
"""

from __future__ import annotations


def vulnerability_text(rec: dict) -> str:
    lines: list[str] = []
    lines.append(f"{rec['cve_id']}"
                 + (f" (status: {rec['vuln_status']})" if rec.get("vuln_status") else ""))
    if rec.get("published_date") or rec.get("last_modified_date"):
        lines.append(f"Published: {rec.get('published_date') or 'unknown'} | "
                      f"Last modified: {rec.get('last_modified_date') or 'unknown'}")
    if rec.get("description"):
        lines.append(f"Description: {rec['description']}")
    cwe_ids = rec.get("cwe_ids") or []
    if cwe_ids:
        lines.append(f"Weakness type(s) (CWE): {', '.join(cwe_ids)}")
    if rec.get("cvss_v3_score") is not None:
        lines.append(f"CVSS v3 (technical severity, NOT exploitation likelihood): "
                      f"{rec['cvss_v3_score']} {rec.get('cvss_v3_severity') or ''} "
                      f"(vector: {rec.get('cvss_v3_vector') or 'n/a'})".strip())
    if rec.get("cvss_v2_score") is not None:
        lines.append(f"CVSS v2: {rec['cvss_v2_score']} {rec.get('cvss_v2_severity') or ''} "
                      f"(vector: {rec.get('cvss_v2_vector') or 'n/a'})".strip())
    if rec.get("epss_score") is not None:
        pct = rec.get("epss_percentile")
        lines.append(f"EPSS (estimated real-world exploitation probability, NOT severity): "
                      f"{rec['epss_score']:.4f}"
                      + (f" ({pct * 100:.1f}th percentile)" if pct is not None else "")
                      + (f" as of {rec['epss_date']}" if rec.get("epss_date") else ""))
    if rec.get("kev_listed"):
        lines.append(
            "CISA KEV status: LISTED — confirmed active exploitation in the wild "
            "(this is neither a severity score nor a probability estimate)."
        )
        if rec.get("kev_vulnerability_name"):
            lines.append(f"KEV vulnerability name: {rec['kev_vulnerability_name']}")
        if rec.get("kev_date_added"):
            lines.append(f"KEV date added: {rec['kev_date_added']}")
        if rec.get("kev_due_date"):
            lines.append(f"KEV required remediation due date: {rec['kev_due_date']}")
        if rec.get("kev_required_action"):
            lines.append(f"KEV required action: {rec['kev_required_action']}")
        if rec.get("kev_known_ransomware"):
            lines.append(f"Known ransomware campaign use: {rec['kev_known_ransomware']}")
    else:
        lines.append("CISA KEV status: not listed as a known exploited vulnerability.")
    refs = rec.get("references") or []
    if refs:
        ref_lines = []
        for r in refs[:15]:
            if isinstance(r, dict):
                ref_lines.append(f"- {r.get('url', '')} ({r.get('source', '')})".strip())
            else:
                ref_lines.append(f"- {r}")
        lines.append("References:\n" + "\n".join(ref_lines))
    return "\n".join(lines)


def cwe_text(rec: dict) -> str:
    lines = [f"{rec['cwe_id']}: {rec.get('name') or ''}".strip()]
    if rec.get("abstraction"):
        lines.append(f"Abstraction: {rec['abstraction']} | Status: {rec.get('status') or 'unknown'}")
    if rec.get("description"):
        lines.append(f"Description: {rec['description']}")
    if rec.get("extended_description"):
        lines.append(f"Extended description: {rec['extended_description']}")
    if rec.get("likelihood_of_exploit"):
        lines.append(f"Likelihood of exploit: {rec['likelihood_of_exploit']}")
    cons = rec.get("common_consequences") or []
    if cons:
        lines.append("Common consequences: " + "; ".join(
            str(c.get("impact") or c) if isinstance(c, dict) else str(c) for c in cons[:10]))
    mits = rec.get("mitigations") or []
    if mits:
        lines.append("Mitigations: " + "; ".join(
            str(m.get("description") or m) if isinstance(m, dict) else str(m) for m in mits[:10]))
    dets = rec.get("detection_methods") or []
    if dets:
        lines.append("Detection methods: " + "; ".join(
            str(d.get("description") or d) if isinstance(d, dict) else str(d) for d in dets[:10]))
    rel = rec.get("related_weaknesses") or []
    if rel:
        lines.append("Related weaknesses: " + "; ".join(
            f"{r.get('nature', '')} {r.get('cwe_id', '')}".strip() if isinstance(r, dict) else str(r)
            for r in rel[:15]))
    if rec.get("version"):
        lines.append(f"MITRE CWE catalog version: {rec['version']}")
    return "\n".join(lines)


def capec_text(rec: dict) -> str:
    lines = [f"{rec['capec_id']}: {rec.get('name') or ''}".strip()]
    if rec.get("abstraction"):
        lines.append(f"Abstraction: {rec['abstraction']} | Status: {rec.get('status') or 'unknown'}")
    if rec.get("description"):
        lines.append(f"Description: {rec['description']}")
    if rec.get("likelihood_of_attack"):
        lines.append(f"Likelihood of attack: {rec['likelihood_of_attack']}")
    if rec.get("typical_severity"):
        lines.append(f"Typical severity: {rec['typical_severity']}")
    flow = rec.get("execution_flow") or []
    if flow:
        steps = []
        for s in flow[:10]:
            if isinstance(s, dict):
                steps.append(f"{s.get('phase', '')}: {s.get('description', '')}".strip(": "))
            else:
                steps.append(str(s))
        lines.append("Execution flow: " + " | ".join(steps))
    prereqs = rec.get("prerequisites") or []
    if prereqs:
        lines.append("Prerequisites: " + "; ".join(str(p) for p in prereqs[:10]))
    rel_cwe = rec.get("related_weaknesses") or []
    if rel_cwe:
        lines.append(f"Related weaknesses (CWE): {', '.join(rel_cwe)}")
    mits = rec.get("mitigations") or []
    if mits:
        lines.append("Mitigations: " + "; ".join(
            str(m.get("description") or m) if isinstance(m, dict) else str(m) for m in mits[:10]))
    if rec.get("version"):
        lines.append(f"MITRE CAPEC catalog version: {rec['version']}")
    return "\n".join(lines)
