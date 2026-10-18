"""Vulnerability-aware retrieval: exact CVE/CWE/CAPEC lookup first, semantic
search as a supplement — never the other way around, so an identifier-shaped
query always resolves to real stored data or a clean "not found locally," and
never a fabricated match.

CVSS, EPSS and KEV are surfaced as three separate labeled objects everywhere
in this module's output — never merged into one figure. A KEV listing boosts
ranking only; it is never written into a severity field.
"""

from __future__ import annotations

import config

from . import identity, osv_store, store
from .sources import capec as capec_src
from .sources import cwe as cwe_src
from .sources import ghsa as ghsa_src
from .sources import osv as osv_src

KEV_RANK_BOOST = 1.25


def _cvss_epss_kev(rec: dict) -> dict:
    return {
        "cvss": {
            "v4": ({"score": rec.get("cvss_v4_score"), "severity": rec.get("cvss_v4_severity"),
                    "vector": rec.get("cvss_v4_vector")} if rec.get("cvss_v4_score") is not None else None),
            "v3": ({"score": rec.get("cvss_v3_score"), "severity": rec.get("cvss_v3_severity"),
                    "vector": rec.get("cvss_v3_vector")} if rec.get("cvss_v3_score") is not None else None),
            "v2": ({"score": rec.get("cvss_v2_score"), "severity": rec.get("cvss_v2_severity"),
                    "vector": rec.get("cvss_v2_vector")} if rec.get("cvss_v2_score") is not None else None),
            "preferred_source": rec.get("cvss_source"),
        },
        "epss": ({"score": rec.get("epss_score"), "percentile": rec.get("epss_percentile"),
                  "as_of": rec.get("epss_date")} if rec.get("epss_score") is not None else None),
        "kev": {
            "listed": bool(rec.get("kev_listed")),
            "date_added": rec.get("kev_date_added"),
            "due_date": rec.get("kev_due_date"),
            "vulnerability_name": rec.get("kev_vulnerability_name"),
            "required_action": rec.get("kev_required_action"),
            "known_ransomware": rec.get("kev_known_ransomware"),
        },
    }


def get_cve(cve_id: str) -> dict | None:
    norm = identity.normalize_cve(cve_id)
    if norm is None:
        return None
    rec = store.get_vulnerability(norm)
    if rec is None:
        return None
    out = dict(rec)
    out.update(_cvss_epss_kev(rec))
    out["citation"] = {"source_url": f"https://nvd.nist.gov/vuln/detail/{norm}",
                       "title": norm, "publisher": "NVD / CISA / FIRST"}
    out["vendor_advisories"] = store.get_vendor_advisories_for_cve(norm)
    out["cvss_by_source"] = store.get_cvss_scores_for_cve(norm)
    out["distro_fixes"] = _distro_fixes_for_cve(norm)
    return out


_DISTRO_ECOSYSTEMS = {"Debian", "Alpine"}  # Ubuntu's OSV export exceeds the storage-safety cap; not installed


def _distro_fixes_for_cve(cve_id: str) -> list[dict]:
    """OS-package-level fix info (e.g. 'Debian: fixed in libx-1.2.3') for a
    CVE, sourced from the OSV Debian/Alpine ecosystem exports and the CVE
    alias each OSV record itself carries — never inferred, never guessed at
    for a distro that isn't installed."""
    out: list[dict] = []
    for rec in osv_store.find_osv_by_alias(cve_id):
        eco_source = rec.get("ecosystem_source")
        if eco_source not in _DISTRO_ECOSYSTEMS:
            continue
        for a in rec.get("affected") or []:
            out.append({
                "distro": eco_source, "package": a.get("package"),
                "introduced": a.get("introduced"), "fixed": a.get("fixed"),
                "last_affected": a.get("last_affected"),
                "osv_id": rec.get("osv_id"), "withdrawn": rec.get("is_withdrawn", False),
            })
    return out


def get_cwe(cwe_id: str) -> dict | None:
    norm = identity.normalize_cwe(cwe_id)
    if norm is None:
        return None
    rec = store.get_cwe(norm)
    if rec is None:
        return None
    rec = dict(rec)
    rec["citation"] = {
        "source_url": f"https://cwe.mitre.org/data/definitions/{norm.split('-')[1]}.html",
        "title": f"{norm}: {rec.get('name') or ''}", "publisher": "MITRE",
        "licence": cwe_src.LICENCE, "attribution": cwe_src.ATTRIBUTION,
    }
    return rec


def get_capec(capec_id: str) -> dict | None:
    norm = identity.normalize_capec(capec_id)
    if norm is None:
        return None
    rec = store.get_capec(norm)
    if rec is None:
        return None
    rec = dict(rec)
    rec["citation"] = {
        "source_url": f"https://capec.mitre.org/data/definitions/{norm.split('-')[1]}.html",
        "title": f"{norm}: {rec.get('name') or ''}", "publisher": "MITRE",
        "licence": capec_src.LICENCE, "attribution": capec_src.ATTRIBUTION,
    }
    return rec


def get_ghsa(ghsa_id: str) -> dict | None:
    norm = identity.normalize_ghsa(ghsa_id)
    if norm is None:
        return None
    rec = osv_store.get_ghsa(norm)
    if rec is None:
        return None
    rec["citation"] = {"source_url": ghsa_src.source_url_for(norm), "title": norm,
                       "publisher": "GitHub Security Advisory Database",
                       "licence": ghsa_src.LICENCE, "attribution": ghsa_src.ATTRIBUTION}
    return rec


def get_osv(osv_id: str) -> dict | None:
    norm = identity.normalize_osv_id(osv_id)
    if norm is None:
        return None
    rec = osv_store.get_osv(norm)
    if rec is None:
        return None
    rec["citation"] = {"source_url": f"https://osv.dev/vulnerability/{norm}", "title": norm,
                       "publisher": f"OSV.dev ({rec.get('ecosystem_source') or 'unknown ecosystem'})",
                       "licence": osv_src.LICENCE, "attribution": osv_src.ATTRIBUTION}
    return rec


def search_package_vulnerabilities(ecosystem: str, package: str) -> dict:
    """Real structured lookup across both GHSA and OSV for a given
    ecosystem/package pair — never a semantic guess. Returns both source's
    findings labeled separately so the caller can see where each came from."""
    ghsa_hits = osv_store.search_ghsa_by_package(ecosystem, package)
    osv_hits = osv_store.search_osv_by_package(ecosystem, package)
    for r in ghsa_hits:
        r["citation"] = {"source_url": ghsa_src.source_url_for(r["ghsa_id"]), "title": r["ghsa_id"],
                         "publisher": "GitHub Security Advisory Database"}
    for r in osv_hits:
        r["citation"] = {"source_url": f"https://osv.dev/vulnerability/{r['osv_id']}", "title": r["osv_id"],
                         "publisher": f"OSV.dev ({r.get('ecosystem_source') or ecosystem})"}
    return {"ecosystem": ecosystem, "package": package, "ghsa": ghsa_hits, "osv": osv_hits,
           "found": bool(ghsa_hits or osv_hits)}


def capecs_related_to_cwe(cwe_id: str) -> list[dict]:
    norm = identity.normalize_cwe(cwe_id)
    if norm is None:
        return []
    cwe_rec = store.get_cwe(norm)
    if cwe_rec is None:
        return []
    return [get_capec(cid) for cid in cwe_rec.get("related_capec_ids", []) if get_capec(cid)]


async def search(query: str, top_k: int = 8, kev_only: bool = False,
                 min_cvss: float | None = None, min_epss: float | None = None,
                 since: str | None = None) -> dict:
    """Identifier-aware search: exact CVE/CWE/CAPEC ids in the query are
    resolved first (guaranteed real or explicitly absent); free-text queries
    fall back to the filtered/ranked vulnerability_records listing."""
    ids = identity.find_identifiers(query)
    exact: list[dict] = []
    for cve_id in ids["cve"]:
        rec = get_cve(cve_id)
        exact.append(rec if rec else {"cve_id": cve_id, "found": False})
    for cwe_id in ids["cwe"]:
        rec = get_cwe(cwe_id)
        exact.append(rec if rec else {"cwe_id": cwe_id, "found": False})
    for capec_id in ids["capec"]:
        rec = get_capec(capec_id)
        exact.append(rec if rec else {"capec_id": capec_id, "found": False})

    listing = store.search_vulnerabilities(kev_only=kev_only, min_cvss=min_cvss,
                                           min_epss=min_epss, since=since, limit=top_k)
    # KEV ranking boost applied to ORDER only — never mutates a stored value.
    listing = sorted(listing, key=lambda r: (KEV_RANK_BOOST if r.get("kev_listed") else 1.0)
                     * (r.get("epss_score") or 0), reverse=True)
    return {"query": query, "identified": ids, "exact_matches": exact, "listing": listing}
