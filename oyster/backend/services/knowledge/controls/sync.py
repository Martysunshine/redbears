"""Sync NIST OSCAL catalogs (CSF 2.0, SP 800-53 rev5, SSDF, SP 800-53 privacy
baseline) into the structured ``control_records`` table.

Each catalog is the official machine-readable OSCAL export published by
NIST/CSRC in ``usnistgov/oscal-content`` (public domain — a US government
work, 17 U.S.C. §105). Downloaded once per sync, parsed by ``oscal.py`` (pure,
no network), and written idempotently via ``store.upsert_control`` — an
unchanged upstream record is a no-op write.
"""

from __future__ import annotations

import requests

import config

from . import oscal, store

_MAX_BYTES = 32 * 1024 * 1024

# One entry per catalog. ``citation_url`` is the real, resolvable DOI/CSRC
# publication landing page (never a guessed per-control deep link).
_CATALOGS = {
    "csf": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json",
        "citation_url": "https://doi.org/10.6028/NIST.CSWP.29.ipd",
        "source_title": "NIST Cybersecurity Framework (CSF) 2.0",
        "publisher": "National Institute of Standards and Technology",
        "guidance_part": "guidance", "example_part": "example",
    },
    "sp800-53": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
        "citation_url": "https://doi.org/10.6028/NIST.SP.800-53r5",
        "source_title": "NIST SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations",
        "publisher": "National Institute of Standards and Technology",
        "guidance_part": "guidance", "example_part": "example",
    },
    "ssdf": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-218/ver1/json/NIST_SP800-218_ver1_catalog.json",
        "citation_url": "https://csrc.nist.gov/publications/detail/sp/800-218/final",
        "source_title": "NIST SP 800-218 — Secure Software Development Framework (SSDF) v1.1",
        "publisher": "National Institute of Standards and Technology",
        "guidance_part": "guidance", "example_part": "example",
    },
    "sp800-53-privacy": {
        "url": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_PRIVACY-baseline-resolved-profile_catalog.json",
        "citation_url": "https://doi.org/10.6028/NIST.SP.800-53r5",
        "source_title": "NIST SP 800-53 Rev. 5 — Privacy Control Baseline (resolved profile)",
        "publisher": "National Institute of Standards and Technology",
        "guidance_part": "guidance", "example_part": "example",
    },
}


def available_frameworks() -> list[str]:
    return list(_CATALOGS)


def sync_framework(framework: str) -> dict:
    cfg = _CATALOGS.get(framework)
    if cfg is None:
        return {"ok": False, "error": f"unknown framework '{framework}'"}

    try:
        r = requests.get(cfg["url"], timeout=config.KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        return {"ok": False, "framework": framework, "error": f"download failed: {e}"}
    if len(r.content) > _MAX_BYTES:
        return {"ok": False, "framework": framework, "error": "catalog exceeds size budget"}

    try:
        data = r.json()
        catalog = data["catalog"]
    except (ValueError, KeyError) as e:
        return {"ok": False, "framework": framework, "error": f"malformed OSCAL catalog: {e}"}

    version = catalog.get("metadata", {}).get("version")
    published = catalog.get("metadata", {}).get("last-modified")

    records, links_by_control = oscal.walk_catalog(
        catalog, framework, cfg["guidance_part"], cfg["example_part"],
    )

    written = 0
    unchanged = 0
    for rec in records:
        rec["source_url"] = cfg["citation_url"]
        rec["source_title"] = cfg["source_title"]
        rec["publisher"] = cfg["publisher"]
        rec["version"] = version
        rec["published_date"] = published
        changed = store.upsert_control(rec)
        if changed:
            written += 1
        else:
            unchanged += 1
        links = links_by_control.get(rec["control_id"])
        if links:
            store.replace_links(framework, rec["control_id"], links)

    link_count = sum(len(v) for v in links_by_control.values())
    store.record_sync(framework, version, len(records), link_count, cfg["url"])

    return {
        "ok": True, "framework": framework, "version": version,
        "records": len(records), "written": written, "unchanged": unchanged,
        "links": link_count, "source_url": cfg["url"],
    }


def sync_all() -> list[dict]:
    return [sync_framework(fw) for fw in _CATALOGS]
