"""CISA Known Exploited Vulnerabilities catalog — single JSON feed, no auth.

https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import json

import httpx

import config
from services.knowledge.connectors import injection_scan

from .. import identity
from ..models import KevEntry
from ..rate_limit import get_capped

SOURCE_ID = "cisa-kev"
LICENCE = "cisa-kev-public"
ATTRIBUTION = "CISA Known Exploited Vulnerabilities (KEV) Catalog, Cybersecurity and Infrastructure Security Agency."


async def fetch_raw() -> dict:
    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        raw = await get_capped(client, config.KEV_FEED_URL)
        return json.loads(raw)


def normalize(raw: dict) -> tuple[list[KevEntry], dict, int]:
    """Returns (entries, catalog_meta, injection_findings_count)."""
    entries: list[KevEntry] = []
    findings = 0
    for v in raw.get("vulnerabilities", []):
        cve_id = identity.normalize_cve(v.get("cveID"))
        if cve_id is None:
            continue  # not a real CVE id — never invent/guess one

        def _clean(s):
            nonlocal findings
            if not s:
                return s
            clean, f = injection_scan.neutralize(s)
            findings += len(f)
            return clean

        cwe_ids = [c for c in (identity.normalize_cwe(x) for x in v.get("cwes", []) or []) if c]
        entries.append(KevEntry(
            cve_id=cve_id,
            vendor_project=_clean(v.get("vendorProject")),
            product=_clean(v.get("product")),
            vulnerability_name=_clean(v.get("vulnerabilityName")),
            date_added=v.get("dateAdded"),
            short_description=_clean(v.get("shortDescription")),
            required_action=_clean(v.get("requiredAction")),
            due_date=v.get("dueDate"),
            known_ransomware=v.get("knownRansomwareCampaignUse"),
            notes=_clean(v.get("notes")),
            cwe_ids=cwe_ids,
        ))
    meta = {
        "catalog_version": raw.get("catalogVersion"),
        "date_released": raw.get("dateReleased"),
        "count": raw.get("count"),
    }
    return entries, meta, findings
