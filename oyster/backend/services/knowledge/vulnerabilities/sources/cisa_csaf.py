"""CISA CSAF (Common Security Advisory Framework) vendor advisories.

CISA publishes real, official, machine-readable CSAF 2.0 JSON advisories for
both IT and OT/ICS products via its trusted-provider CSAF distribution point
(``www.cisa.gov/.../csaf/provider-metadata.json``), which points at the
``cisagov/CSAF`` GitHub repository's ROLIE feeds. These are TLP:WHITE (public)
by CISA's own metadata.

Each advisory enriches — never duplicates — the existing NVD-derived
``vulnerability_records`` row for its CVE(s): real CVSS, CWE, vendor
remediation text and fixed-version info, plus a citation back to CISA's own
published advisory. A CVE with no matching NVD row yet still gets its
enrichment row stored (joined at answer time), so nothing is dropped.

Production incremental synchronizer: walks the *entire* available feed index
(no fixed truncation) but only re-fetches an advisory document when the
ROLIE feed's own ``updated`` timestamp has moved past what was recorded on a
prior run (see ``store.cisa_csaf_seen``) — the resume/checkpoint mechanism.
A caller-supplied ``max_advisories``/wall-clock budget still applies at the
*sync* layer (``sync.py``) so a single invocation stays bounded; this module
itself has no artificial ceiling on corpus size.
"""

from __future__ import annotations

import asyncio

import httpx

import config
from services.knowledge.connectors import injection_scan

from .. import identity

SOURCE_ID = "cisa-csaf"
LICENCE = "public-domain"
ATTRIBUTION = "CISA Cybersecurity and Industrial Control Systems Advisories (CSAF), Cybersecurity and Infrastructure Security Agency — a U.S. Government work."

PROVIDER_METADATA_URL = "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json"
_MAX_ADVISORY_BYTES = 2 * 1024 * 1024


async def _get_json(client: httpx.AsyncClient, url: str) -> dict:
    resp = await client.get(url)
    resp.raise_for_status()
    return resp.json()


async def fetch_feed_index() -> list[dict]:
    """Every advisory entry across CISA's public (TLP:WHITE) IT and OT/ICS
    ROLIE feeds, each with its own real document URL and feed-reported
    ``updated`` timestamp (the checkpoint key), newest first."""
    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        meta = await _get_json(client, PROVIDER_METADATA_URL)
        feed_urls = []
        for dist in meta.get("distributions", []):
            for feed in dist.get("rolie", {}).get("feeds", []):
                if feed.get("tlp_label") == "WHITE" and feed.get("url"):
                    feed_urls.append(feed["url"])

        entries: list[dict] = []
        for feed_url in feed_urls:
            feed = await _get_json(client, feed_url)
            source = "cisa-csaf-ot" if "/OT/" in feed_url else "cisa-csaf-it"
            for e in feed.get("feed", {}).get("entry", []):
                content_url = (e.get("content") or {}).get("src")
                if not content_url:
                    continue
                entries.append({
                    "advisory_id": e.get("id"), "title": e.get("title"),
                    "published": e.get("published"), "updated": e.get("updated"),
                    "content_url": content_url, "source": source,
                })

    entries.sort(key=lambda e: e.get("updated") or e.get("published") or "", reverse=True)
    return entries


async def fetch_advisory(client: httpx.AsyncClient, url: str) -> dict:
    """Single attempt — retry/backoff lives in ``fetch_advisory_with_retry``."""
    resp = await client.get(url)
    resp.raise_for_status()
    if len(resp.content) > _MAX_ADVISORY_BYTES:
        raise ValueError("CSAF advisory exceeds size budget")
    return resp.json()


async def fetch_advisory_with_retry(client: httpx.AsyncClient, url: str,
                                    max_retries: int | None = None) -> dict:
    retries = config.CISA_CSAF_MAX_RETRIES if max_retries is None else max_retries
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await fetch_advisory(client, url)
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                await asyncio.sleep(2 ** attempt)
                last_exc = e
                continue
            raise
        except (httpx.TimeoutException, httpx.TransportError) as e:
            last_exc = e
            if attempt < retries:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
    raise last_exc or RuntimeError("CSAF advisory fetch failed with no captured exception")


def normalize_advisory(raw: dict, entry: dict) -> tuple[dict, list[dict], int]:
    """Returns (advisory_meta, per_cve_findings, injection_findings_count).
    Never fabricates a CVE/CVSS/remediation — fields not present in the real
    CSAF document are left ``None``, never guessed."""
    doc = raw.get("document", {})
    tracking = doc.get("tracking", {})
    findings_count = 0

    def _clean(s):
        nonlocal findings_count
        if not s:
            return s
        clean, f = injection_scan.neutralize(s)
        findings_count += len(f)
        return clean

    advisory = {
        "advisory_id": entry["advisory_id"],
        "source": entry["source"],
        "title": _clean(doc.get("title") or entry.get("title")),
        "publisher": (doc.get("publisher") or {}).get("name"),
        "initial_release_date": tracking.get("initial_release_date"),
        "current_release_date": tracking.get("current_release_date"),
        "source_url": entry["content_url"],
    }

    per_cve: list[dict] = []
    for v in raw.get("vulnerabilities", []) or []:
        cve_id = identity.normalize_cve(v.get("cve"))
        if cve_id is None:
            continue
        cwe = v.get("cwe") or {}
        score = None
        vector = None
        severity = None
        for s in v.get("scores", []) or []:
            v3 = s.get("cvss_v3")
            if v3:
                score, vector, severity = v3.get("baseScore"), v3.get("vectorString"), v3.get("baseSeverity")
                break
        description = None
        for note in v.get("notes", []) or []:
            if note.get("category") == "summary":
                description = _clean(note.get("text"))
                break
        remediation_parts = []
        fixed_version = None
        for rem in v.get("remediations", []) or []:
            details = _clean(rem.get("details"))
            if details:
                remediation_parts.append(details)
                if "fixed in" in details.lower() and fixed_version is None:
                    fixed_version = details
        vendor_ref = None
        for ref in v.get("references", []) or []:
            if ref.get("category") == "external" and "cve.org" not in (ref.get("url") or ""):
                vendor_ref = ref.get("url")
                break
        per_cve.append({
            "cve_id": cve_id, "cwe_id": cwe.get("id"),
            "cvss_score": score, "cvss_vector": vector, "severity": severity,
            "description": description,
            "remediation": " | ".join(remediation_parts) or None,
            "fixed_version": fixed_version,
            "vendor_reference_url": vendor_ref,
        })

    return advisory, per_cve, findings_count
