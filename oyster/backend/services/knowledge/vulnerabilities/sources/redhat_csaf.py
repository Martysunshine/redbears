"""Red Hat CSAF (Common Security Advisory Framework) vendor advisories.

Red Hat publishes real, official, machine-readable CSAF 2.0 JSON advisories via
its trusted-provider CSAF distribution point
(``security.access.redhat.com/data/csaf/v2/provider-metadata.json``), which
explicitly declares ``list_on_CSAF_aggregators`` and ``mirror_on_CSAF_aggregators``
as true — CSAF's own standard signal that downstream mirroring is authorized.
Every individual advisory document additionally carries its own
``legal_disclaimer`` note stating the content is licensed CC BY 4.0 (verified
directly against a real advisory, not inferred).

Only ``RHSA-*`` (security advisory) documents are fetched — the same feed also
lists ``RHBA-*`` (bug fix) and ``RHEA-*`` (enhancement) advisories, which carry
no CVE/CVSS content and would be storage noise for a vulnerability-intelligence
knowledge base.

Same production shape as ``cisa_csaf.py``: resume/checkpoint via
``redhat_csaf_seen`` (keyed on the provider's own per-file ``changes.csv``
timestamp), bounded concurrency + retry/backoff (``fetch_advisory_with_retry``
is imported directly from ``cisa_csaf`` — it is fully generic, CISA-specific
only in name), never fabricates a field CSAF didn't provide.
"""

from __future__ import annotations

import csv
import io

import httpx

import config
from services.knowledge.connectors import injection_scan

from .. import identity
from .cisa_csaf import fetch_advisory_with_retry  # generic client+url fetch, reused as-is

SOURCE_ID = "redhat-csaf"
LICENCE = "cc-by-4.0"
ATTRIBUTION = ("Red Hat Product Security Advisories (CSAF), Red Hat, Inc. — "
              "licensed CC BY 4.0 per each advisory's own legal_disclaimer note.")

PROVIDER_METADATA_URL = "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json"
INDEX_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/index.txt"
CHANGES_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/changes.csv"
ADVISORIES_BASE = "https://security.access.redhat.com/data/csaf/v2/advisories/"


async def fetch_feed_index() -> list[dict]:
    """Every RHSA advisory entry with its real document URL and the provider's
    own per-file ``changes.csv`` timestamp (the checkpoint key), newest first.
    Bug-fix (RHBA) and enhancement (RHEA) advisories are excluded — they carry
    no CVE/CVSS content."""
    async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
        resp = await client.get(CHANGES_URL)
        resp.raise_for_status()
        reader = csv.reader(io.StringIO(resp.text))
        entries: list[dict] = []
        seen_paths: set[str] = set()
        for row in reader:
            if len(row) < 2:
                continue
            rel_path, updated = row[0].strip(), row[1].strip()
            fname = rel_path.rsplit("/", 1)[-1]
            if not fname.lower().startswith("rhsa-") or not fname.endswith(".json"):
                continue
            if rel_path in seen_paths:
                continue
            seen_paths.add(rel_path)
            advisory_id = fname[:-5].upper().replace("_", ":", 1)
            entries.append({
                "advisory_id": advisory_id,
                "content_url": ADVISORIES_BASE + rel_path,
                "updated": updated,
                "source": SOURCE_ID,
            })
    entries.sort(key=lambda e: e.get("updated") or "", reverse=True)
    return entries


def normalize_advisory(raw: dict, entry: dict) -> tuple[dict, list[dict], int]:
    """Returns (advisory_meta, per_cve_findings, injection_findings_count).
    Never fabricates a CVE/CVSS/remediation — fields not present in the real
    CSAF document are left ``None``, never guessed.

    Differs from CISA's ``normalize_advisory`` only in how remediation/fixed-
    version info is derived: Red Hat's CSAF uses a per-vulnerability
    ``product_status.fixed`` list of fixed package NVRs rather than a free-text
    ``remediations[].details`` block."""
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
            if note.get("category") == "description":
                description = _clean(note.get("text"))
                break
        if description is None:
            for note in v.get("notes", []) or []:
                if note.get("category") == "summary":
                    description = _clean(note.get("text"))
                    break
        fixed_nvrs = list((v.get("product_status") or {}).get("fixed") or [])
        fixed_version = "; ".join(sorted(set(fixed_nvrs))[:10]) if fixed_nvrs else None
        remediation = f"Fixed in: {fixed_version}" if fixed_version else None
        vendor_ref = None
        for ref in v.get("references", []) or []:
            if ref.get("category") == "self" and "redhat.com" in (ref.get("url") or ""):
                vendor_ref = ref.get("url")
                break
        per_cve.append({
            "cve_id": cve_id, "cwe_id": cwe.get("id"),
            "cvss_score": score, "cvss_vector": vector, "severity": severity,
            "description": description,
            "remediation": remediation,
            "fixed_version": fixed_version,
            "vendor_reference_url": vendor_ref,
        })

    return advisory, per_cve, findings_count
