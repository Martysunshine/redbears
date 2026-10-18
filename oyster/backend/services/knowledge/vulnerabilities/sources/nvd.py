"""NIST NVD CVE 2.0 API — paginated, windowed, rate-limited, resumable.

https://nvd.nist.gov/developers/vulnerabilities

Works with or without an API key (``OYSTER_NVD_API_KEY``, read from the
environment only — never from a `.env` file, never logged). Absent, the
conservative unauthenticated pace applies; nothing about this connector
requires a key to function correctly, just more slowly.
"""

from __future__ import annotations

import asyncio
import re

import httpx

import config
from services.knowledge.connectors import injection_scan

from .. import identity
from ..models import NvdCveEntry
from ..rate_limit import Pacer, nvd_api_key, nvd_min_interval_seconds, shared_pacer

SOURCE_ID = "nvd-cve"
LICENCE = "nist-nvd-public"
ATTRIBUTION = "National Vulnerability Database (NVD), National Institute of Standards and Technology (NIST)."

_CPE_RE = re.compile(r"^cpe:2\.3:[aoh]:([^:]*):([^:]*):([^:]*):")


def new_pacer() -> Pacer:
    """The process-wide pacer.

    Name kept for its three existing call sites, but it no longer builds a fresh
    one per call — NIST rate-limits this server's IP, not an individual sync, so
    every caller has to share the same spacing or overlapping syncs double the
    real request rate.
    """
    return shared_pacer()


def _headers() -> dict:
    key = nvd_api_key()
    return {"apiKey": key} if key else {}


def _clean(text: str | None, findings_counter: list[int]) -> str | None:
    if not text:
        return text
    clean, f = injection_scan.neutralize(text)
    findings_counter[0] += len(f)
    return clean


def _best_cvss_v4(metrics: dict) -> tuple[str | None, float | None, str | None, str | None]:
    entries = metrics.get("cvssMetricV40") or []
    if not entries:
        return None, None, None, None
    primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
    data = primary.get("cvssData", {})
    return (data.get("vectorString"), data.get("baseScore"), data.get("baseSeverity"),
            primary.get("source"))


def _best_cvss_v3(metrics: dict) -> tuple[str | None, float | None, str | None, str | None]:
    """Prefer cvssMetricV31 over V30; within a version prefer type=Primary."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {})
        return (data.get("vectorString"), data.get("baseScore"), data.get("baseSeverity"),
                primary.get("source"))
    return None, None, None, None


def _best_cvss_v2(metrics: dict) -> tuple[str | None, float | None, str | None]:
    entries = metrics.get("cvssMetricV2") or []
    if not entries:
        return None, None, None
    primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
    data = primary.get("cvssData", {})
    return data.get("vectorString"), data.get("baseScore"), data.get("baseSeverity")


# NVD's own metric-block key -> the CVSS version label we store alongside it.
_CVSS_METRIC_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                    ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))


def _all_cvss_scores(metrics: dict) -> list[dict]:
    """Every individual CVSS metric entry NVD returned, one row per
    (source, version) — preserves disagreement between e.g. the NVD-assigned
    score and a CNA- or ADP-submitted score instead of collapsing to one."""
    out: list[dict] = []
    for key, version in _CVSS_METRIC_KEYS:
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData", {})
            out.append({
                "source": entry.get("source"), "cvss_version": version,
                "vector": data.get("vectorString"), "score": data.get("baseScore"),
                "severity": data.get("baseSeverity"), "type": entry.get("type"),
            })
    return out


def _parse_cpe(criteria: str) -> dict | None:
    m = _CPE_RE.match(criteria or "")
    if not m:
        return None
    vendor, product, version = m.groups()
    return {"vendor": vendor, "product": product, "version": version, "cpe": criteria}


def normalize_cve_obj(cve: dict, findings_counter: list[int] | None = None) -> NvdCveEntry | None:
    cve_id = identity.normalize_cve(cve.get("id"))
    if cve_id is None:
        return None
    findings = findings_counter if findings_counter is not None else [0]

    description = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value")
            break

    cwe_ids: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") != "en":
                continue
            norm = identity.normalize_cwe(d.get("value"))
            if norm and norm not in cwe_ids:
                cwe_ids.append(norm)

    references = []
    for r in cve.get("references", [])[: config.VULN_MAX_REFERENCES_STORED]:
        references.append({"url": r.get("url"), "source": r.get("source"),
                           "tags": r.get("tags", [])})

    products: list[dict] = []
    for block in cve.get("configurations", []) or []:
        for node in block.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                parsed = _parse_cpe(match.get("criteria", ""))
                if parsed:
                    products.append(parsed)
                if len(products) >= config.VULN_MAX_CPE_MATCHES_STORED:
                    break
            if len(products) >= config.VULN_MAX_CPE_MATCHES_STORED:
                break
        if len(products) >= config.VULN_MAX_CPE_MATCHES_STORED:
            break

    metrics = cve.get("metrics", {})
    v4_vector, v4_score, v4_sev, v4_source = _best_cvss_v4(metrics)
    v3_vector, v3_score, v3_sev, v3_source = _best_cvss_v3(metrics)
    v2_vector, v2_score, v2_sev = _best_cvss_v2(metrics)
    # Deterministic preferred-score policy, explicit and provenance-tagged:
    # newest CVSS version wins (v4 > v3.1/v3.0 > v2), Primary over Secondary
    # within a version — see _best_cvss_v4/_best_cvss_v3/_best_cvss_v2. The
    # "preferred source" recorded is whichever version actually won.
    preferred_source = v4_source or v3_source

    return NvdCveEntry(
        cve_id=cve_id,
        vuln_status=cve.get("vulnStatus"),
        description=_clean(description, findings),
        source_identifier=cve.get("sourceIdentifier"),
        published_date=cve.get("published"),
        last_modified_date=cve.get("lastModified"),
        cvss_v4_vector=v4_vector, cvss_v4_score=v4_score, cvss_v4_severity=v4_sev,
        cvss_v3_vector=v3_vector, cvss_v3_score=v3_score, cvss_v3_severity=v3_sev,
        cvss_v2_vector=v2_vector, cvss_v2_score=v2_score, cvss_v2_severity=v2_sev,
        cvss_source=preferred_source,
        cwe_ids=cwe_ids,
        references=references,
        affected_products=products,
        all_cvss_scores=_all_cvss_scores(metrics),
    )


async def _get_with_retry(client: httpx.AsyncClient, pacer: Pacer, params: dict) -> dict:
    last_exc: Exception | None = None
    for attempt in range(config.NVD_MAX_RETRIES + 1):
        await pacer.wait()
        try:
            resp = await client.get(config.NVD_API_BASE_URL, params=params,
                                    headers=_headers(), timeout=config.NVD_NET_TIMEOUT_S)
            if resp.status_code in (403, 429):
                await asyncio.sleep(2 ** attempt)
                last_exc = RuntimeError(f"NVD rate-limited (HTTP {resp.status_code})")
                continue
            resp.raise_for_status()
            return resp.json()
        except (httpx.TimeoutException, httpx.TransportError) as e:
            last_exc = e
            await asyncio.sleep(2 ** attempt)
    raise last_exc or RuntimeError("NVD request failed with no captured exception")


async def fetch_window(start_iso: str, end_iso: str, *, results_per_page: int | None = None,
                       max_pages: int | None = None) -> list[dict]:
    """Fetch every CVE with lastModified in [start_iso, end_iso). Returns raw
    ``cve`` dicts (not yet normalized) so the caller can track fetch progress
    page by page for checkpointing."""
    per_page = results_per_page or config.NVD_RESULTS_PER_PAGE
    pacer = new_pacer()
    out: list[dict] = []
    start_index = 0
    pages = 0
    async with httpx.AsyncClient() as client:
        while True:
            params = {
                "lastModStartDate": start_iso, "lastModEndDate": end_iso,
                "resultsPerPage": per_page, "startIndex": start_index,
            }
            data = await _get_with_retry(client, pacer, params)
            vulns = data.get("vulnerabilities", [])
            out.extend(v["cve"] for v in vulns if "cve" in v)
            total = data.get("totalResults", len(out))
            start_index += len(vulns)
            pages += 1
            if start_index >= total or not vulns:
                break
            if max_pages is not None and pages >= max_pages:
                break
    return out


async def fetch_by_cve_id(cve_id: str) -> dict | None:
    pacer = new_pacer()
    async with httpx.AsyncClient() as client:
        data = await _get_with_retry(client, pacer, {"cveId": cve_id})
    vulns = data.get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None
