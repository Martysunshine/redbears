"""Normalized record shapes produced by each vulnerability source module,
before they are merged into the SQLite store by CVE/CWE/CAPEC id.

Plain dataclasses — no I/O, no execution. Every free-text field is expected to
already be injection-neutralized by the source module (via
``connectors.injection_scan.neutralize``) before a record reaches here.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class KevEntry:
    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    short_description: str | None = None
    required_action: str | None = None
    due_date: str | None = None
    known_ransomware: str | None = None
    notes: str | None = None
    cwe_ids: list[str] = field(default_factory=list)


@dataclass
class NvdCveEntry:
    cve_id: str
    vuln_status: str | None = None
    description: str | None = None
    source_identifier: str | None = None
    published_date: str | None = None
    last_modified_date: str | None = None
    cvss_v4_vector: str | None = None
    cvss_v4_score: float | None = None
    cvss_v4_severity: str | None = None
    cvss_v3_vector: str | None = None
    cvss_v3_score: float | None = None
    cvss_v3_severity: str | None = None
    cvss_v2_vector: str | None = None
    cvss_v2_score: float | None = None
    cvss_v2_severity: str | None = None
    cvss_source: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    affected_products: list[dict] = field(default_factory=list)
    # Every individual CVSS metric entry NVD returned (not just the
    # "preferred" one selected above) — one dict per (source, version) pair,
    # so disagreeing sources are preserved rather than collapsed.
    all_cvss_scores: list[dict] = field(default_factory=list)


@dataclass
class EpssEntry:
    cve_id: str
    score: float
    percentile: float
    as_of: str


@dataclass
class CweRecord:
    cwe_id: str
    name: str | None = None
    abstraction: str | None = None
    status: str | None = None
    description: str | None = None
    extended_description: str | None = None
    likelihood_of_exploit: str | None = None
    common_consequences: list[dict] = field(default_factory=list)
    related_weaknesses: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    detection_methods: list[dict] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    version: str | None = None


@dataclass
class CapecRecord:
    capec_id: str
    name: str | None = None
    abstraction: str | None = None
    status: str | None = None
    description: str | None = None
    likelihood_of_attack: str | None = None
    typical_severity: str | None = None
    execution_flow: list[dict] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    skills_required: list[dict] = field(default_factory=list)
    related_weaknesses: list[str] = field(default_factory=list)  # CWE ids
    related_attack_patterns: list[dict] = field(default_factory=list)
    mitigations: list[dict] = field(default_factory=list)
    references: list[dict] = field(default_factory=list)
    version: str | None = None
