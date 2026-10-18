"""Shared parser for the OSV JSON schema (https://ossf.github.io/osv-schema/).

Both the GitHub Advisory Database (``ghsa.py``) and OSV.dev's own per-
ecosystem exports (``osv.py``) publish records in this exact shape — GHSA's
repo literally stores each advisory as an OSV-schema JSON file. One parser,
two source connectors, so the normalization logic (and its tests) exist in
exactly one place.

Never fabricates: every field is read straight from the document or left
``None``/empty; nothing here infers a CVE alias, a fixed version, or a
severity that the source didn't state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.knowledge.connectors import injection_scan

from .. import identity


@dataclass
class OsvAffectedRange:
    ecosystem: str | None
    package: str | None
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None


@dataclass
class OsvRecord:
    record_id: str
    schema_version: str | None = None
    summary: str | None = None
    details: str | None = None
    published: str | None = None
    modified: str | None = None
    withdrawn: str | None = None
    severity_vector: str | None = None
    severity_type: str | None = None
    database_severity: str | None = None
    cwe_ids: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    cve_aliases: list[str] = field(default_factory=list)
    ghsa_alias: str | None = None
    references: list[dict] = field(default_factory=list)
    affected: list[OsvAffectedRange] = field(default_factory=list)


def parse_osv_record(raw: dict, *, findings_counter: list[int] | None = None) -> OsvRecord | None:
    """Parses one OSV-schema JSON document. Returns ``None`` only when the
    document has no usable ``id`` at all — every other field is optional and
    simply left empty when the source doesn't provide it."""
    if not isinstance(raw, dict):
        return None
    record_id = raw.get("id")
    if not record_id or not isinstance(record_id, str):
        return None
    findings = findings_counter if findings_counter is not None else [0]

    def _clean(s):
        if not s or not isinstance(s, str):
            return s if isinstance(s, str) else None
        clean, f = injection_scan.neutralize(s)
        findings[0] += len(f)
        return clean

    aliases = [a for a in (raw.get("aliases") or []) if isinstance(a, str)]
    cve_aliases = sorted({identity.normalize_cve(a) for a in aliases if identity.normalize_cve(a)})
    ghsa_alias = next((identity.normalize_ghsa(a) for a in aliases if identity.normalize_ghsa(a)), None)

    severity_vector = None
    severity_type = None
    for s in raw.get("severity", []) or []:
        if isinstance(s, dict) and s.get("score"):
            severity_type = s.get("type")
            severity_vector = s.get("score")
            break

    db_specific = raw.get("database_specific") or {}
    cwe_ids = sorted({identity.normalize_cwe(c) for c in (db_specific.get("cwe_ids") or []) if identity.normalize_cwe(c)})

    references = [{"type": r.get("type"), "url": r.get("url")}
                  for r in (raw.get("references") or []) if isinstance(r, dict) and r.get("url")][:20]

    affected: list[OsvAffectedRange] = []
    for a in raw.get("affected", []) or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        ecosystem, name = pkg.get("ecosystem"), pkg.get("name")
        ranges = a.get("ranges") or []
        if not ranges:
            affected.append(OsvAffectedRange(ecosystem=ecosystem, package=name))
            continue
        for r in ranges:
            introduced = fixed = last_affected = None
            for event in r.get("events", []) or []:
                if not isinstance(event, dict):
                    continue
                introduced = introduced or event.get("introduced")
                fixed = fixed or event.get("fixed")
                last_affected = last_affected or event.get("last_affected")
            affected.append(OsvAffectedRange(ecosystem=ecosystem, package=name,
                                             introduced=introduced, fixed=fixed,
                                             last_affected=last_affected))
        if len(affected) >= 200:
            break

    return OsvRecord(
        record_id=record_id.upper() if identity.normalize_ghsa(record_id) else record_id,
        schema_version=raw.get("schema_version"),
        summary=_clean(raw.get("summary")),
        details=_clean(raw.get("details")),
        published=raw.get("published"),
        modified=raw.get("modified"),
        withdrawn=raw.get("withdrawn"),
        severity_vector=severity_vector,
        severity_type=severity_type,
        database_severity=db_specific.get("severity"),
        cwe_ids=cwe_ids,
        aliases=aliases,
        cve_aliases=cve_aliases,
        ghsa_alias=ghsa_alias,
        references=references,
        affected=affected[:200],
    )
