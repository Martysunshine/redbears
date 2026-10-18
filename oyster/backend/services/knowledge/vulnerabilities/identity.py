"""CVE / CWE / CAPEC identifier validation and normalization.

Every merge in the vulnerability knowledge system happens through one of these
three identifiers — never fuzzy matching. An identifier that doesn't match the
canonical shape is rejected rather than guessed at.
"""

from __future__ import annotations

import re

_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
_CWE_RE = re.compile(r"^CWE-(\d+)$")
_CAPEC_RE = re.compile(r"^CAPEC-(\d+)$")
_GHSA_RE = re.compile(r"^GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}$")
# OSV ids are ecosystem-specific and not one fixed shape (PYSEC-2024-1,
# GO-2024-1234, RUSTSEC-2024-0001, GHSA-xxxx-xxxx-xxxx when OSV mirrors
# GitHub, DSA-xxxx-x, ...). This validates the general "PREFIX-digits/rest"
# convention widely used across OSV's source databases, not a single spec.
_OSV_RE = re.compile(r"^[A-Z][A-Z0-9]{1,14}-[\w.-]{1,40}$")


def normalize_cve(raw: str | None) -> str | None:
    """Return a canonical 'CVE-YYYY-NNNN...' id, or None if not CVE-shaped."""
    if not raw:
        return None
    tok = str(raw).strip().upper()
    if not tok.startswith("CVE-") and re.match(r"^\d{4}-\d{4,}$", tok):
        tok = f"CVE-{tok}"
    return tok if _CVE_RE.match(tok) else None


def normalize_cwe(raw: str | int | None) -> str | None:
    if raw is None:
        return None
    tok = str(raw).strip().upper()
    if tok.isdigit():
        tok = f"CWE-{tok}"
    tok = tok.replace("CWE-CWE-", "CWE-")
    return tok if _CWE_RE.match(tok) else None


def normalize_capec(raw: str | int | None) -> str | None:
    if raw is None:
        return None
    tok = str(raw).strip().upper()
    if tok.isdigit():
        tok = f"CAPEC-{tok}"
    tok = tok.replace("CAPEC-CAPEC-", "CAPEC-")
    return tok if _CAPEC_RE.match(tok) else None


def normalize_ghsa(raw: str | None) -> str | None:
    if not raw:
        return None
    tok = str(raw).strip().upper()
    return tok if _GHSA_RE.match(tok) else None


def normalize_osv_id(raw: str | None) -> str | None:
    """Looser than the other normalizers by necessity — OSV ids are
    ecosystem-defined, not one canonical shape. Upper-cases and validates the
    general PREFIX-rest convention; the actual existence check is a DB
    lookup, not this regex."""
    if not raw:
        return None
    tok = str(raw).strip().upper()
    return tok if _OSV_RE.match(tok) else None


def is_cve(raw: str) -> bool:
    return normalize_cve(raw) is not None


def is_cwe(raw: str) -> bool:
    return normalize_cwe(raw) is not None


def is_capec(raw: str) -> bool:
    return normalize_capec(raw) is not None


def is_ghsa(raw: str) -> bool:
    return normalize_ghsa(raw) is not None


# Query-time detection: does a free-text query contain an identifier-shaped
# token? Used to short-circuit to exact lookup before any semantic search.
_QUERY_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_QUERY_CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)
_QUERY_CAPEC_RE = re.compile(r"\bCAPEC-\d+\b", re.I)
_QUERY_GHSA_RE = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.I)
# General "PREFIX(-PREFIX)*-YYYY-rest" shape shared by every OSV source
# database we ingest (PYSEC-2024-1, GO-2024-1234, RUSTSEC-2024-0001,
# DRUPAL-CONTRIB-2022-014, ...) rather than a fixed prefix whitelist — OSV
# aggregates dozens of upstream id schemes and a closed list kept missing
# real ones. The mandatory 4-digit year segment is what keeps this from
# false-positiving on ordinary hyphenated text (e.g. "aws-sdk-go-v2" does
# NOT contain a bare 4-digit run, so "go-v2" is never mistaken for an id).
# CVE/CWE/CAPEC/GHSA have their own dedicated, stricter regexes — excluded
# here so a real CVE id is never double-classified as a generic OSV one.
_QUERY_OSV_RE = re.compile(
    r"\b(?!GHSA-|CVE-|CWE-|CAPEC-)[A-Z]+(?:-[A-Z]+)*-\d{4}-[\w.-]{1,20}\b", re.I)


def find_identifiers(text: str) -> dict[str, list[str]]:
    """Extract every CVE/CWE/CAPEC/GHSA/OSV-shaped token from free text,
    normalized."""
    if not text:
        return {"cve": [], "cwe": [], "capec": [], "ghsa": [], "osv": []}
    cves = sorted({normalize_cve(m.group(0)) for m in _QUERY_CVE_RE.finditer(text)})
    cwes = sorted({normalize_cwe(m.group(0)) for m in _QUERY_CWE_RE.finditer(text)})
    capecs = sorted({normalize_capec(m.group(0)) for m in _QUERY_CAPEC_RE.finditer(text)})
    ghsas = sorted({normalize_ghsa(m.group(0)) for m in _QUERY_GHSA_RE.finditer(text)})
    osvs = sorted({normalize_osv_id(m.group(0)) for m in _QUERY_OSV_RE.finditer(text)
                  if not _QUERY_GHSA_RE.match(m.group(0))} - set(ghsas))
    return {"cve": cves, "cwe": cwes, "capec": capecs, "ghsa": ghsas, "osv": osvs}
