"""Deterministic package/version vulnerability evaluation against installed
GHSA + OSV affected-range data.

Version comparison only trusts dotted-numeric-with-optional-prerelease
version strings (the common case across npm/PyPI/Go/RubyGems/crates.io/etc.
for released versions). A version string this module cannot confidently
parse — or a range whose own bounds it cannot parse — is never guessed at:
the affected-range check is reported as ``"indeterminate"``, never silently
folded into "safe" or "vulnerable". Likewise a package with no installed
GHSA/OSV data at all is reported as ``not_found`` — never as "not vulnerable"
— because absence of installed data is not evidence of absence of a real
vulnerability.
"""

from __future__ import annotations

import re

from . import osv_store

_VERSION_RE = re.compile(r"^\d+(\.\d+)*(-[0-9A-Za-z.\-]+)?$")


def _parse(v: str) -> tuple[tuple[int, ...], str] | None:
    v = (v or "").strip()
    if not v or not _VERSION_RE.match(v):
        return None
    core, _, pre = v.partition("-")
    try:
        nums = tuple(int(p) for p in core.split("."))
    except ValueError:
        return None
    return nums, pre


def compare_versions(a: str, b: str) -> int | None:
    """-1/0/1 if both parse; ``None`` if either doesn't (never guessed)."""
    pa, pb = _parse(a), _parse(b)
    if pa is None or pb is None:
        return None
    (na, prea), (nb, preb) = pa, pb
    length = max(len(na), len(nb))
    na = na + (0,) * (length - len(na))
    nb = nb + (0,) * (length - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    # Equal numeric core: no prerelease suffix outranks any suffix (1.0.0 > 1.0.0-rc1).
    if prea == preb:
        return 0
    if not prea:
        return 1
    if not preb:
        return -1
    return -1 if prea < preb else 1


def _range_verdict(version: str, introduced: str | None, fixed: str | None,
                   last_affected: str | None) -> str:
    """Returns ``"affected"``, ``"not_affected"`` or ``"indeterminate"`` for
    one single affected-range row. OSV convention: a missing/empty
    ``introduced`` means affected from the very first release."""
    lo_cmp = 0 if not introduced else compare_versions(version, introduced)
    if lo_cmp is None:
        return "indeterminate"
    if lo_cmp < 0:
        return "not_affected"  # version predates the range's start

    if fixed:
        hi_cmp = compare_versions(version, fixed)
        if hi_cmp is None:
            return "indeterminate"
        return "affected" if hi_cmp < 0 else "not_affected"

    if last_affected:
        hi_cmp = compare_versions(version, last_affected)
        if hi_cmp is None:
            return "indeterminate"
        return "affected" if hi_cmp <= 0 else "not_affected"

    # No fixed / last_affected bound at all: range is open-ended, still affected.
    return "affected"


def check_version(ecosystem: str, package: str, version: str) -> dict:
    ghsa_hits = osv_store.search_ghsa_by_package(ecosystem, package)
    osv_hits = osv_store.search_osv_by_package(ecosystem, package)
    if not ghsa_hits and not osv_hits:
        return {"ecosystem": ecosystem, "package": package, "version": version,
               "status": "not_found",
               "note": "No installed GHSA/OSV advisory names this ecosystem/package — "
                       "this is not evidence the version is safe, only that nothing "
                       "about it is installed locally."}

    version_parses = _parse(version) is not None
    matches: list[dict] = []
    for kind, rec_id_field, hits in (("ghsa", "ghsa_id", ghsa_hits), ("osv", "osv_id", osv_hits)):
        for rec in hits:
            for a in rec.get("affected", []):
                if a.get("ecosystem") != ecosystem or a.get("package") != package:
                    continue
                verdict = (_range_verdict(version, a.get("introduced"), a.get("fixed"),
                                          a.get("last_affected")) if version_parses else "indeterminate")
                matches.append({"advisory_id": rec[rec_id_field], "kind": kind, "verdict": verdict,
                                "introduced": a.get("introduced"), "fixed": a.get("fixed"),
                                "last_affected": a.get("last_affected"),
                                "withdrawn": rec.get("is_withdrawn", False)})

    active = [m for m in matches if not m["withdrawn"]]
    if not version_parses:
        status = "indeterminate"
        note = (f"'{version}' is not a plain dotted-numeric version this evaluator can compare — "
               f"returning every advisory that names this package instead of guessing.")
    elif any(m["verdict"] == "affected" for m in active):
        status = "vulnerable"
        note = None
    elif any(m["verdict"] == "indeterminate" for m in active):
        status = "indeterminate"
        note = "At least one advisory's version range could not be confidently compared."
    else:
        status = "not_affected_by_installed_advisories"
        note = ("No installed advisory's affected range covers this version — this reflects "
               "only the advisories installed locally, not a guarantee of no vulnerability.")

    fixed_versions = sorted({m["fixed"] for m in active
                             if m["verdict"] == "affected" and m.get("fixed")})
    return {"ecosystem": ecosystem, "package": package, "version": version, "status": status,
           "note": note, "fixed_versions": fixed_versions, "matches": matches}
