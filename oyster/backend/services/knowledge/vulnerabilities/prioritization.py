"""Deterministic, explainable defensive-patch prioritization.

This is NOT a universal risk score — it is one specific, transparent way to
rank CVEs for patching triage using only real installed data (CISA KEV
status, EPSS, the preferred CVSS score with its source, fix availability,
advisory recency, and optional caller-supplied asset context). Every factor
that contributed is returned alongside the score, with its own weight and raw
value, so a caller can see exactly why one CVE outranked another.

The hard rule this module exists to enforce: missing data is never silently
treated as zero risk. A factor whose underlying data isn't installed is
excluded from the weighted average (not defaulted to 0) and named in
``missing_factors`` / reflected in a reduced ``confidence``. A CVE with almost
no installed data gets a low ``confidence``, not a falsely-precise low score.
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import retrieval

# (factor_name, weight) — weights are relative, renormalized over whichever
# factors actually have real data for a given CVE (see _renormalize).
_WEIGHTS = {
    "kev": 0.30,
    "epss": 0.25,
    "cvss": 0.20,
    "fix_available": 0.10,
    "advisory_recency": 0.05,
    "asset_criticality": 0.05,
    "asset_exposure": 0.05,
}

_BANDS = (  # (floor, label) — highest matching floor wins
    (0.75, "critical"),
    (0.55, "high"),
    (0.30, "medium"),
    (0.0, "low"),
)


def _band(score: float) -> str:
    for floor, label in _BANDS:
        if score >= floor:
            return label
    return "low"


def _recency_factor(rec: dict) -> float | None:
    """1.0 for an advisory published today, decaying to ~0 by one year old.
    None (excluded, not zero) when no vendor advisory has a usable date."""
    dates = []
    for adv in rec.get("vendor_advisories") or []:
        d = adv.get("current_release_date")
        if d:
            dates.append(d)
    if not dates:
        return None
    try:
        newest = max(datetime.fromisoformat(d.replace("Z", "+00:00")) for d in dates)
    except ValueError:
        return None
    if newest.tzinfo is None:
        newest = newest.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (datetime.now(timezone.utc) - newest).total_seconds() / 86400.0)
    return max(0.0, 1.0 - age_days / 365.0)


def _fix_available_factor(rec: dict) -> float | None:
    """1.0 if any installed source names a fixed version, 0.0 if every
    installed advisory explicitly has no fix, None if no source has spoken
    to fix status at all (genuinely unknown, not 'no fix')."""
    advisories = rec.get("vendor_advisories") or []
    if not advisories:
        return None
    any_fixed = any(a.get("fixed_version") for a in advisories)
    return 1.0 if any_fixed else 0.0


def score_cve(cve_id: str, *, asset_criticality: float | None = None,
             asset_exposure: float | None = None) -> dict:
    """``asset_criticality``/``asset_exposure`` are optional caller-supplied
    0..1 inputs (e.g. from a CMDB) — omitted entirely from the score, not
    defaulted to 0, when the caller doesn't provide them."""
    rec = retrieval.get_cve(cve_id)
    if rec is None:
        return {"cve_id": cve_id, "found": False}

    raw: dict[str, float | None] = {}
    kev = rec.get("kev") or {}
    raw["kev"] = 1.0 if kev.get("listed") else 0.0  # KEV absence is real data, never missing

    epss = rec.get("epss")
    raw["epss"] = float(epss["score"]) if epss and epss.get("score") is not None else None

    cvss = rec.get("cvss") or {}
    preferred = None
    for version in ("v4", "v3", "v2"):
        block = cvss.get(version)
        if block and block.get("score") is not None:
            preferred = block
            break
    raw["cvss"] = (float(preferred["score"]) / 10.0) if preferred else None
    cvss_source = rec.get("cvss_source") or (cvss.get("preferred_source"))

    raw["fix_available"] = _fix_available_factor(rec)
    raw["advisory_recency"] = _recency_factor(rec)
    raw["asset_criticality"] = float(asset_criticality) if asset_criticality is not None else None
    raw["asset_exposure"] = float(asset_exposure) if asset_exposure is not None else None

    present = {k: v for k, v in raw.items() if v is not None}
    missing = sorted(k for k, v in raw.items() if v is None)
    weight_total = sum(_WEIGHTS[k] for k in present) or 1.0
    score = sum(_WEIGHTS[k] * v for k, v in present.items()) / weight_total

    # confidence: how much of the *core* signal (kev/epss/cvss — the factors
    # that exist for essentially every enriched CVE) is actually present.
    core = ("kev", "epss", "cvss")
    confidence = sum(1 for k in core if raw[k] is not None) / len(core)

    explanation = []
    if raw["kev"] == 1.0:
        explanation.append(f"Listed in CISA KEV (added {kev.get('date_added')}) — actively exploited.")
    if raw["epss"] is not None:
        explanation.append(f"EPSS exploitation probability {raw['epss']:.1%}.")
    if raw["cvss"] is not None:
        explanation.append(f"CVSS {preferred['score']} ({preferred.get('severity')}) from {cvss_source}.")
    if raw["fix_available"] == 1.0:
        explanation.append("A fix/patched version is available from an installed advisory source.")
    elif raw["fix_available"] == 0.0:
        explanation.append("No fix is listed as available in any installed advisory source yet.")
    if missing:
        explanation.append(f"No installed data for: {', '.join(missing)} — excluded from the score, "
                           f"not counted as zero risk.")

    return {
        "cve_id": rec["cve_id"], "found": True,
        "score": round(score, 4), "band": _band(score),
        "confidence": round(confidence, 2),
        "factors": {
            k: {"weight": _WEIGHTS[k], "value": raw[k]}
            for k in _WEIGHTS
        },
        "missing_factors": missing,
        "explanation": explanation,
        "note": "A defensive patch-triage heuristic over installed KEV/EPSS/CVSS/advisory data — "
               "not a universal risk score.",
        "citation": rec.get("citation"),
    }


def rank_cves(cve_ids: list[str], *, asset_criticality: dict[str, float] | None = None,
             asset_exposure: dict[str, float] | None = None) -> list[dict]:
    """Scores each CVE independently and returns them sorted highest-score
    first. ``asset_criticality``/``asset_exposure`` are optional per-CVE maps
    (keyed by the same cve_id strings the caller passed in)."""
    ac = asset_criticality or {}
    ae = asset_exposure or {}
    results = [
        score_cve(c, asset_criticality=ac.get(c), asset_exposure=ae.get(c))
        for c in cve_ids
    ]
    return sorted(results, key=lambda r: (r.get("found", False), r.get("score", -1)), reverse=True)
