"""Deterministic licence policy for source ingestion.

Public accessibility is **not** permission to copy. Each licence maps to a
disposition that decides whether full text may be stored locally, only metadata
may be kept, or the source is excluded entirely. Installation is blocked when the
licence or required attribution is missing, or when the disposition forbids
local storage.

The mapping is intentionally conservative: an unknown or proprietary licence is
``EXCLUDED`` (never silently stored).
"""

from __future__ import annotations

import re

from .base import ConnectorProfile, LicenceDisposition

# Normalized-licence-token -> default disposition. A profile may still declare a
# stricter disposition; we take the more restrictive of the two.
_LICENCE_POLICY: dict[str, str] = {
    # Permissive / share-alike: local storage OK, attribution required.
    "mit": LicenceDisposition.STORE_LOCAL,
    "apache-2.0": LicenceDisposition.STORE_LOCAL,
    "apache 2.0": LicenceDisposition.STORE_LOCAL,
    "bsd-2-clause": LicenceDisposition.STORE_LOCAL,
    "bsd-3-clause": LicenceDisposition.STORE_LOCAL,
    "cc-by-4.0": LicenceDisposition.STORE_LOCAL,
    "cc by 4.0": LicenceDisposition.STORE_LOCAL,
    "cc-by-sa-4.0": LicenceDisposition.STORE_LOCAL,
    "cc by-sa 4.0": LicenceDisposition.STORE_LOCAL,
    "cc by-sa 4.0 (owasp wstg)": LicenceDisposition.STORE_LOCAL,
    "gpl-2.0": LicenceDisposition.STORE_LOCAL,
    "gpl-3.0": LicenceDisposition.STORE_LOCAL,
    "agpl-3.0": LicenceDisposition.STORE_LOCAL,
    "mpl-2.0": LicenceDisposition.STORE_LOCAL,
    "unlicense": LicenceDisposition.STORE_LOCAL,
    "cc0-1.0": LicenceDisposition.STORE_LOCAL,
    "public-domain": LicenceDisposition.STORE_LOCAL,
    # MITRE ATT&CK / CAPEC / CWE terms — redistribution permitted with attribution.
    "mitre-attack-terms": LicenceDisposition.STORE_LOCAL,
    "apache-2.0 (attack stix)": LicenceDisposition.STORE_LOCAL,
    "mitre-cwe-terms": LicenceDisposition.STORE_LOCAL,
    "mitre-capec-terms": LicenceDisposition.STORE_LOCAL,
    # US Government works — CISA KEV catalog and the NVD CVE API are both
    # federal-government-produced data, usable with attribution.
    "cisa-kev-public": LicenceDisposition.STORE_LOCAL,
    "nist-nvd-public": LicenceDisposition.STORE_LOCAL,
    # FIRST.org publishes EPSS for open reuse with attribution.
    "epss-first-terms": LicenceDisposition.STORE_LOCAL,
    # Detection Rule License (Sigma) — use/modify/redistribute with attribution.
    "drl-1.1": LicenceDisposition.STORE_LOCAL,
    "drl-1.0": LicenceDisposition.STORE_LOCAL,
    "detection-rule-license": LicenceDisposition.STORE_LOCAL,
    "detection-rule-license-1.1": LicenceDisposition.STORE_LOCAL,
    # Community Specification License 1.0 (SLSA, SPDX spec) — explicitly grants
    # "reproduce, prepare derivative works of... and distribute" with attribution.
    "community-specification-1.0": LicenceDisposition.STORE_LOCAL,
    "community-spec-1.0": LicenceDisposition.STORE_LOCAL,
    "cc-by-3.0": LicenceDisposition.STORE_LOCAL,
    "elastic-license-2.0": LicenceDisposition.MANUAL_CONFIRM,
    # IETF Trust Legal Provisions (TLP) §3.c grants a perpetual, non-exclusive
    # licence to copy/publish/display/distribute RFC text, with attribution.
    "ietf-trust-tlp": LicenceDisposition.STORE_LOCAL,
    # Non-commercial: needs a human decision before storing.
    "cc-by-nc-4.0": LicenceDisposition.MANUAL_CONFIRM,
    "cc by-nc 4.0": LicenceDisposition.MANUAL_CONFIRM,
    "cc-by-nc-sa-4.0": LicenceDisposition.MANUAL_CONFIRM,
    # Datasets — usable for evaluation only, never stored as retrievable knowledge.
    "evaluation-only": LicenceDisposition.EVALUATION_ONLY,
    # Licence unclear / needs a human decision before storing.
    "manual-confirm": LicenceDisposition.MANUAL_CONFIRM,
    "unverified": LicenceDisposition.MANUAL_CONFIRM,
    "unknown": LicenceDisposition.MANUAL_CONFIRM,
    # Explicitly reference/link only.
    "proprietary": LicenceDisposition.EXCLUDED,
    "all-rights-reserved": LicenceDisposition.EXCLUDED,
}

# Ordering from most to least permissive (for taking the stricter of two).
_RANK = {
    LicenceDisposition.STORE_LOCAL: 0,
    LicenceDisposition.METADATA_ONLY: 1,
    LicenceDisposition.LINK_ONLY: 2,
    LicenceDisposition.MANUAL_CONFIRM: 3,
    LicenceDisposition.EVALUATION_ONLY: 4,
    LicenceDisposition.EXCLUDED: 5,
}


def normalize_licence(licence: str | None) -> str | None:
    if not licence:
        return None
    tok = licence.strip().lower()
    # exact hit first
    if tok in _LICENCE_POLICY:
        return tok
    # match a known token as a prefix/substring (e.g. "cc-by-sa-4.0 (owasp ...)")
    for known in _LICENCE_POLICY:
        if known in tok:
            return known
    # canonicalize common spellings
    canon = re.sub(r"[\s_]+", "-", tok)
    canon = canon.replace("creative-commons-", "cc-")
    if canon in _LICENCE_POLICY:
        return canon
    return None


def _stricter(a: str, b: str) -> str:
    return a if _RANK.get(a, 5) >= _RANK.get(b, 5) else b


def evaluate(profile: ConnectorProfile) -> dict:
    """Decide whether ``profile`` may be materialized/stored locally.

    Returns ``{allowed, disposition, reasons, requires_attribution}``.
    """
    reasons: list[str] = []
    if not profile.licence:
        return {"allowed": False, "disposition": LicenceDisposition.EXCLUDED,
                "reasons": ["licence missing — installation blocked"],
                "requires_attribution": True}
    if profile.requires_attribution and not profile.attribution:
        reasons.append("attribution required but missing")

    token = normalize_licence(profile.licence)
    if token is None:
        return {"allowed": False, "disposition": LicenceDisposition.EXCLUDED,
                "reasons": reasons + [f"unrecognized licence '{profile.licence}' — treated as excluded"],
                "requires_attribution": profile.requires_attribution}

    policy_disp = _LICENCE_POLICY[token]
    # honor a stricter declared disposition on the profile
    disp = _stricter(policy_disp, profile.licence_disposition or policy_disp)

    allowed = disp == LicenceDisposition.STORE_LOCAL and not reasons
    if disp != LicenceDisposition.STORE_LOCAL:
        reasons.append(f"licence '{profile.licence}' disposition is '{disp}', not store_local")
    return {"allowed": allowed, "disposition": disp, "reasons": reasons,
            "requires_attribution": profile.requires_attribution,
            "licence_token": token}
