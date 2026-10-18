"""Deterministic pre-LLM security-question router.

Classifies a free-text security question into a route BEFORE any retrieval or
LLM call runs, so exact-identifier questions (CVE/CWE/CAPEC/ATT&CK/D3FEND) go
straight to a real DB lookup instead of risking a semantic-search/LLM
substitute, and topic questions are scoped to the packs/tables that actually
answer them. Every branch below is a plain regex/keyword match — no ML, no
LLM call, fully deterministic and unit-testable. Anything that doesn't match a
more specific route falls through to the existing hybrid retrieval unscoped.

Route priority (first match wins): an exact identifier always wins over topic
keywords, since a user asking "how do I detect CVE-2021-44228" still wants the
real CVE record surfaced, not just a detection-pack search.
"""

from __future__ import annotations

import re

from . import retrieval
from .controls import store as controls_store
from .graph import query as graph_query
from .graph import store as graph_store
from .vulnerabilities import identity as vuln_identity
from .vulnerabilities import prioritization
from .vulnerabilities import retrieval as vuln_retrieval
from .vulnerabilities import version_check

ROUTE_EXACT_LOOKUP = "exact_lookup"
ROUTE_VULN_FILTER = "vulnerability_filter"
ROUTE_PACKAGE = "package_vulnerabilities"
ROUTE_VERSION_CHECK = "version_check"
ROUTE_PRIORITIZATION = "prioritization"
ROUTE_DETECTION = "detection"
ROUTE_MITIGATION = "mitigation"
ROUTE_IR = "incident_response"
ROUTE_CLOUD = "cloud"
ROUTE_COMPLIANCE = "compliance"
ROUTE_GENERAL = "general"

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_D3F_RE = re.compile(r"\bd3f:([A-Za-z][A-Za-z0-9-]*)\b", re.IGNORECASE)

# The 20 real NIST SP 800-53 Rev. 5 control-family prefixes — used to bound
# the control-id regex so it doesn't false-positive on arbitrary "XX-1"
# tokens in unrelated text.
_SP80053_FAMILIES = ("AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP",
                     "PE", "PL", "PM", "PS", "PT", "RA", "SA", "SC", "SI", "SR")
# Trailing "(?!\w)" rather than "\b": a "\b" right after the enhancement's
# closing ")" (e.g. "AC-2(1)") sees non-word on both sides of that boundary
# and fails to anchor, silently backtracking the whole optional "(N)" group
# away. "(?!\w)" has no such blind spot.
_NIST_CONTROL_RE = re.compile(
    r"\b(?:(?:" + "|".join(_SP80053_FAMILIES) + r")-\d{1,2}(?:\(\d{1,2}\))?"
    r"|(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(?:-\d{2})?"
    r"|(?:PO|PS|PW|RV)\.\d{1,2}(?:\.\d{1,2})?)(?!\w)",
    re.IGNORECASE,
)

# Package/ecosystem vulnerability questions ("what CVEs affect the npm
# package lodash", "vulnerabilities in PyPI package requests"): triggers only
# when BOTH an ecosystem keyword AND a name-introducing phrase are present —
# a bare ecosystem mention ("npm best practices") never forces this route.
_PACKAGE_ECOSYSTEM_KEYWORDS = {
    "npm": "npm", "pypi": "PyPI", "pip package": "PyPI", "python package": "PyPI",
    "maven": "Maven", "go module": "Go", "golang package": "Go", "cargo": "crates.io",
    "crates.io": "crates.io", "rust crate": "crates.io", "nuget": "NuGet",
    "rubygems": "RubyGems", "ruby gem": "RubyGems", "composer": "Packagist",
    "packagist": "Packagist", "php package": "Packagist", "github action": "GitHub Actions",
}
# Two separate patterns (not one alternation) so both get an independent
# chance to match even when one already "used up" the relevant text — e.g.
# in "npm package left-pad", the "X package" pattern (_B) matches "npm
# package" first if searched jointly, which would hide the correct "package
# left-pad" match (_A) that starts partway through that same span.
_PACKAGE_NAME_RE_A = re.compile(
    r"\b(?:package|library|module|crate|gem|action)\s+[\"'`]?([A-Za-z0-9@][\w.\-@/]{0,80})[\"'`]?",
    re.IGNORECASE,
)
_PACKAGE_NAME_RE_B = re.compile(r"\b([A-Za-z0-9@][\w.\-@/]{0,80})\s+(?:package|library)\b", re.IGNORECASE)

# "is <package> version <X> vulnerable" / "does version <X> of <package> fix
# this" — a version-shaped token immediately after the literal word
# "version", so this never fires on an ecosystem+package query that doesn't
# actually name a version.
_VERSION_TOKEN_RE = re.compile(r"\bversion\s+[\"'`]?[vV]?(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.\-]+)?)[\"'`]?")

# "what should I patch first" / "prioritize these CVEs" / "patch priority" —
# deliberately narrow phrases so a plain "how do I patch X" mitigation
# question doesn't get pulled into this route.
_PRIORITIZATION_KEYWORDS = (
    "patch first", "patch priority", "prioritize", "prioritise", "what should i patch",
    "which cve should i fix first", "triage these", "rank these vulnerabilities",
)

# Deliberately literal keyword lists, not NLP — a query either contains one of
# these substrings or it doesn't. Checked in this fixed priority order.
_VULN_FILTER_KEYWORDS = (
    "kev", "known exploited", "exploited in the wild", "epss", "cvss",
    "critical severity", "high severity", "vulnerabilities in",
    "vulnerable versions", "list vulnerabilities", "recent vulnerabilities",
    "cves affecting", "cves for", "cve list", "vendor advisor", "cisa advisor",
)
_DETECTION_KEYWORDS = (
    "detect", "detection", "sigma rule", "yara rule", "siem", "log source",
    "indicators of compromise", "hunt for", "threat hunting", "ocsf",
    "splunk", "falco rule", "falco", "zeek script", "zeek", "suricata rule", "suricata",
    "atomic red team",
)
_MITIGATION_KEYWORDS = (
    "mitigate", "mitigation", "how do i prevent", "how to prevent", "harden",
    "hardening", "remediate", "remediation", "fix for", "countermeasure",
    "defend against", "asvs",
)
# Deliberately excluded from the list above: generic phrases like "best
# practice" that appear constantly in cloud/platform questions too ("AWS IAM
# best practices") and would always out-rank the more specific cloud route.
_COMPLIANCE_KEYWORDS = (
    "nist control", "nist controls", "csf function", "csf category",
    "csf subcategory", "800-53", "sp 800-53", "ssdf practice",
    "secure software development framework", "compliance control",
    "control mapping", "zero trust", "supply chain risk management",
    "c-scrm", "cybersecurity framework", "privacy framework",
    "slsa", "sbom", "spdx", "cyclonedx", "sigstore", "cosign", "code signing",
    "openssf", "scorecard", "oauth", "openid connect", "webauthn", "fido2",
    "tls 1.3", "dnssec", "spf record", "dkim", "dmarc", "email authentication",
    "phishing-resistant mfa", "privileged access management", "pam",
    "security baseline", "csf", "800-161", "sp 800-161", "csaf",
)
_IR_KEYWORDS = (
    "incident response", "ir plan", "breach", "containment", "eradication",
    "forensic", "chain of custody", "playbook", "post-incident",
    "ransomware incident", "preserve evidence", "detection and analysis phase",
    "sp 800-61", "800-61", "coordinated disclosure", "active incident",
)
_CLOUD_KEYWORDS = (
    "aws", "azure", "gcp", "google cloud", "kubernetes", "k8s", "docker",
    "container", "iam policy", "s3 bucket", "cloud security",
)
_PLATFORM_KEYWORD_MAP = {
    "aws": "cloud", "azure": "cloud", "gcp": "cloud", "google cloud": "cloud",
    "kubernetes": "kubernetes", "k8s": "kubernetes", "docker": "docker",
    "container": "docker", "iam policy": "cloud", "s3 bucket": "cloud",
    "cloud security": "cloud",
}

DETECTION_PACKS = ("sigma-src", "yara-reversinglabs-src", "mitre-attack-src",
                   "mitre-attack-mobile-src", "mitre-attack-ics-src", "atomic-red-team-src",
                   "azure-sentinel-detections-src", "osquery-docs-src", "ocsf-docs-src",
                   "splunk-security-content-src", "falco-rules-src", "falco-docs-src",
                   "zeek-docs-src", "suricata-userguide-src")
MITIGATION_PACKS = ("mitre-d3fend-src", "owasp-cheatsheets-src", "owasp-asvs-src",
                    "kubernetes-security-docs-src", "docker-security-docs-src",
                    "owasp-cicd-top10-src", "owasp-k8s-top10-src")
IR_PACKS = ("incident-response-dfir", "nist-sp800-61-src")
COMPLIANCE_PACKS = ("nist-sp800-207-src", "nist-sp800-161-src",
                    "slsa-spec-src", "spdx-spec-src", "openssf-scorecard-docs-src",
                    "openssf-best-practices-src", "sigstore-cosign-docs-src",
                    "rfc9700-oauth-security-src", "rfc8446-tls13-src", "rfc7208-spf-src",
                    "rfc6376-dkim-src", "rfc7489-dmarc-src", "rfc8252-oauth-native-src")


def extract_identifiers(text: str) -> dict[str, list[str]]:
    """Every CVE/CWE/CAPEC/ATT&CK/D3FEND/NIST-control-shaped token in free
    text, normalized."""
    ids = vuln_identity.find_identifiers(text)
    ids["attack"] = sorted({m.group(0).upper() for m in _TID_RE.finditer(text or "")})
    ids["d3fend"] = sorted({m.group(1) for m in _D3F_RE.finditer(text or "")})
    ids["nist_control"] = sorted({m.group(0).upper() for m in _NIST_CONTROL_RE.finditer(text or "")})
    return ids


def _keyword_hits(text_lower: str, keywords: tuple[str, ...]) -> list[str]:
    return [k for k in keywords if k in text_lower]


def _detect_package_query(text: str, text_lower: str) -> tuple[str, str] | None:
    """Returns ``(ecosystem, package_name)`` only when both an ecosystem
    keyword and a name-introducing phrase are present — never guesses a
    package name out of a query that doesn't clearly name one."""
    ecosystem = next((v for k, v in _PACKAGE_ECOSYSTEM_KEYWORDS.items() if k in text_lower), None)
    if ecosystem is None:
        return None
    # "package X" (_A) is checked before "X package" (_B) — _B risks
    # matching the ecosystem word itself (e.g. "npm package" in "npm package
    # left-pad"), which is filtered out below and never returned as a name.
    for pattern in (_PACKAGE_NAME_RE_A, _PACKAGE_NAME_RE_B):
        for m in pattern.finditer(text or ""):
            name = m.group(1)
            if name and name.lower() not in _PACKAGE_ECOSYSTEM_KEYWORDS:
                return ecosystem, name
    return None


def _detect_version_query(text: str, text_lower: str) -> tuple[str, str, str] | None:
    """Returns ``(ecosystem, package_name, version)`` only when an ecosystem
    keyword, a name-introducing phrase, AND a version-shaped token following
    the literal word "version" are all present."""
    pkg = _detect_package_query(text, text_lower)
    if pkg is None:
        return None
    m = _VERSION_TOKEN_RE.search(text or "")
    if not m:
        return None
    ecosystem, package = pkg
    return ecosystem, package, m.group(1)


def classify(text: str) -> dict:
    """Return ``{route, identifiers, matched_keywords, platforms}``."""
    text_lower = (text or "").lower()
    ids = extract_identifiers(text)
    if any(ids.values()):
        # An identifier plus explicit prioritization phrasing ("what should I
        # patch first: CVE-A, CVE-B") still wants the ranking, not a single
        # exact-lookup record — checked here since exact_lookup would
        # otherwise always win once any identifier is present.
        if ids.get("cve") and _keyword_hits(text_lower, _PRIORITIZATION_KEYWORDS):
            return {"route": ROUTE_PRIORITIZATION, "identifiers": ids,
                    "matched_keywords": _keyword_hits(text_lower, _PRIORITIZATION_KEYWORDS),
                    "platforms": []}
        return {"route": ROUTE_EXACT_LOOKUP, "identifiers": ids,
                "matched_keywords": [], "platforms": []}

    prio_hits = _keyword_hits(text_lower, _PRIORITIZATION_KEYWORDS)
    if prio_hits:
        return {"route": ROUTE_PRIORITIZATION, "identifiers": ids,
                "matched_keywords": prio_hits, "platforms": []}

    # Checked before the plain package route: a query naming both a package
    # AND a version is more specific and answerable with a real yes/no/
    # indeterminate verdict, not just a list of advisories.
    vq = _detect_version_query(text, text_lower)
    if vq:
        ecosystem, package, version = vq
        return {"route": ROUTE_VERSION_CHECK, "identifiers": ids, "matched_keywords": [],
                "platforms": [], "version_query": {"ecosystem": ecosystem, "package": package,
                                                    "version": version}}

    pkg = _detect_package_query(text, text_lower)
    if pkg:
        ecosystem, package = pkg
        return {"route": ROUTE_PACKAGE, "identifiers": ids, "matched_keywords": [],
                "platforms": [], "package_query": {"ecosystem": ecosystem, "package": package}}

    vuln_hits = _keyword_hits(text_lower, _VULN_FILTER_KEYWORDS)
    if vuln_hits:
        return {"route": ROUTE_VULN_FILTER, "identifiers": ids,
                "matched_keywords": vuln_hits, "platforms": []}

    # Checked before detection: NIST SP 800-61's own phase names ("detection
    # and analysis phase") and other IR-specific phrases contain the bare
    # word "detection", which would otherwise always win via the more
    # general detection-engineering route below.
    ir_hits = _keyword_hits(text_lower, _IR_KEYWORDS)
    if ir_hits:
        return {"route": ROUTE_IR, "identifiers": ids,
                "matched_keywords": ir_hits, "platforms": []}

    det_hits = _keyword_hits(text_lower, _DETECTION_KEYWORDS)
    if det_hits:
        return {"route": ROUTE_DETECTION, "identifiers": ids,
                "matched_keywords": det_hits, "platforms": []}

    mit_hits = _keyword_hits(text_lower, _MITIGATION_KEYWORDS)
    if mit_hits:
        return {"route": ROUTE_MITIGATION, "identifiers": ids,
                "matched_keywords": mit_hits, "platforms": []}

    # Checked before cloud: a handful of compliance/supply-chain terms
    # ("cosign", "sigstore", "slsa"...) can co-occur with a generic cloud word
    # like "container" ("sign container images with cosign") — the more
    # specific standards/supply-chain pack set is the better answer there.
    compliance_hits = _keyword_hits(text_lower, _COMPLIANCE_KEYWORDS)
    if compliance_hits:
        return {"route": ROUTE_COMPLIANCE, "identifiers": ids,
                "matched_keywords": compliance_hits, "platforms": []}

    cloud_hits = _keyword_hits(text_lower, _CLOUD_KEYWORDS)
    if cloud_hits:
        platforms = sorted({_PLATFORM_KEYWORD_MAP[k] for k in cloud_hits
                            if k in _PLATFORM_KEYWORD_MAP})
        return {"route": ROUTE_CLOUD, "identifiers": ids,
                "matched_keywords": cloud_hits, "platforms": platforms}

    return {"route": ROUTE_GENERAL, "identifiers": ids,
            "matched_keywords": [], "platforms": []}


# ---------------------------------------------------------------------------
# Exact-identifier resolution (real DB lookups only — never invented)
# ---------------------------------------------------------------------------

def _d3fend_label_for(local_name: str) -> str | None:
    """Map a ``d3f:LocalName`` ontology-style token back to its human label by
    scanning real ``countermeasure`` graph nodes — no guessing/fuzzy matching."""
    target = re.sub(r"[^a-z0-9]", "", local_name.lower())
    with graph_store.conn() as con:
        rows = con.execute(
            "SELECT node_id, label FROM kg_nodes WHERE node_type='countermeasure'"
        ).fetchall()
    for row in rows:
        label = row["label"] or ""
        if re.sub(r"[^a-z0-9]", "", label.lower()) == target:
            return label
    return None


def resolve_exact(ids: dict[str, list[str]]) -> dict:
    """Resolve every extracted identifier against its real store. Absent
    identifiers are reported as ``found: False`` — never silently dropped and
    never fabricated as if they existed."""
    out: dict[str, list[dict]] = {"cve": [], "cwe": [], "capec": [], "attack": [], "d3fend": [],
                                  "nist_control": [], "ghsa": [], "osv": []}

    for cve_id in ids.get("cve", []):
        rec = vuln_retrieval.get_cve(cve_id)
        out["cve"].append(rec if rec else {"cve_id": cve_id, "found": False})

    for cwe_id in ids.get("cwe", []):
        rec = vuln_retrieval.get_cwe(cwe_id)
        out["cwe"].append(rec if rec else {"cwe_id": cwe_id, "found": False})

    for capec_id in ids.get("capec", []):
        rec = vuln_retrieval.get_capec(capec_id)
        out["capec"].append(rec if rec else {"capec_id": capec_id, "found": False})

    for ghsa_id in ids.get("ghsa", []):
        rec = vuln_retrieval.get_ghsa(ghsa_id)
        out["ghsa"].append(rec if rec else {"ghsa_id": ghsa_id, "found": False})

    for osv_id in ids.get("osv", []):
        rec = vuln_retrieval.get_osv(osv_id)
        out["osv"].append(rec if rec else {"osv_id": osv_id, "found": False})

    for tid in ids.get("attack", []):
        rec = graph_query.technique_coverage(tid)
        out["attack"].append(rec if rec else {"technique_id": tid, "found": False})

    for local_name in ids.get("d3fend", []):
        label = _d3fend_label_for(local_name)
        node = graph_store.get_node(f"countermeasure:{label}") if label else None
        if node:
            countered = [
                e["src"].split(":", 1)[-1]
                for e in graph_store.edges_to(node["node_id"])
                if e["edge_type"] == "countered_by"
            ]
            out["d3fend"].append({
                "label": label, "found": True,
                "source_url": node["attrs"].get("source_url"),
                "counters_techniques": sorted(countered),
            })
        else:
            out["d3fend"].append({"local_name": local_name, "found": False})

    for control_id in ids.get("nist_control", []):
        rec = controls_store.find_control_any_framework(control_id)
        if rec:
            rec["found"] = True
            rec["identifier"] = rec["control_id"]
            rec["related"] = controls_store.get_links(rec["framework"], rec["control_id"])
            rec["children"] = controls_store.get_children(rec["framework"], rec["control_id"])
        else:
            rec = {"control_id": control_id, "found": False}
        out["nist_control"].append(rec)

    return out


# ---------------------------------------------------------------------------
# Topic-scoped retrieval
# ---------------------------------------------------------------------------

async def route_and_retrieve(question: str, top_k: int = 8) -> dict:
    """Classify ``question`` and run the matching retrieval strategy.

    Returns ``{route, identifiers, matched_keywords, results}`` where
    ``results`` shape depends on the route:
      * exact_lookup           -> resolve_exact() output
      * vulnerability_filter   -> vulnerabilities.retrieval.search() output
      * detection/mitigation/incident_response/cloud/compliance/general ->
        list of citation dicts from the shared hybrid retriever, scoped by
        pack_id for the topic routes (cloud is scoped via real ``platform``
        graph edges when the platform's packs are actually installed).
    """
    decision = classify(question)
    route = decision["route"]

    if route == ROUTE_EXACT_LOOKUP:
        results = resolve_exact(decision["identifiers"])
    elif route == ROUTE_PACKAGE:
        pq = decision["package_query"]
        results = vuln_retrieval.search_package_vulnerabilities(pq["ecosystem"], pq["package"])
    elif route == ROUTE_VERSION_CHECK:
        vq = decision["version_query"]
        results = version_check.check_version(vq["ecosystem"], vq["package"], vq["version"])
    elif route == ROUTE_PRIORITIZATION:
        results = prioritization.rank_cves(decision["identifiers"].get("cve", []))
    elif route == ROUTE_VULN_FILTER:
        results = await vuln_retrieval.search(question, top_k=top_k)
    elif route in (ROUTE_DETECTION, ROUTE_MITIGATION, ROUTE_IR):
        pack_ids = {
            ROUTE_DETECTION: DETECTION_PACKS,
            ROUTE_MITIGATION: MITIGATION_PACKS,
            ROUTE_IR: IR_PACKS,
        }[route]
        merged: list[dict] = []
        for pid in pack_ids:
            merged.extend(await retrieval.retrieve(question, top_k=top_k, pack_id=pid))
        merged.sort(key=lambda c: c.get("score", 0), reverse=True)
        results = merged[:top_k]
    elif route == ROUTE_COMPLIANCE:
        pack_ids = COMPLIANCE_PACKS
        merged: list[dict] = []
        for pid in pack_ids:
            merged.extend(await retrieval.retrieve(question, top_k=top_k, pack_id=pid))
        merged.sort(key=lambda c: c.get("score", 0), reverse=True)
        results = merged[:top_k]
    elif route == ROUTE_CLOUD:
        pack_ids = _packs_for_platforms(decision["platforms"])
        if pack_ids:
            merged = []
            for pid in pack_ids:
                merged.extend(await retrieval.retrieve(question, top_k=top_k, pack_id=pid))
            merged.sort(key=lambda c: c.get("score", 0), reverse=True)
            results = merged[:top_k]
        else:
            results = await retrieval.retrieve(question, top_k=top_k)
    else:
        results = await retrieval.retrieve(question, top_k=top_k)

    return {
        "route": route,
        "identifiers": decision["identifiers"],
        "matched_keywords": decision["matched_keywords"],
        "platforms": decision.get("platforms", []),
        "results": results,
    }


def _packs_for_platforms(platforms: list[str]) -> list[str]:
    """Real pack ids currently declaring guidance for these platforms, via the
    knowledge graph's ``platform --has_guidance--> pack`` edges — never a
    hardcoded list, so this tracks whatever platforms are actually installed."""
    pack_ids: set[str] = set()
    for platform in platforms:
        node_id = f"platform:{platform}"
        for e in graph_store.edges_from(node_id):
            if e["edge_type"] == "has_guidance":
                pack_ids.add(e["dst"].split(":", 1)[-1])
    return sorted(pack_ids)
