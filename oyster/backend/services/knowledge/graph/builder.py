"""Deterministic cross-source graph builder.

Scans the ``knowledge_chunks`` provenance table and joins sources on the ATT&CK
technique id. No LLM and no network — pure string/regex extraction over already
imported, licence-cleared content.

Role of each pack in the graph:

* ``mitre-attack*``   → **mapping** (authoritative technique definition). The
  technique id is taken from the doc's *own* title / canonical url only — never
  from a content-wide scan — so a technique's prose mentioning other techniques
  does not fabricate mappings.
* ``atomic-red-team-src`` → **emulation** (one atomic doc == one technique; id
  from the leading token of its title).
* ``sigma-src``      → **detection** (a rule may tag several techniques via
  ``tags: attack.tXXXX`` — all are linked).
* ``mitre-d3fend-src`` → **countermeasure** (each doc lists the real ATT&CK
  techniques its D3FEND technique counters, from the official mapping export).

A second pass joins the structured vulnerability tables (``services.knowledge.
vulnerabilities.store`` — CWE/CAPEC catalogs + CVE↔CWE / CAPEC↔CWE link tables
populated by the vulnerability sync pipeline, not by this module) so CVE→CWE
and CWE→CAPEC edges reflect only relationships that were actually ingested from
NVD/MITRE — never inferred from prose. CVE nodes are only created for CVEs that
carry at least one real edge (CWE classification or KEV listing); the full CVE
corpus stays in ``vulnerability_records`` and is reached via structured search,
not duplicated into the graph.

A third pass links each installed pack's declared ``applicable_platforms`` to a
platform node, so "cloud platform / OS → hardening guidance" is queryable.
"""

from __future__ import annotations

import re
import sqlite3

import config

from . import store

# Enterprise/Mobile: T1234 or T1234.001 ; ICS: T0800-range (also 4 digits).
_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SIGMA_TAG_RE = re.compile(r"attack[._]t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_URL_TID_RE = re.compile(r"/techniques/(T\d{4})(?:/(\d{3}))?")
_D3FEND_TID_RE = re.compile(r"\*\*(T\d{4}(?:\.\d{3})?)\*\*")
_D3FEND_TITLE_RE = re.compile(r"^D3FEND — (.+)$")

_MITRE_PREFIX = "mitre-attack"
_ATOMIC_PACK = "atomic-red-team-src"
_SIGMA_PACK = "sigma-src"
_D3FEND_PACK = "mitre-d3fend-src"

# Splunk Security Content (`mitre_attack_id:\n  - T1190`) and Falco rules
# (`tags: [..., T1555]`) each embed real, source-supplied ATT&CK technique
# ids directly in their detection-rule YAML — a bare token match is safe here
# specifically because both packs are curated detection-rule content, not
# general prose where a "T1234"-shaped substring could appear coincidentally.
_BARE_TID_RE = re.compile(r"\bT(\d{4}(?:\.\d{3})?)\b")
_DETECTION_TID_PACKS = ("splunk-security-content-src", "falco-rules-src")


def _kchunk_rows() -> list[dict]:
    con = sqlite3.connect(str(config.MEMORY_DB), check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT pack_id, title, canonical_url, content FROM knowledge_chunks"
        ).fetchall()
    finally:
        con.close()
    return [dict(r) for r in rows]


def _leading_tid(title: str | None) -> str | None:
    if not title:
        return None
    m = _TID_RE.match(title.strip())
    return m.group(0) if m else None


def _url_tid(url: str | None) -> str | None:
    if not url:
        return None
    m = _URL_TID_RE.search(url)
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)


def _parent_tid(tid: str) -> str | None:
    return tid.split(".", 1)[0] if "." in tid else None


def build() -> dict:
    """Rebuild the whole graph from installed knowledge. Returns a stats dict."""
    rows = _kchunk_rows()

    labels: dict[str, str] = {}          # tid -> best human label
    urls: dict[str, str] = {}            # tid -> a canonical url
    mapped: set[str] = set()             # tids defined by ATT&CK
    # (tid, pack_id, role) -> aggregate
    agg: dict[tuple[str, str, str], dict] = {}
    roles_by_tid: dict[str, set[str]] = {}
    packs_seen: set[str] = set()
    d3fend_edges: dict[tuple[str, str], dict] = {}  # (tid, d3fend_label) -> {url}

    def _touch(tid: str, pack_id: str, role: str, title: str | None, url: str | None):
        packs_seen.add(pack_id)
        key = (tid, pack_id, role)
        a = agg.get(key)
        if a is None:
            agg[key] = {"count": 1, "sample_title": title, "sample_url": url}
        else:
            a["count"] += 1
            if not a.get("sample_url") and url:
                a["sample_url"] = url
        roles_by_tid.setdefault(tid, set()).add(role)

    for r in rows:
        pack = r.get("pack_id") or ""
        title = r.get("title")
        url = r.get("canonical_url")
        if pack.startswith(_MITRE_PREFIX):
            tid = _leading_tid(title) or _url_tid(url)
            if not tid:
                continue
            mapped.add(tid)
            labels.setdefault(tid, (title or tid).strip())
            if url:
                urls.setdefault(tid, url)
            _touch(tid, pack, "mapped_by", title, url)
        elif pack == _ATOMIC_PACK:
            tid = _leading_tid(title)
            if not tid:
                continue
            labels.setdefault(tid, (title or tid).strip())
            _touch(tid, pack, "emulated_by", title, url)
        elif pack == _SIGMA_PACK:
            content = r.get("content") or ""
            found = {m.group(1).upper() for m in _SIGMA_TAG_RE.finditer(content)}
            for raw in found:
                tid = f"T{raw}"
                _touch(tid, pack, "detected_by", title, url)
                labels.setdefault(tid, tid)
        elif pack in _DETECTION_TID_PACKS:
            content = r.get("content") or ""
            found = {m.group(1).upper() for m in _BARE_TID_RE.finditer(content)}
            for raw in found:
                tid = f"T{raw}"
                _touch(tid, pack, "detected_by", title, url)
                labels.setdefault(tid, tid)
        elif pack == _D3FEND_PACK:
            m = _D3FEND_TITLE_RE.match((title or "").strip())
            if not m:
                continue
            d3fend_label = m.group(1).strip()
            content = r.get("content") or ""
            for tm in _D3FEND_TID_RE.finditer(content):
                tid = tm.group(1).upper()
                _touch(tid, pack, "countered_by", title, url)
                labels.setdefault(tid, tid)
                key = (tid, d3fend_label)
                if key not in d3fend_edges:
                    d3fend_edges[key] = {"url": url}
        # yara / other packs carry no ATT&CK ids — skipped by design.

    # --- assemble nodes -----------------------------------------------------
    nodes: list[dict] = []
    all_tids = set(roles_by_tid) | mapped
    # ensure parents exist as nodes even if only referenced by a sub-technique
    for tid in list(all_tids):
        p = _parent_tid(tid)
        if p:
            all_tids.add(p)

    pack_meta = _pack_titles()
    for pack in sorted(packs_seen):
        nodes.append({
            "node_id": f"pack:{pack}", "node_type": "pack",
            "label": pack_meta.get(pack, pack),
            "attrs": {"pack_id": pack},
        })
    for tid in sorted(all_tids):
        nodes.append({
            "node_id": f"technique:{tid}", "node_type": "technique",
            "label": labels.get(tid, tid),
            "attrs": {
                "technique_id": tid,
                "mapped": tid in mapped,
                "is_subtechnique": "." in tid,
                "source_url": urls.get(tid),
                "roles": sorted(roles_by_tid.get(tid, set())),
            },
        })

    d3fend_labels = sorted({label for _, label in d3fend_edges})
    d3fend_urls: dict[str, str] = {}
    for (_, label), a in d3fend_edges.items():
        if a.get("url"):
            d3fend_urls.setdefault(label, a["url"])
    for label in d3fend_labels:
        nodes.append({
            "node_id": f"countermeasure:{label}", "node_type": "countermeasure",
            "label": label,
            "attrs": {"source": "MITRE D3FEND", "source_url": d3fend_urls.get(label)},
        })

    # --- assemble edges -----------------------------------------------------
    edges: list[dict] = []
    for (tid, pack, role), a in agg.items():
        edges.append({
            "src": f"technique:{tid}", "dst": f"pack:{pack}", "edge_type": role,
            "attrs": {"count": a["count"], "sample_url": a.get("sample_url"),
                      "sample_title": a.get("sample_title")},
        })
    for tid in sorted(all_tids):
        p = _parent_tid(tid)
        if p:
            edges.append({
                "src": f"technique:{tid}", "dst": f"technique:{p}",
                "edge_type": "child_of", "attrs": {},
            })
    for (tid, label), a in d3fend_edges.items():
        edges.append({
            "src": f"technique:{tid}", "dst": f"countermeasure:{label}",
            "edge_type": "countered_by", "attrs": {"source_url": a.get("url")},
        })

    vuln_nodes, vuln_edges = _vuln_relationships()
    nodes.extend(vuln_nodes)
    edges.extend(vuln_edges)

    platform_nodes, platform_edges = _platform_relationships()
    nodes.extend(platform_nodes)
    edges.extend(platform_edges)

    control_nodes, control_edges = _control_relationships()
    nodes.extend(control_nodes)
    edges.extend(control_edges)

    ghsa_osv_nodes, ghsa_osv_edges = _ghsa_osv_relationships()
    nodes.extend(ghsa_osv_nodes)
    edges.extend(ghsa_osv_edges)

    # --- inconsistencies / coverage gaps ------------------------------------
    incons: list[dict] = []
    for tid in sorted(roles_by_tid):
        roles = roles_by_tid[tid]
        referenced = {"emulated_by", "detected_by", "countered_by"} & roles
        if referenced and tid not in mapped:
            who = sorted(r.replace("_by", "") for r in referenced)
            incons.append({
                "kind": "dangling_reference", "subject": tid, "severity": "warning",
                "detail": f"{tid} is referenced for {', '.join(who)} but is not "
                          f"present in the imported MITRE ATT&CK set "
                          f"(deprecated/renamed technique, or an un-imported ATT&CK domain).",
                "attrs": {"roles": sorted(roles)},
            })
    for tid in sorted(mapped):
        roles = roles_by_tid.get(tid, set())
        if "detected_by" in roles and "emulated_by" not in roles:
            incons.append({
                "kind": "detection_without_emulation", "subject": tid, "severity": "info",
                "detail": f"{tid} has Sigma detection coverage but no Atomic Red Team "
                          f"emulation test — detection is unvalidated by emulation.",
                "attrs": {"roles": sorted(roles)},
            })
        elif "emulated_by" in roles and "detected_by" not in roles:
            incons.append({
                "kind": "emulation_without_detection", "subject": tid, "severity": "info",
                "detail": f"{tid} has an Atomic Red Team emulation test but no Sigma "
                          f"detection rule — a potential detection gap.",
                "attrs": {"roles": sorted(roles)},
            })

    stats = {
        "techniques": sum(1 for n in nodes if n["node_type"] == "technique"),
        "techniques_mapped": len(mapped),
        "packs": len(packs_seen),
        "countermeasures": len(d3fend_labels),
        "edges": len(edges),
        "nodes_by_type": {
            t: sum(1 for n in nodes if n["node_type"] == t)
            for t in sorted({n["node_type"] for n in nodes})
        },
        "coverage": {
            "mapping_only": _count_roles(roles_by_tid, mapped, {"mapped_by"}, exact=True),
            "with_detection": sum(1 for t in mapped if "detected_by" in roles_by_tid.get(t, set())),
            "with_emulation": sum(1 for t in mapped if "emulated_by" in roles_by_tid.get(t, set())),
            "detection_and_emulation": sum(
                1 for t in mapped
                if {"detected_by", "emulated_by"} <= roles_by_tid.get(t, set())),
        },
        "inconsistencies": {
            "dangling_reference": sum(1 for i in incons if i["kind"] == "dangling_reference"),
            "detection_without_emulation": sum(
                1 for i in incons if i["kind"] == "detection_without_emulation"),
            "emulation_without_detection": sum(
                1 for i in incons if i["kind"] == "emulation_without_detection"),
        },
    }

    # --- structural invariant: no edge may reference a node absent from this
    # same build. Every relationship builder above already only emits an edge
    # once it has confirmed both endpoints are real rows in their own source
    # table, so this should be a no-op in practice — it is enforced here as a
    # hard guarantee on what actually gets stored, not just on builder intent,
    # and any violation is dropped (never silently) and recorded so it stays
    # auditable via kg_inconsistencies / store.dangling_edges(). -------------
    node_ids = {n["node_id"] for n in nodes}
    kept_edges: list[dict] = []
    for e in edges:
        if e["src"] in node_ids and e["dst"] in node_ids:
            kept_edges.append(e)
        else:
            incons.append({
                "kind": "dangling_edge_dropped", "subject": f"{e['src']}->{e['dst']}",
                "severity": "error",
                "detail": f"edge_type={e['edge_type']} referenced a node absent from this "
                          f"build; dropped rather than stored.",
                "attrs": {"src": e["src"], "dst": e["dst"], "edge_type": e["edge_type"]},
            })
    edges = kept_edges
    stats["edges"] = len(edges)
    stats["inconsistencies"]["dangling_edge_dropped"] = sum(
        1 for i in incons if i["kind"] == "dangling_edge_dropped")

    store.replace_graph(nodes, edges, incons, stats)
    return stats


# ---------------------------------------------------------------------------
# Vulnerability relationships (CVE <-> CWE <-> CAPEC, CVE -> KEV)
# ---------------------------------------------------------------------------
#
# Sourced entirely from the structured tables the vulnerability sync pipeline
# (services.knowledge.vulnerabilities) populates from NVD/CISA-KEV/MITRE — this
# module never re-derives them from prose. CVE nodes are created only for CVEs
# that carry at least one real edge (a stored CWE classification or a KEV
# listing); the full CVE corpus remains queryable via structured search
# (services.knowledge.vulnerabilities.retrieval) without being duplicated here.
_KEV_NODE = "kev:cisa-kev-catalog"


def _vuln_relationships() -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    try:
        con = sqlite3.connect(str(config.MEMORY_DB), check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            cwe_rows = con.execute("SELECT cwe_id, name FROM cwe_records").fetchall()
            capec_rows = con.execute("SELECT capec_id, name FROM capec_records").fetchall()
            cve_cwe_rows = con.execute(
                "SELECT cve_id, cwe_id FROM vulnerability_cwe_links").fetchall()
            capec_cwe_rows = con.execute(
                "SELECT capec_id, cwe_id FROM capec_cwe_links").fetchall()
            cve_ids_needed = {r["cve_id"] for r in cve_cwe_rows}
            kev_rows = con.execute(
                "SELECT cve_id, kev_date_added, cvss_v3_score, cvss_v3_severity, "
                "epss_score, epss_percentile FROM vulnerability_records WHERE kev_listed=1"
            ).fetchall()
            cve_ids_needed |= {r["cve_id"] for r in kev_rows}
            cve_attr_rows = []
            if cve_ids_needed:
                placeholders = ",".join("?" * len(cve_ids_needed))
                cve_attr_rows = con.execute(
                    f"SELECT cve_id, kev_listed, kev_date_added, cvss_v3_score, "
                    f"cvss_v3_severity, epss_score, epss_percentile FROM vulnerability_records "
                    f"WHERE cve_id IN ({placeholders})", tuple(cve_ids_needed)).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        # Vulnerability tables not yet initialized/synced — graph build still
        # succeeds with ATT&CK-side relationships only.
        return nodes, edges

    if not cwe_rows and not capec_rows:
        return nodes, edges

    for r in cwe_rows:
        nodes.append({
            "node_id": f"cwe:{r['cwe_id']}", "node_type": "cwe",
            "label": r["name"] or r["cwe_id"], "attrs": {"cwe_id": r["cwe_id"]},
        })
    for r in capec_rows:
        nodes.append({
            "node_id": f"capec:{r['capec_id']}", "node_type": "capec",
            "label": r["name"] or r["capec_id"], "attrs": {"capec_id": r["capec_id"]},
        })
    for r in capec_cwe_rows:
        edges.append({
            "src": f"capec:{r['capec_id']}", "dst": f"cwe:{r['cwe_id']}",
            "edge_type": "exploits", "attrs": {},
        })

    if cve_attr_rows:
        nodes.append({
            "node_id": _KEV_NODE, "node_type": "catalog",
            "label": "CISA Known Exploited Vulnerabilities Catalog", "attrs": {},
        })
    for r in cve_attr_rows:
        nodes.append({
            "node_id": f"cve:{r['cve_id']}", "node_type": "cve",
            "label": r["cve_id"],
            "attrs": {
                "cve_id": r["cve_id"],
                "kev_listed": bool(r["kev_listed"]),
                "kev_date_added": r["kev_date_added"],
                "cvss_v3_score": r["cvss_v3_score"],
                "cvss_v3_severity": r["cvss_v3_severity"],
                "epss_score": r["epss_score"],
                "epss_percentile": r["epss_percentile"],
            },
        })
        if r["kev_listed"]:
            edges.append({
                "src": f"cve:{r['cve_id']}", "dst": _KEV_NODE,
                "edge_type": "listed_in", "attrs": {"date_added": r["kev_date_added"]},
            })
    for r in cve_cwe_rows:
        edges.append({
            "src": f"cve:{r['cve_id']}", "dst": f"cwe:{r['cwe_id']}",
            "edge_type": "classified_as", "attrs": {},
        })

    return nodes, edges


# ---------------------------------------------------------------------------
# Platform / cloud guidance relationships
# ---------------------------------------------------------------------------
def _platform_relationships() -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    try:
        from services.knowledge import registry as kb_registry
        packs = kb_registry.list_packs()
    except Exception:  # noqa: BLE001
        return nodes, edges

    seen_platforms: set[str] = set()
    seen_packs: set[str] = set()
    for p in packs:
        pack_id = p.get("id")
        platforms = p.get("applicable_platforms") or []
        if not pack_id or not platforms:
            continue
        for platform in platforms:
            platform = (platform or "").strip().lower()
            if not platform:
                continue
            seen_platforms.add(platform)
            edges.append({
                "src": f"platform:{platform}", "dst": f"pack:{pack_id}",
                "edge_type": "has_guidance", "attrs": {},
            })
        if pack_id not in seen_packs:
            seen_packs.add(pack_id)
            nodes.append({
                "node_id": f"pack:{pack_id}", "node_type": "pack",
                "label": p.get("title") or pack_id, "attrs": {"pack_id": pack_id},
            })
    for platform in sorted(seen_platforms):
        nodes.append({
            "node_id": f"platform:{platform}", "node_type": "platform",
            "label": platform, "attrs": {},
        })
    return nodes, edges


# ---------------------------------------------------------------------------
# NIST control relationships (CSF / SP 800-53 / SSDF / privacy baseline)
# ---------------------------------------------------------------------------
#
# Sourced entirely from ``services.knowledge.controls.store`` (real OSCAL
# ``related``/``external_reference`` links parsed by controls/oscal.py — this
# module never re-derives them). A control node is only created when the
# control carries at least one real "related" edge whose target also has a
# real record — the same "no dangling fabricated edge" rule as the ATT&CK
# side. ``external_reference`` cross-framework mentions (e.g. an SSDF task
# citing "NISTCSF: ID.GV-3") carry free-text, not a resolved target id, so
# they are surfaced as a node attribute rather than a fabricated edge.
def _control_relationships() -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    try:
        con = sqlite3.connect(str(config.MEMORY_DB), check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            link_rows = con.execute(
                "SELECT framework, control_id, target_framework, target_control_id, note "
                "FROM control_links WHERE rel='related' AND target_control_id IS NOT NULL"
            ).fetchall()
            if not link_rows:
                return nodes, edges
            control_ids_needed = {(r["framework"], r["control_id"]) for r in link_rows}
            control_ids_needed |= {(r["target_framework"], r["target_control_id"]) for r in link_rows}
            rows = []
            for fw, cid in control_ids_needed:
                row = con.execute(
                    "SELECT framework, control_id, title, class FROM control_records "
                    "WHERE framework=? AND control_id=?", (fw, cid),
                ).fetchone()
                if row:
                    rows.append(row)
        finally:
            con.close()
    except sqlite3.Error:
        return nodes, edges

    real_ids = {(r["framework"], r["control_id"]) for r in rows}
    for r in rows:
        nodes.append({
            "node_id": f"control:{r['framework']}:{r['control_id']}", "node_type": "control",
            "label": f"{r['control_id']} ({r['framework']})",
            "attrs": {"framework": r["framework"], "control_id": r["control_id"],
                     "title": r["title"], "class": r["class"]},
        })
    for r in link_rows:
        src_key = (r["framework"], r["control_id"])
        dst_key = (r["target_framework"], r["target_control_id"])
        if src_key not in real_ids or dst_key not in real_ids:
            continue  # never a dangling/fabricated edge
        edges.append({
            "src": f"control:{src_key[0]}:{src_key[1]}",
            "dst": f"control:{dst_key[0]}:{dst_key[1]}",
            "edge_type": "related_control", "attrs": {},
        })
    return nodes, edges


def _ghsa_osv_relationships() -> tuple[list[dict], list[dict]]:
    """GHSA/OSV -> CVE and GHSA/OSV -> CWE edges, using only real identifiers
    the source itself supplied (an advisory's own ``aliases``/``cwe_ids``) —
    never an inferred mapping. Both endpoints must already exist as real
    rows before an edge is created."""
    nodes: list[dict] = []
    edges: list[dict] = []
    try:
        con = sqlite3.connect(str(config.MEMORY_DB), check_same_thread=False)
        con.row_factory = sqlite3.Row
        try:
            ghsa_rows = con.execute("SELECT ghsa_id, summary FROM ghsa_advisories").fetchall()
            ghsa_alias_rows = con.execute(
                "SELECT ghsa_id, alias FROM ghsa_aliases WHERE alias LIKE 'CVE-%'").fetchall()
            ghsa_cwe_rows = con.execute("SELECT ghsa_id, cwe_id FROM ghsa_cwe_links").fetchall()
            osv_rows = con.execute("SELECT osv_id, summary FROM osv_records").fetchall()
            osv_alias_rows = con.execute(
                "SELECT osv_id, alias FROM osv_aliases WHERE alias LIKE 'CVE-%'").fetchall()
            osv_cwe_rows = con.execute("SELECT osv_id, cwe_id FROM osv_cwe_links").fetchall()

            cve_ids_needed = {r["alias"] for r in ghsa_alias_rows} | {r["alias"] for r in osv_alias_rows}
            real_cve_ids: set[str] = set()
            if cve_ids_needed:
                placeholders = ",".join("?" * len(cve_ids_needed))
                real_cve_ids = {
                    r["cve_id"] for r in con.execute(
                        f"SELECT cve_id FROM vulnerability_records WHERE cve_id IN ({placeholders})",
                        tuple(cve_ids_needed)).fetchall()
                }
            cwe_ids_needed = {r["cwe_id"] for r in ghsa_cwe_rows} | {r["cwe_id"] for r in osv_cwe_rows}
            real_cwe_ids: set[str] = set()
            if cwe_ids_needed:
                placeholders = ",".join("?" * len(cwe_ids_needed))
                real_cwe_ids = {
                    r["cwe_id"] for r in con.execute(
                        f"SELECT cwe_id FROM cwe_records WHERE cwe_id IN ({placeholders})",
                        tuple(cwe_ids_needed)).fetchall()
                }
        finally:
            con.close()
    except sqlite3.Error:
        return nodes, edges

    if not ghsa_rows and not osv_rows:
        return nodes, edges

    for r in ghsa_rows:
        nodes.append({"node_id": f"ghsa:{r['ghsa_id']}", "node_type": "ghsa",
                      "label": r["summary"] or r["ghsa_id"], "attrs": {"ghsa_id": r["ghsa_id"]}})
    for r in osv_rows:
        nodes.append({"node_id": f"osv:{r['osv_id']}", "node_type": "osv",
                      "label": r["summary"] or r["osv_id"], "attrs": {"osv_id": r["osv_id"]}})
    for cve_id in real_cve_ids:
        nodes.append({"node_id": f"cve:{cve_id}", "node_type": "cve", "label": cve_id,
                      "attrs": {"cve_id": cve_id}})

    for r in ghsa_alias_rows:
        if r["alias"] in real_cve_ids:
            edges.append({"src": f"ghsa:{r['ghsa_id']}", "dst": f"cve:{r['alias']}",
                         "edge_type": "documents", "attrs": {}})
    for r in osv_alias_rows:
        if r["alias"] in real_cve_ids:
            edges.append({"src": f"osv:{r['osv_id']}", "dst": f"cve:{r['alias']}",
                         "edge_type": "documents", "attrs": {}})
    for r in ghsa_cwe_rows:
        if r["cwe_id"] in real_cwe_ids:
            edges.append({"src": f"ghsa:{r['ghsa_id']}", "dst": f"cwe:{r['cwe_id']}",
                         "edge_type": "classified_as", "attrs": {}})
    for r in osv_cwe_rows:
        if r["cwe_id"] in real_cwe_ids:
            edges.append({"src": f"osv:{r['osv_id']}", "dst": f"cwe:{r['cwe_id']}",
                         "edge_type": "classified_as", "attrs": {}})

    return nodes, edges


def _count_roles(roles_by_tid, universe, roleset, exact=False) -> int:
    n = 0
    for t in universe:
        r = roles_by_tid.get(t, set())
        # mapped techniques always have mapped_by; count those whose *coverage*
        # (detection/emulation) roles are empty → mapping only.
        cover = r - {"mapped_by"}
        if exact and not cover:
            n += 1
    return n


def _pack_titles() -> dict[str, str]:
    try:
        from services.knowledge import store as kstore
        meta = kstore.pack_meta_map()
        return {pid: (m.get("title") or pid) for pid, m in meta.items()}
    except Exception:  # noqa: BLE001
        return {}
