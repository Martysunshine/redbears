"""
Entity graph builder for SOC Copilot Workbench.

Builds investigation graphs from existing case data across all analysis modules.
Read-only — no data modification, no external calls.
"""

import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.correlated_finding import CorrelatedFinding
from socmat.services.api.models.case_mitre_mapping import CaseMitreMapping
from socmat.services.api.models.ioc import Ioc
from socmat.services.api.schemas.graph_schema import GraphEdge, GraphMetadata, GraphNode, GraphResponse

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _sev_max(a: str, b: str) -> str:
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


def _load_json(val: Optional[str], fallback=None):
    if fallback is None:
        fallback = []
    if not val:
        return fallback
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except Exception:
        return fallback


class GraphBuilder:
    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: Dict[str, GraphEdge] = {}
        self._edge_counter = 0
        self._seen_pairs: Set[Tuple] = set()

    def _add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        description: str = "",
        severity: str = "info",
        confidence: str = "medium",
        source_id: Optional[int] = None,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        if node_id in self._nodes:
            existing = self._nodes[node_id]
            new_sev = _sev_max(existing.severity, severity)
            sids = existing.source_ids
            if source_id is not None and source_id not in sids:
                sids = sids + [source_id]
            self._nodes[node_id] = existing.model_copy(update={"severity": new_sev, "source_ids": sids})
        else:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type=node_type,
                label=label[:80],
                description=(description or "")[:200],
                severity=severity,
                confidence=confidence,
                source_ids=[source_id] if source_id is not None else [],
                properties=properties or {},
            )
        return node_id

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        label: str,
        confidence: str = "medium",
        evidence_reference: str = "",
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        key = f"{source}|{target}|{edge_type}"
        if key in self._edges:
            return
        self._edge_counter += 1
        self._edges[key] = GraphEdge(
            id=f"e_{self._edge_counter}",
            source=source,
            target=target,
            type=edge_type,
            label=label,
            confidence=confidence,
            evidence_reference=evidence_reference or "",
            properties=properties or {},
        )

    def build(
        self,
        db: Session,
        case_id: int,
        show_hosts: bool = True,
        show_users: bool = True,
        show_ips: bool = True,
        show_domains: bool = True,
        show_processes: bool = True,
        show_detections: bool = True,
        show_mitre: bool = True,
        show_iocs: bool = True,
        show_evidence: bool = False,
        only_suspicious: bool = False,
    ) -> GraphResponse:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return GraphResponse(nodes=[], edges=[], metadata=GraphMetadata(
                total_nodes=0, total_edges=0, node_type_counts={},
                case_id=case_id, filters_applied={},
            ))

        case_node = f"case_{case_id}"
        self._add_node(case_node, "case", case.title[:60], f"Investigation case #{case_id}", "info", "high")

        # Evidence files
        evidence_list = db.query(Evidence).filter(Evidence.case_id == case_id).all()
        if show_evidence:
            for ev in evidence_list[:10]:
                ev_node = f"evidence_{ev.id}"
                sha_prefix = (ev.sha256[:16] + "…") if ev.sha256 else ""
                self._add_node(
                    ev_node, "evidence_file", ev.original_filename,
                    f"Uploaded evidence ({ev.file_type})", "info", "high", ev.id,
                    {"file_size": ev.file_size, "sha256_prefix": sha_prefix},
                )
                self._add_edge(case_node, ev_node, "related_to", "contains", "high")

        # Normalized events — build frequency maps for capping
        norm_events = db.query(NormalizedEvent).filter(NormalizedEvent.case_id == case_id).all()

        host_count: Dict[str, int] = defaultdict(int)
        user_count: Dict[str, int] = defaultdict(int)
        ip_count: Dict[str, int] = defaultdict(int)
        process_count: Dict[str, int] = defaultdict(int)
        host_sev: Dict[str, str] = {}
        user_sev: Dict[str, str] = {}
        ip_sev: Dict[str, str] = {}
        process_sev: Dict[str, str] = {}

        for ev in norm_events:
            sev = ev.severity or "info"
            if ev.host:
                host_count[ev.host] += 1
                host_sev[ev.host] = _sev_max(host_sev.get(ev.host, "info"), sev)
            if ev.user:
                user_count[ev.user] += 1
                user_sev[ev.user] = _sev_max(user_sev.get(ev.user, "info"), sev)
            for ip in [ev.source_ip, ev.destination_ip]:
                if ip:
                    ip_count[ip] += 1
                    ip_sev[ip] = _sev_max(ip_sev.get(ip, "info"), sev)
            if ev.process_name:
                process_count[ev.process_name] += 1
                process_sev[ev.process_name] = _sev_max(process_sev.get(ev.process_name, "info"), sev)

        top_hosts = set(sorted(host_count, key=lambda k: host_count[k], reverse=True)[:20])
        top_users = set(sorted(user_count, key=lambda k: user_count[k], reverse=True)[:20])
        top_ips = set(sorted(ip_count, key=lambda k: ip_count[k], reverse=True)[:20])
        top_processes = set(sorted(process_count, key=lambda k: process_count[k], reverse=True)[:15])

        if show_hosts:
            for h in top_hosts:
                self._add_node(f"host_{h}", "host", h, f"Host in {host_count[h]} events", host_sev.get(h, "info"), "high")
                self._add_edge(case_node, f"host_{h}", "related_to", "includes", "high")

        if show_users:
            for u in top_users:
                self._add_node(f"user_{u}", "user", u, f"User in {user_count[u]} events", user_sev.get(u, "info"), "high")

        if show_ips:
            for ip in top_ips:
                self._add_node(f"ip_{ip}", "ip_address", ip, f"IP in {ip_count[ip]} events", ip_sev.get(ip, "info"), "high")

        if show_processes:
            for p in top_processes:
                self._add_node(f"process_{p}", "process", p, f"Process in {process_count[p]} events", process_sev.get(p, "info"), "high")

        # Add parent process nodes (up to 10 unique parents not already in top_processes)
        if show_processes:
            parent_added = 0
            for ev in norm_events:
                if ev.parent_process_name and ev.parent_process_name not in top_processes:
                    p_key = f"process_{ev.parent_process_name}"
                    if p_key not in self._nodes and parent_added < 10:
                        self._add_node(p_key, "process", ev.parent_process_name, "Parent process", "info", "medium")
                        parent_added += 1

        # Edges from normalized events
        for ev in norm_events:
            h_node = f"host_{ev.host}" if ev.host and ev.host in top_hosts else None
            u_node = f"user_{ev.user}" if ev.user and ev.user in top_users else None
            src_node = f"ip_{ev.source_ip}" if ev.source_ip and ev.source_ip in top_ips else None
            dst_node = f"ip_{ev.destination_ip}" if ev.destination_ip and ev.destination_ip in top_ips else None
            p_key = f"process_{ev.process_name}"
            p_node = p_key if ev.process_name and p_key in self._nodes else None
            pp_key = f"process_{ev.parent_process_name}"
            pp_node = pp_key if ev.parent_process_name and pp_key in self._nodes else None
            ev_ref = f"NormalizedEvent #{ev.id}"

            if show_hosts and show_users and u_node and h_node:
                pair = ("u_h", u_node, h_node)
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    self._add_edge(u_node, h_node, "logged_into", "logged into", "high", ev_ref)

            if show_ips and show_hosts and src_node and h_node:
                pair = ("ip_h", src_node, h_node)
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    self._add_edge(src_node, h_node, "connected_to", "connected to", "medium", ev_ref)

            if show_processes and show_hosts and p_node and h_node:
                pair = ("p_h", p_node, h_node)
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    self._add_edge(p_node, h_node, "executed", "executed on", "high", ev_ref)

            if show_processes and pp_node and p_node and pp_node != p_node:
                pair = ("pp_p", pp_node, p_node)
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    self._add_edge(pp_node, p_node, "spawned", "spawned", "high", ev_ref)

            if show_processes and show_ips and p_node and dst_node:
                pair = ("p_ip", p_node, dst_node)
                if pair not in self._seen_pairs:
                    self._seen_pairs.add(pair)
                    self._add_edge(p_node, dst_node, "connected_to", "connected to", "medium", ev_ref)

        # Detection findings — Sigma rules (limit 15 by severity)
        if show_detections:
            det_findings = (
                db.query(DetectionFinding)
                .filter(DetectionFinding.case_id == case_id)
                .all()
            )
            seen_sigma: Dict[str, str] = {}
            sigma_count = 0
            for df in sorted(det_findings, key=lambda x: _SEV_RANK.get(x.severity, 0), reverse=True):
                s_node = f"sigma_{df.rule_id}"
                if df.rule_id not in seen_sigma:
                    if sigma_count >= 15:
                        continue
                    self._add_node(s_node, "sigma_rule", df.rule_title[:60], f"Sigma: {df.rule_id}", df.severity, "high", df.id)
                    seen_sigma[df.rule_id] = s_node
                    sigma_count += 1
                else:
                    self._add_node(s_node, "sigma_rule", df.rule_title[:60], "", df.severity, "high", df.id)

                matched_ev = db.query(NormalizedEvent).filter(NormalizedEvent.id == df.matched_event_id).first()
                if matched_ev:
                    if show_hosts and matched_ev.host and matched_ev.host in top_hosts:
                        self._add_edge(s_node, f"host_{matched_ev.host}", "matched_rule", "matched on", "high", f"DetectionFinding #{df.id}")
                    if show_processes and matched_ev.process_name:
                        p_k = f"process_{matched_ev.process_name}"
                        if p_k in self._nodes:
                            self._add_edge(s_node, p_k, "matched_rule", "matched", "high", f"DetectionFinding #{df.id}")
                    if show_users and matched_ev.user and matched_ev.user in top_users:
                        self._add_edge(s_node, f"user_{matched_ev.user}", "matched_rule", "matched on", "high", f"DetectionFinding #{df.id}")

        # YARA results (limit 10)
        if show_detections:
            yara_results = (
                db.query(MalwareTriageResult)
                .filter(MalwareTriageResult.case_id == case_id)
                .all()
            )
            yara_rule_count = 0
            for yr in yara_results:
                if yr.sha256:
                    hash_node = f"hash_{yr.sha256[:16]}"
                    self._add_node(
                        hash_node, "file_hash", yr.sha256[:16] + "…",
                        "File hash (SHA256)",
                        "high" if yr.risk_score > 50 else "medium", "high", yr.id,
                        {"sha256": yr.sha256, "risk_score": yr.risk_score},
                    )
                    if show_evidence:
                        ev_node = f"evidence_{yr.evidence_id}"
                        if ev_node in self._nodes:
                            self._add_edge(ev_node, hash_node, "extracted_from", "hash of", "high")

                    yara_matches = _load_json(yr.yara_matches, [])
                    for match_name in yara_matches[:5]:
                        if yara_rule_count >= 10:
                            break
                        y_node = f"yara_{match_name}"
                        self._add_node(y_node, "yara_rule", str(match_name)[:60], "YARA rule match", "high", "high")
                        self._add_edge(hash_node, y_node, "matched_rule", "matched", "high", f"MalwareTriageResult #{yr.id}")
                        yara_rule_count += 1

        # Network analysis — domains and Suricata signatures
        net_results = (
            db.query(NetworkAnalysisResult)
            .filter(NetworkAnalysisResult.case_id == case_id)
            .all()
        )
        domain_count = 0
        suricata_count = 0
        for nr in net_results:
            summary_data = _load_json(nr.summary_data, {})

            if show_domains:
                dns_summary = summary_data.get("dns_summary", {}) if isinstance(summary_data, dict) else {}
                domains_raw = dns_summary.get("top_domains", []) if isinstance(dns_summary, dict) else []
                for dom_entry in (domains_raw or [])[:15]:
                    if domain_count >= 15:
                        break
                    dom = dom_entry if isinstance(dom_entry, str) else (dom_entry.get("domain", "") if isinstance(dom_entry, dict) else "")
                    if not dom or len(dom) < 4:
                        continue
                    self._add_node(f"domain_{dom}", "domain", dom, "Domain in network logs", "info", "medium")
                    domain_count += 1

            if show_detections:
                findings = _load_json(nr.findings, [])
                for finding in (findings or [])[:10]:
                    if suricata_count >= 10:
                        break
                    sig = (finding.get("signature") or finding.get("title") or "") if isinstance(finding, dict) else ""
                    if not sig:
                        continue
                    sig_clean = str(sig)[:60]
                    s_node = f"suricata_{sig_clean}"
                    sev = (finding.get("severity") or "medium") if isinstance(finding, dict) else "medium"
                    self._add_node(s_node, "suricata_signature", sig_clean, "Suricata IDS/IPS alert", sev, "high")
                    src_ip = (finding.get("src_ip") or "") if isinstance(finding, dict) else ""
                    if show_ips and src_ip and f"ip_{src_ip}" in self._nodes:
                        self._add_edge(f"ip_{src_ip}", s_node, "triggered_alert", "triggered", "high", f"NetworkAnalysisResult #{nr.id}")
                    suricata_count += 1

        # Correlated findings
        corr_findings = (
            db.query(CorrelatedFinding)
            .filter(CorrelatedFinding.case_id == case_id)
            .all()
        )
        for cf in corr_findings:
            c_node = f"correlated_{cf.id}"
            self._add_node(c_node, "correlated_finding", cf.title[:60], cf.summary or "", cf.severity, cf.confidence, cf.id)

            entities = _load_json(cf.entities, [])
            for ent in (entities or []):
                if not isinstance(ent, dict):
                    continue
                ent_type = ent.get("type", "")
                ent_value = ent.get("value", "")
                if not ent_value:
                    continue
                target_key = None
                if show_hosts and ent_type == "host":
                    target_key = f"host_{ent_value}"
                elif show_users and ent_type == "user":
                    target_key = f"user_{ent_value}"
                elif show_ips and ent_type in ("ip", "src_ip", "dst_ip"):
                    target_key = f"ip_{ent_value}"
                elif show_processes and ent_type == "process":
                    target_key = f"process_{ent_value}"
                if target_key and target_key in self._nodes:
                    self._add_edge(c_node, target_key, "correlated_with", "involves", cf.confidence, f"CorrelatedFinding #{cf.id}")

        # MITRE mappings
        if show_mitre:
            mitre_mappings = (
                db.query(CaseMitreMapping)
                .filter(CaseMitreMapping.case_id == case_id)
                .all()
            )
            for mm in mitre_mappings:
                m_node = f"mitre_{mm.technique_id}"
                self._add_node(
                    m_node, "mitre_technique",
                    f"{mm.technique_id} {mm.technique_name}",
                    f"ATT&CK {mm.tactic}: {mm.technique_name}",
                    "high", mm.confidence, mm.id,
                    {"tactic": mm.tactic, "technique_id": mm.technique_id},
                )
                self._add_edge(case_node, m_node, "mapped_to_mitre", "mapped to", mm.confidence, f"CaseMitreMapping #{mm.id}")

                # Link evidence references → try to connect correlated/sigma nodes to MITRE
                ev_refs = _load_json(mm.evidence_reference, [])
                for ref in (ev_refs or []):
                    if not isinstance(ref, dict):
                        continue
                    source = ref.get("source", "")
                    detail = str(ref.get("detail", ""))[:40]
                    if source == "correlation":
                        for c_nid in [k for k in self._nodes if k.startswith("correlated_")]:
                            if detail and detail[:30] in self._nodes[c_nid].label:
                                self._add_edge(c_nid, m_node, "mapped_to_mitre", "mapped to", mm.confidence)
                                break
                    elif source == "sigma":
                        for s_nid in [k for k in self._nodes if k.startswith("sigma_")]:
                            if detail and detail[:30] in self._nodes[s_nid].label:
                                self._add_edge(s_nid, m_node, "mapped_to_mitre", "mapped to", mm.confidence)
                                break

        # IOCs (limit 25, high confidence first, skip benign)
        if show_iocs:
            iocs = (
                db.query(Ioc)
                .filter(Ioc.case_id == case_id)
                .limit(50)
                .all()
            )
            ioc_added = 0
            for ioc in sorted(iocs, key=lambda x: _SEV_RANK.get(x.confidence, 0), reverse=True):
                if ioc_added >= 25:
                    break
                tags = _load_json(ioc.tags_json, [])
                if "benign" in tags:
                    continue
                i_node = f"ioc_{ioc.id}"
                sev = "medium" if "suspicious" in tags or "confirmed_malicious" in tags else "low"
                self._add_node(i_node, "ioc", ioc.value[:60], f"IOC: {ioc.ioc_type}", sev, ioc.confidence, ioc.id, {"ioc_type": ioc.ioc_type, "source_type": ioc.source_type or ""})

                # Link to related graph nodes
                if ioc.ioc_type == "ipv4":
                    t_key = f"ip_{ioc.value}"
                    if t_key in self._nodes:
                        self._add_edge(i_node, t_key, "extracted_from", "extracted from", ioc.confidence, f"IOC #{ioc.id}")
                elif ioc.ioc_type == "domain":
                    t_key = f"domain_{ioc.value}"
                    if t_key in self._nodes:
                        self._add_edge(i_node, t_key, "extracted_from", "extracted from", ioc.confidence, f"IOC #{ioc.id}")
                elif ioc.ioc_type == "hostname":
                    t_key = f"host_{ioc.value}"
                    if t_key in self._nodes:
                        self._add_edge(i_node, t_key, "observed_in", "observed in", ioc.confidence, f"IOC #{ioc.id}")
                elif ioc.ioc_type == "username":
                    t_key = f"user_{ioc.value}"
                    if t_key in self._nodes:
                        self._add_edge(i_node, t_key, "observed_in", "observed in", ioc.confidence, f"IOC #{ioc.id}")
                elif ioc.ioc_type == "process_name":
                    t_key = f"process_{ioc.value}"
                    if t_key in self._nodes:
                        self._add_edge(i_node, t_key, "observed_in", "observed in", ioc.confidence, f"IOC #{ioc.id}")
                elif ioc.ioc_type in ("sha256", "sha1", "md5"):
                    t_key = f"hash_{ioc.normalized_value[:16]}"
                    if t_key in self._nodes:
                        self._add_edge(i_node, t_key, "extracted_from", "extracted from", ioc.confidence, f"IOC #{ioc.id}")
                ioc_added += 1

        # only_suspicious: keep nodes connected to detection/correlation nodes
        if only_suspicious:
            suspicious_types = {"sigma_rule", "yara_rule", "suricata_signature", "correlated_finding", "mitre_technique"}
            detection_nids = {nid for nid, n in self._nodes.items() if n.type in suspicious_types}
            connected: Set[str] = set()
            for edge in self._edges.values():
                if edge.source in detection_nids or edge.target in detection_nids:
                    connected.add(edge.source)
                    connected.add(edge.target)
            keep_ids = detection_nids | connected | {case_node}
            self._nodes = {k: v for k, v in self._nodes.items() if k in keep_ids}

        # Remove edges referencing nodes that were filtered out
        valid_ids = set(self._nodes.keys())
        self._edges = {k: v for k, v in self._edges.items() if v.source in valid_ids and v.target in valid_ids}

        nodes_list = list(self._nodes.values())
        edges_list = list(self._edges.values())

        node_type_counts: Dict[str, int] = defaultdict(int)
        for n in nodes_list:
            node_type_counts[n.type] += 1

        return GraphResponse(
            nodes=nodes_list,
            edges=edges_list,
            metadata=GraphMetadata(
                total_nodes=len(nodes_list),
                total_edges=len(edges_list),
                node_type_counts=dict(node_type_counts),
                case_id=case_id,
                filters_applied={
                    "show_hosts": show_hosts,
                    "show_users": show_users,
                    "show_ips": show_ips,
                    "show_domains": show_domains,
                    "show_processes": show_processes,
                    "show_detections": show_detections,
                    "show_mitre": show_mitre,
                    "show_iocs": show_iocs,
                    "show_evidence": show_evidence,
                    "only_suspicious": only_suspicious,
                },
            ),
        )


def build_graph(db: Session, case_id: int, **filters) -> GraphResponse:
    return GraphBuilder().build(db, case_id, **filters)
