"""
Suricata eve.json parser.

Supports Suricata Extensible Event Format (EVE) output files
(newline-delimited JSON). Processes alert-type records, normalises
them, and flags suspicious network activity patterns.
"""

import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Suricata numeric severity: 1=high, 2=medium, 3=low
_SEV_MAP: Dict[int, str] = {1: "high", 2: "medium", 3: "low"}


def _parse_timestamp(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    # Trim to 23 chars and normalise separator so strptime works on all platforms
    ts_clean = ts[:23].replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts_clean, fmt)
        except ValueError:
            continue
    return None


def _normalise(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return a normalised alert dict, or None if the record is not an alert."""
    if raw.get("event_type") != "alert":
        return None

    alert = raw.get("alert") or {}
    dns_block = raw.get("dns") or {}
    http_block = raw.get("http") or {}
    tls_block = raw.get("tls") or {}

    # Suricata DNS block can be a dict with a 'queries' list or a flat 'rrname'
    dns_query = ""
    queries = dns_block.get("queries")
    if isinstance(queries, list) and queries:
        dns_query = queries[0].get("rrname", "")
    elif isinstance(dns_block, dict):
        dns_query = dns_block.get("rrname", "")

    ts_raw = raw.get("timestamp", "")
    sev_int = int(alert.get("severity") or 3)

    return {
        "timestamp": ts_raw,
        "timestamp_dt": _parse_timestamp(ts_raw),
        "src_ip": raw.get("src_ip", ""),
        "src_port": str(raw.get("src_port") or ""),
        "dest_ip": raw.get("dest_ip", ""),
        "dest_port": str(raw.get("dest_port") or ""),
        "proto": raw.get("proto", ""),
        "app_proto": raw.get("app_proto", ""),
        "flow_id": str(raw.get("flow_id") or ""),
        "signature": alert.get("signature", ""),
        "signature_id": str(alert.get("signature_id") or ""),
        "category": alert.get("category", ""),
        "severity": _SEV_MAP.get(sev_int, "low"),
        "action": alert.get("action", ""),
        "dns_query": dns_query,
        "http_host": http_block.get("hostname", ""),
        "http_url": http_block.get("url", ""),
        "http_method": http_block.get("http_method", ""),
        "http_user_agent": http_block.get("http_user_agent", ""),
        "tls_sni": tls_block.get("sni", ""),
        "raw": json.dumps(raw, default=str),
    }


def _detect(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run detection logic across all normalised alert records.

    Returns a list of finding dicts with keys:
        severity, description, src_ip, dest_ip, signature
    """
    findings: List[Dict[str, Any]] = []

    # Group by source IP
    by_src: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        if a["src_ip"]:
            by_src[a["src_ip"]].append(a)

    for src_ip, recs in by_src.items():
        # 5+ alerts from the same source — aggressive scanning or attack
        if len(recs) >= 5:
            findings.append({
                "severity": "high",
                "description": (
                    f"{len(recs)} IDS alerts from source {src_ip} — "
                    "possible scanning or sustained attack"
                ),
                "src_ip": src_ip,
                "dest_ip": "",
                "signature": "",
            })

        # Multiple unique destinations from one source — port/host scan
        unique_dests = {r["dest_ip"] for r in recs if r["dest_ip"]}
        if len(unique_dests) >= 4:
            findings.append({
                "severity": "high",
                "description": (
                    f"Host {src_ip} contacted {len(unique_dests)} unique destinations — "
                    "possible lateral movement or scanning"
                ),
                "src_ip": src_ip,
                "dest_ip": "",
                "signature": "",
            })

    # High-severity (Suricata sev 1) individual alert signatures — deduplicated
    seen_sigs: set = set()
    for a in alerts:
        sig = a["signature"]
        if a["severity"] == "high" and sig and sig not in seen_sigs:
            seen_sigs.add(sig)
            findings.append({
                "severity": "high",
                "description": (
                    f"High-severity IDS alert: {sig} "
                    f"({a['src_ip']} → {a['dest_ip']})"
                ),
                "src_ip": a["src_ip"],
                "dest_ip": a["dest_ip"],
                "signature": sig,
            })

    # Category-based detections — deduplicated per category keyword
    seen_cats: set = set()
    for a in alerts:
        cat = a["category"].lower()
        sig = a["signature"]

        if any(kw in cat for kw in ("malware", "trojan", "backdoor", "exploit")):
            key = f"malware:{cat}"
            if key not in seen_cats:
                seen_cats.add(key)
                findings.append({
                    "severity": "critical",
                    "description": f"Malware/exploit IDS alert: {a['category']} — {sig}",
                    "src_ip": a["src_ip"],
                    "dest_ip": a["dest_ip"],
                    "signature": sig,
                })

        elif any(kw in cat for kw in ("c2", "command and control", "command-and-control",
                                       "c&c", "cnc", "beacon", "command_and_control")):
            key = f"c2:{cat}"
            if key not in seen_cats:
                seen_cats.add(key)
                findings.append({
                    "severity": "critical",
                    "description": f"Possible C2 traffic detected: {a['category']} — {sig}",
                    "src_ip": a["src_ip"],
                    "dest_ip": a["dest_ip"],
                    "signature": sig,
                })

        elif any(kw in cat for kw in ("dns", "domain")):
            key = f"dns:{cat}"
            if key not in seen_cats:
                seen_cats.add(key)
                query = a.get("dns_query", "")
                findings.append({
                    "severity": "medium",
                    "description": (
                        f"Suspicious DNS activity: {a['category']} — "
                        f"{query or sig}"
                    ),
                    "src_ip": a["src_ip"],
                    "dest_ip": a["dest_ip"],
                    "signature": sig,
                })

    return findings


def parse_suricata(
    content: bytes,
    filename: str,  # noqa: ARG001  (reserved for future format hints)
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse Suricata eve.json content (newline-delimited JSON).

    Returns:
        normalised_alerts – list of normalised alert record dicts
        findings          – list of suspicious finding dicts
    """
    text = content.decode("utf-8", errors="replace")
    alerts: List[Dict[str, Any]] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        rec = _normalise(raw)
        if rec is not None:
            alerts.append(rec)

    findings = _detect(alerts)
    return alerts, findings
