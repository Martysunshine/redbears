"""
PCAP / network traffic analysis module.

Parses PCAP and PCAPNG files statically — no live capture, no file execution.

Library: dpkt (pure-Python, read-only packet file parsing)
Supported: IPv4 traffic; PCAP and PCAPNG formats.
IPv6 packets are counted but not deeply parsed in this MVP.

Requirements: dpkt>=1.9.8
"""

import math
import socket
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone

try:
    import dpkt
except ImportError:
    dpkt = None

SAFE_NOTICE = (
    "PCAP analysis is static-only. Files are read but never executed. "
    "No live network capture is performed."
)

# Hard cap on packets to keep analysis time bounded (50 MB file ≈ ~80 k packets avg)
MAX_PACKETS = 100_000

# Ports commonly used by C2 frameworks or unusual services
_C2_PORTS = {4444, 4445, 5555, 6666, 7777, 8888, 9001, 9002, 9090, 31337}

# Boring internal traffic ports to exclude from "suspicious port" alerts
_COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 3306, 3389, 5432, 8080, 8443,
}


def _error_result(msg: str) -> dict:
    return {
        "total_packets": 0, "total_bytes": 0,
        "duration_seconds": 0.0, "start_time": None,
        "protocol_counts": {}, "top_talkers": [],
        "dns_queries": [], "http_requests": [], "tls_hosts": [],
        "findings": [], "risk_score": 0, "summary": msg, "error": msg,
    }


def _ip4(raw: bytes) -> str:
    try:
        return socket.inet_ntoa(raw)
    except Exception:
        return ""


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _extract_tls_sni(data: bytes) -> str:
    """Return the SNI hostname from a TLS ClientHello, or empty string."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return ""
        record_len = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + record_len:
            return ""
        payload = data[5: 5 + record_len]
        if len(payload) < 4 or payload[0] != 0x01:
            return ""
        hs_len = struct.unpack("!I", b"\x00" + payload[1:4])[0]
        if len(payload) < 4 + hs_len:
            return ""
        hello = payload[4: 4 + hs_len]

        offset = 2 + 32  # skip version + random
        if len(hello) <= offset:
            return ""
        session_len = hello[offset]
        offset += 1 + session_len
        if len(hello) < offset + 2:
            return ""
        cipher_len = struct.unpack("!H", hello[offset: offset + 2])[0]
        offset += 2 + cipher_len
        if len(hello) < offset + 1:
            return ""
        comp_len = hello[offset]
        offset += 1 + comp_len
        if len(hello) < offset + 2:
            return ""
        ext_total = struct.unpack("!H", hello[offset: offset + 2])[0]
        offset += 2
        ext_end = offset + ext_total

        while offset + 4 <= ext_end and offset + 4 <= len(hello):
            ext_type = struct.unpack("!H", hello[offset: offset + 2])[0]
            ext_len = struct.unpack("!H", hello[offset + 2: offset + 4])[0]
            offset += 4
            if ext_type == 0x0000:  # SNI
                ext_data = hello[offset: offset + ext_len]
                if len(ext_data) >= 5 and ext_data[2] == 0x00:
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if len(ext_data) >= 5 + name_len:
                        return ext_data[5: 5 + name_len].decode("ascii", errors="ignore")
            offset += ext_len
    except Exception:
        pass
    return ""


def _parse_dns_query(data: bytes, src_ip: str) -> dict:
    """Extract DNS query name from a UDP payload. Returns {} on failure."""
    try:
        dns = dpkt.dns.DNS(data)
        if dns.qr != dpkt.dns.DNS_Q or not dns.qd:
            return {}
        qname = dns.qd[0].name
        qtype = dns.qd[0].type
        qtype_name = {
            1: "A", 28: "AAAA", 5: "CNAME", 15: "MX",
            2: "NS", 16: "TXT", 255: "ANY",
        }.get(qtype, str(qtype))
        return {"src_ip": src_ip, "query": qname, "query_type": qtype_name}
    except Exception:
        return {}


def _parse_http_request(data: bytes, src_ip: str, dst_ip: str) -> dict:
    """Try to parse an HTTP request from TCP payload. Returns {} on failure."""
    try:
        req = dpkt.http.Request(data)
        host = req.headers.get("host", dst_ip)
        ua = req.headers.get("user-agent", "")
        auth = req.headers.get("authorization", "")
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "method": req.method,
            "host": str(host)[:200],
            "uri": str(req.uri)[:300],
            "user_agent": str(ua)[:200],
            "has_basic_auth": str(auth).lower().startswith("basic "),
        }
    except Exception:
        return {}


def _compute_risk_score(findings: list) -> int:
    score = 0
    for f in findings:
        sev = f.get("severity", "low")
        score += {"critical": 20, "high": 10, "medium": 5, "low": 1}.get(sev, 0)
    return min(score, 100)


def _generate_summary(
    total_packets: int,
    total_bytes: int,
    n_conversations: int,
    n_dns: int,
    n_http: int,
    n_tls: int,
    findings: list,
    duration: float,
) -> str:
    parts = [
        f"Analysed {total_packets:,} packets "
        f"({total_bytes / 1024 / 1024:.1f} MB) "
        f"over {duration:.1f}s.",
        f"{n_conversations} unique conversations.",
    ]
    if n_dns:
        parts.append(f"{n_dns} DNS queries observed.")
    if n_http:
        parts.append(f"{n_http} HTTP requests observed.")
    if n_tls:
        parts.append(f"{n_tls} unique TLS/SNI hostnames.")
    high = sum(1 for f in findings if f.get("severity") in ("high", "critical"))
    if high:
        parts.append(f"{high} high-severity finding(s) detected.")
    elif findings:
        parts.append(f"{len(findings)} suspicious indicator(s) detected.")
    else:
        parts.append("No suspicious patterns detected.")
    return " ".join(parts)


def parse_pcap(filepath: str, max_packets: int = MAX_PACKETS) -> dict:
    """
    Parse a PCAP or PCAPNG file and return a structured analysis dict.

    The file is read but never executed.
    Processing stops after max_packets to keep analysis time bounded.

    Returns a dict with keys:
        total_packets, total_bytes, duration_seconds, start_time,
        protocol_counts, top_talkers, dns_queries, http_requests,
        tls_hosts, findings, risk_score, summary, error
    """
    if dpkt is None:
        return _error_result(
            "dpkt library is not installed. Add 'dpkt>=1.9.8' to requirements.txt."
        )

    conversations: dict = {}    # flow_key -> {proto, src_ip, src_port, dst_ip, dst_port, packets, bytes, first_seen}
    src_bytes: dict = defaultdict(int)
    src_packets: dict = defaultdict(int)
    src_dests: dict = defaultdict(set)
    src_dst_ports: dict = defaultdict(set)   # for port-scan detection

    dns_queries: list = []
    dns_seen: set = set()
    http_requests: list = []
    tls_hosts: list = []
    tls_seen: set = set()

    beacon_ts: dict = defaultdict(list)    # dst_ip -> [timestamps]

    total_packets = 0
    total_bytes = 0
    proto_counts: dict = {"TCP": 0, "UDP": 0, "ICMP": 0, "IPv6": 0, "other": 0}
    first_ts = None
    last_ts = None

    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            f.seek(0)

            # PCAPNG starts with 0x0a0d0d0a; classic PCAP with d4c3b2a1 or a1b2c3d4
            if magic == b"\x0a\x0d\x0d\x0a":
                reader = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)

            for ts, buf in reader:
                if total_packets >= max_packets:
                    break
                total_packets += 1
                pkt_len = len(buf)
                total_bytes += pkt_len
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                ip = eth.data
                # IPv6 — count only for now
                if isinstance(ip, dpkt.ip6.IP6):
                    proto_counts["IPv6"] += 1
                    continue
                if not isinstance(ip, dpkt.ip.IP):
                    proto_counts["other"] += 1
                    continue

                src_ip = _ip4(ip.src)
                dst_ip = _ip4(ip.dst)
                if not src_ip or not dst_ip:
                    continue

                src_bytes[src_ip] += pkt_len
                src_packets[src_ip] += 1
                src_dests[src_ip].add(dst_ip)

                transport = ip.data

                if isinstance(transport, dpkt.tcp.TCP):
                    proto_counts["TCP"] += 1
                    sport = transport.sport
                    dport = transport.dport
                    src_dst_ports[src_ip].add(dport)

                    flow_key = ("tcp", src_ip, sport, dst_ip, dport)
                    if flow_key not in conversations:
                        conversations[flow_key] = {
                            "proto": "tcp", "src_ip": src_ip, "src_port": sport,
                            "dst_ip": dst_ip, "dst_port": dport,
                            "packets": 0, "bytes": 0,
                            "first_seen": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                        }
                    conversations[flow_key]["packets"] += 1
                    conversations[flow_key]["bytes"] += pkt_len

                    payload = bytes(transport.data)
                    if payload:
                        if dport == 80:
                            req = _parse_http_request(payload, src_ip, dst_ip)
                            if req:
                                http_requests.append(req)
                        if dport == 443:
                            sni = _extract_tls_sni(payload)
                            if sni and sni not in tls_seen:
                                tls_hosts.append({"host": sni, "dst_ip": dst_ip})
                                tls_seen.add(sni)

                    if dport in (80, 443, 4444, 8080, 8443):
                        beacon_ts[dst_ip].append(ts)

                elif isinstance(transport, dpkt.udp.UDP):
                    proto_counts["UDP"] += 1
                    sport = transport.sport
                    dport = transport.dport

                    flow_key = ("udp", src_ip, sport, dst_ip, dport)
                    if flow_key not in conversations:
                        conversations[flow_key] = {
                            "proto": "udp", "src_ip": src_ip, "src_port": sport,
                            "dst_ip": dst_ip, "dst_port": dport,
                            "packets": 0, "bytes": 0,
                            "first_seen": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                        }
                    conversations[flow_key]["packets"] += 1
                    conversations[flow_key]["bytes"] += pkt_len

                    payload = bytes(transport.data)
                    if dport == 53 and payload:
                        q = _parse_dns_query(payload, src_ip)
                        if q:
                            dedup_key = (q["query"], q["query_type"])
                            if dedup_key not in dns_seen:
                                dns_queries.append(q)
                                dns_seen.add(dedup_key)

                elif isinstance(transport, dpkt.icmp.ICMP):
                    proto_counts["ICMP"] += 1
                else:
                    proto_counts["other"] += 1

    except Exception as exc:
        return _error_result(f"Failed to parse PCAP: {exc}")

    # Top talkers (by bytes sent)
    top_talkers = [
        {
            "host": ip,
            "packets": src_packets[ip],
            "bytes_sent": src_bytes[ip],
            "destinations": len(src_dests[ip]),
        }
        for ip in sorted(src_bytes, key=lambda x: src_bytes[x], reverse=True)[:10]
    ]

    # Suspicious patterns
    findings = _detect_suspicious(
        src_bytes, src_dests, src_dst_ports,
        dns_queries, http_requests, beacon_ts, conversations,
    )

    duration = (last_ts - first_ts) if (first_ts and last_ts) else 0.0
    risk_score = _compute_risk_score(findings)

    summary = _generate_summary(
        total_packets, total_bytes, len(conversations),
        len(dns_queries), len(http_requests), len(tls_hosts),
        findings, duration,
    )

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": round(duration, 2),
        "start_time": (
            datetime.fromtimestamp(first_ts, tz=timezone.utc).isoformat()
            if first_ts else None
        ),
        "protocol_counts": proto_counts,
        "top_talkers": top_talkers,
        "dns_queries": dns_queries[:200],
        "http_requests": http_requests[:200],
        "tls_hosts": tls_hosts[:100],
        "conversations": list(conversations.values())[:500],
        "findings": findings,
        "risk_score": risk_score,
        "summary": summary,
        "error": None,
    }


def _detect_suspicious(
    src_bytes: dict,
    src_dests: dict,
    src_dst_ports: dict,
    dns_queries: list,
    http_requests: list,
    beacon_ts: dict,
    conversations: dict,
) -> list:
    findings = []
    seen_keys: set = set()

    def _add(category, severity, description, host=None, details=None):
        key = (category, host or "", description[:60])
        if key in seen_keys:
            return
        seen_keys.add(key)
        findings.append({
            "category": category,
            "severity": severity,
            "description": description,
            "host": host,
            "details": details,
        })

    # Port scan: one host contacted many distinct dst_ports
    for ip, ports in src_dst_ports.items():
        if len(ports) > 25:
            _add(
                "Port Scan", "high",
                f"Host {ip} contacted {len(ports)} distinct destination ports",
                host=ip,
                details=f"{len(ports)} unique ports",
            )

    # Large outbound transfer (> 10 MB from one host)
    for ip, b in sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:5]:
        if b > 10 * 1024 * 1024:
            _add(
                "Large Transfer", "medium",
                f"Host {ip} sent {b / 1024 / 1024:.1f} MB — possible data exfiltration",
                host=ip,
                details=f"{b / 1024 / 1024:.1f} MB",
            )

    # High fan-out: one host contacted many unique destinations
    for ip, dests in src_dests.items():
        if len(dests) > 30:
            _add(
                "High Fan-Out", "medium",
                f"Host {ip} contacted {len(dests)} unique destinations",
                host=ip,
                details=f"{len(dests)} unique destinations",
            )

    # Beaconing: regular check-in intervals
    for dst_ip, timestamps in beacon_ts.items():
        if len(timestamps) < 5:
            continue
        timestamps_sorted = sorted(timestamps)
        intervals = [
            timestamps_sorted[i + 1] - timestamps_sorted[i]
            for i in range(len(timestamps_sorted) - 1)
        ]
        if not intervals:
            continue
        avg = sum(intervals) / len(intervals)
        if avg <= 0:
            continue
        max_dev = max(abs(iv - avg) for iv in intervals)
        # Regular beacon: deviation < 20% of average interval, 30 s – 1 hr range
        if max_dev / avg < 0.20 and 30 < avg < 3600:
            _add(
                "Beaconing", "high",
                f"Regular beaconing to {dst_ip} every ~{avg:.0f}s "
                f"({len(timestamps)} connections)",
                host=dst_ip,
                details=f"avg interval {avg:.0f}s, {len(timestamps)} connections",
            )

    # DGA candidates: high-entropy DNS queries
    dga_domains = []
    for q in dns_queries:
        domain = q.get("query", "")
        label = domain.split(".")[0] if "." in domain else domain
        if len(label) > 10 and _entropy(label) > 3.5:
            dga_domains.append(domain)
    if dga_domains:
        _add(
            "DGA Candidates", "high",
            f"{len(dga_domains)} high-entropy DNS queries — possible domain generation algorithm",
            host=None,
            details=", ".join(dga_domains[:3]),
        )

    # Cleartext HTTP credentials
    basic_auth_reqs = [r for r in http_requests if r.get("has_basic_auth")]
    if basic_auth_reqs:
        hosts = list({r["host"] for r in basic_auth_reqs})
        _add(
            "Cleartext Credentials", "medium",
            f"HTTP Basic Auth credentials transmitted in cleartext to {len(hosts)} host(s)",
            host=hosts[0] if hosts else None,
            details=", ".join(hosts[:3]),
        )

    # Traffic on suspicious C2 ports
    for key, flow in conversations.items():
        dport = flow.get("dst_port", 0)
        if dport in _C2_PORTS and dport not in _COMMON_PORTS and flow.get("packets", 0) >= 3:
            _add(
                "Suspicious Port", "high",
                f"Traffic on C2-associated port {dport}: "
                f"{flow['src_ip']} → {flow['dst_ip']}",
                host=flow["src_ip"],
                details=f"port {dport}, {flow['packets']} packets",
            )

    return findings
