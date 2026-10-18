"""
Suspicious network behavior analysis for Zeek log records.
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

_SUSPICIOUS_TLDS = {'.xyz', '.tk', '.top', '.pw', '.cc', '.bit', '.onion', '.info', '.biz'}

_COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587,
    993, 995, 3306, 3389, 5432, 8080, 8443, 8888,
}

_SUSPICIOUS_AGENT_FRAGMENTS = [
    'sqlmap', 'nikto', 'masscan', 'zgrab', 'nuclei',
    'python-requests', 'go-http-client', 'nmap', 'scanner',
    'mozilla/4.0 (compatible; msie 6.0',
]

_SUSPICIOUS_URI_PATTERNS = [
    '/cmd', '/shell', '/exec', '/webshell', '/.env',
    '/wp-login', '/xmlrpc', '/../', '/etc/passwd', '/bin/bash',
]

_FAILED_CONN_STATES = {'REJ', 'RSTO', 'RSTOS0', 'OTH', 'S0', 'SHR', 'SH'}


# ── conn.log ──────────────────────────────────────────────────────────────────

def analyze_conn_log(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    host_destinations: Dict[str, set] = defaultdict(set)
    host_bytes: Dict[str, int] = defaultdict(int)
    host_connections: Dict[str, int] = defaultdict(int)
    unusual_port_src: Dict[int, List[str]] = defaultdict(list)
    rejected_by_host: Dict[str, int] = defaultdict(int)

    for r in records:
        src = r.get('id.orig_h', '')
        dst = r.get('id.resp_h', '')
        dst_port_raw = r.get('id.resp_p', '')
        state = r.get('conn_state', '')
        orig_bytes_raw = r.get('orig_bytes', '') or '0'

        if not src:
            continue

        if dst:
            host_destinations[src].add(dst)
        host_connections[src] += 1

        try:
            host_bytes[src] += int(orig_bytes_raw)
        except ValueError:
            pass

        try:
            port = int(dst_port_raw)
            if 1024 < port < 65535 and port not in _COMMON_PORTS:
                unusual_port_src[port].append(src)
        except ValueError:
            pass

        if state in _FAILED_CONN_STATES:
            rejected_by_host[src] += 1

    findings: List[Dict[str, Any]] = []

    for host, dsts in host_destinations.items():
        if len(dsts) >= 20:
            sev = 'high' if len(dsts) >= 50 else 'medium'
            findings.append({
                'category': 'many_destinations',
                'severity': sev,
                'description': f'{host} contacted {len(dsts)} unique destinations',
                'host': host,
                'count': len(dsts),
                'details': None,
            })

    for host, total in host_bytes.items():
        if total > 50 * 1024 * 1024:
            mb = total // (1024 * 1024)
            findings.append({
                'category': 'high_outbound_volume',
                'severity': 'medium',
                'description': f'{host} sent {mb} MB of outbound data',
                'host': host,
                'count': total,
                'details': None,
            })

    for host, cnt in rejected_by_host.items():
        if cnt >= 10:
            findings.append({
                'category': 'failed_connections',
                'severity': 'low',
                'description': f'{host} has {cnt} failed/rejected connections',
                'host': host,
                'count': cnt,
                'details': None,
            })

    for port, srcs in sorted(unusual_port_src.items(), key=lambda x: -len(x[1]))[:5]:
        unique_srcs = list(dict.fromkeys(srcs))
        if len(unique_srcs) >= 3:
            findings.append({
                'category': 'unusual_port',
                'severity': 'low',
                'description': f'{len(unique_srcs)} hosts used unusual port {port}',
                'host': None,
                'count': len(unique_srcs),
                'details': f'port {port}',
            })

    top_talkers = [
        {
            'host': host,
            'connection_count': cnt,
            'total_bytes': host_bytes.get(host, 0),
            'destinations': len(host_destinations.get(host, set())),
        }
        for host, cnt in sorted(host_connections.items(), key=lambda x: -x[1])[:10]
    ]

    return {'top_talkers': top_talkers, 'findings': findings, 'total_records': len(records)}


# ── dns.log ───────────────────────────────────────────────────────────────────

def analyze_dns_log(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    domain_counts: Counter = Counter()
    nxdomain_by_host: Dict[str, int] = defaultdict(int)
    long_domains: List[str] = []
    suspicious_domains: List[str] = []

    for r in records:
        query = r.get('query', '')
        rcode = r.get('rcode_name', '')
        src = r.get('id.orig_h', '')

        if not query:
            continue

        domain_counts[query] += 1

        if len(query) > 50:
            long_domains.append(query)

        parts = query.rstrip('.').split('.')
        if len(parts) >= 2:
            tld = '.' + parts[-1].lower()
            if tld in _SUSPICIOUS_TLDS:
                suspicious_domains.append(query)

        if rcode in ('NXDOMAIN', 'SERVFAIL') and src:
            nxdomain_by_host[src] += 1

    findings: List[Dict[str, Any]] = []

    if long_domains:
        unique_long = list(dict.fromkeys(long_domains))
        findings.append({
            'category': 'long_domain_query',
            'severity': 'medium',
            'description': f'{len(long_domains)} queries with unusually long domain names (possible DNS tunneling)',
            'host': None,
            'count': len(long_domains),
            'details': unique_long[0][:80] if unique_long else None,
        })

    if suspicious_domains:
        unique_susp = list(dict.fromkeys(suspicious_domains))
        findings.append({
            'category': 'suspicious_tld',
            'severity': 'medium',
            'description': f'{len(unique_susp)} queries to suspicious TLDs',
            'host': None,
            'count': len(unique_susp),
            'details': ', '.join(unique_susp[:3]),
        })

    for host, cnt in nxdomain_by_host.items():
        if cnt >= 20:
            findings.append({
                'category': 'high_nxdomain_rate',
                'severity': 'low',
                'description': f'{host} generated {cnt} failed DNS responses',
                'host': host,
                'count': cnt,
                'details': None,
            })

    for domain, cnt in domain_counts.most_common(3):
        if cnt >= 50:
            findings.append({
                'category': 'repeated_dns_query',
                'severity': 'low',
                'description': f'Domain "{domain}" queried {cnt} times (possible beaconing)',
                'host': None,
                'count': cnt,
                'details': domain[:80],
            })

    return {
        'top_queried': [d for d, _ in domain_counts.most_common(10)],
        'suspicious_domains': list(dict.fromkeys(suspicious_domains))[:20],
        'total_queries': len(records),
        'unique_domains': len(domain_counts),
        'findings': findings,
        'total_records': len(records),
    }


# ── http.log ──────────────────────────────────────────────────────────────────

def analyze_http_log(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    host_counts: Counter = Counter()
    user_agents: Counter = Counter()
    suspicious_uri_hits: List[tuple] = []

    for r in records:
        host = r.get('host', '')
        ua = r.get('user_agent', '')
        uri = r.get('uri', '')

        if host:
            host_counts[host] += 1
        user_agents[ua] += 1

        if uri:
            uri_lower = uri.lower()
            for pattern in _SUSPICIOUS_URI_PATTERNS:
                if pattern in uri_lower:
                    suspicious_uri_hits.append((uri, host))
                    break

    suspicious_agents: List[str] = []
    for ua in user_agents:
        ua_lower = ua.lower()
        for frag in _SUSPICIOUS_AGENT_FRAGMENTS:
            if frag in ua_lower:
                suspicious_agents.append(ua[:80])
                break

    findings: List[Dict[str, Any]] = []

    if suspicious_uri_hits:
        findings.append({
            'category': 'suspicious_uri',
            'severity': 'high',
            'description': f'{len(suspicious_uri_hits)} HTTP requests to suspicious URIs',
            'host': suspicious_uri_hits[0][1] or None,
            'count': len(suspicious_uri_hits),
            'details': suspicious_uri_hits[0][0][:80],
        })

    if suspicious_agents:
        findings.append({
            'category': 'suspicious_user_agent',
            'severity': 'medium',
            'description': f'{len(suspicious_agents)} suspicious user agent(s) detected',
            'host': None,
            'count': len(suspicious_agents),
            'details': suspicious_agents[0],
        })

    empty_ua = user_agents.get('', 0)
    if empty_ua >= 5:
        findings.append({
            'category': 'missing_user_agent',
            'severity': 'low',
            'description': f'{empty_ua} HTTP requests with no user agent',
            'host': None,
            'count': empty_ua,
            'details': None,
        })

    return {
        'top_hosts': [h for h, _ in host_counts.most_common(10)],
        'suspicious_agents': suspicious_agents[:10],
        'total_requests': len(records),
        'unique_hosts': len(host_counts),
        'findings': findings,
        'total_records': len(records),
    }


# ── shared ────────────────────────────────────────────────────────────────────

def compute_risk_score(findings: List[Dict[str, Any]]) -> int:
    _points = {'critical': 40, 'high': 20, 'medium': 10, 'low': 5}
    return min(sum(_points.get(f.get('severity', 'low'), 5) for f in findings), 100)


def generate_summary(
    original_filename: str,
    log_type: str,
    total_records: int,
    findings: List[Dict[str, Any]],
    risk_score: int,
) -> str:
    if risk_score == 0:
        return (
            f"No suspicious indicators detected in '{original_filename}' "
            f"({total_records} {log_type} records). Static analysis only."
        )

    high = [f for f in findings if f.get('severity') in ('high', 'critical')]
    med = [f for f in findings if f.get('severity') == 'medium']

    parts = [f"Analyzed '{original_filename}' ({total_records} {log_type} records)."]
    if high:
        parts.append(f"{len(high)} high-severity finding(s) detected.")
    if med:
        parts.append(f"{len(med)} medium-severity finding(s) detected.")
    if findings:
        parts.append(f"Top finding: {findings[0]['description']}.")
    parts.append("Static analysis only.")
    return ' '.join(parts)
