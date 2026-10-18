"""
Deterministic correlation engine for SOC Copilot Workbench.

Six correlation patterns — no AI, rule-based signal correlation:
  1. brute_force         — repeated failed logons followed by successful auth
  2. scripting_network   — script interpreter execution + suspicious network activity
  3. yara_process        — YARA hit correlated with process execution events
  4. ids_network         — Suricata IDS alert correlated with Zeek network findings
  5. dns_http            — suspicious DNS queries correlated with suspicious HTTP
  6. service_privilege   — service installation with privileged account activity
"""

import json
from collections import defaultdict
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult


_SCRIPTING_PROCESSES = {
    'powershell', 'powershell.exe',
    'cmd', 'cmd.exe',
    'wscript', 'wscript.exe',
    'cscript', 'cscript.exe',
    'mshta', 'mshta.exe',
    'regsvr32', 'regsvr32.exe',
    'rundll32', 'rundll32.exe',
    'bitsadmin', 'bitsadmin.exe',
}

_FAILED_LOGON_EVENTS = {'4625', '4776', '4771'}
_SUCCESS_LOGON_EVENTS = {'4624', '4648'}
_PROCESS_CREATE_EVENTS = {'4688', '1'}
_SERVICE_INSTALL_EVENTS = {'4697', '7045'}
_PRIVILEGE_EVENTS = {'4672', '4673'}


def run_correlation(db: Session, case_id: int) -> List[Dict[str, Any]]:
    """Run all patterns and return list of finding dicts ready for persistence."""
    norm_events = db.query(NormalizedEvent).filter(NormalizedEvent.case_id == case_id).all()
    yara_results = db.query(MalwareTriageResult).filter(MalwareTriageResult.case_id == case_id).all()
    net_results = db.query(NetworkAnalysisResult).filter(NetworkAnalysisResult.case_id == case_id).all()

    findings: List[Dict[str, Any]] = []
    findings.extend(_pattern_brute_force(norm_events))
    findings.extend(_pattern_scripting_network(norm_events, net_results))
    findings.extend(_pattern_yara_process(yara_results, norm_events))
    findings.extend(_pattern_ids_network(norm_events, net_results))
    findings.extend(_pattern_dns_http(net_results))
    findings.extend(_pattern_service_privilege(norm_events))

    return findings


# ── Pattern 1: Brute Force ────────────────────────────────────────────────────

def _pattern_brute_force(events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
    failed_by_host: Dict[str, List[int]] = defaultdict(list)
    success_by_host: Dict[str, List[int]] = defaultdict(list)
    proc_by_host: Dict[str, List[int]] = defaultdict(list)

    for ev in events:
        if ev.source != 'windows_logs':
            continue
        host = (ev.host or '').strip()
        if not host:
            continue
        eid = (ev.event_id or '').strip()
        desc = (ev.description or '').lower()
        pname = (ev.process_name or '').lower()

        if eid in _FAILED_LOGON_EVENTS or ('logon' in desc and 'fail' in desc):
            failed_by_host[host].append(ev.id)
        elif eid in _SUCCESS_LOGON_EVENTS:
            success_by_host[host].append(ev.id)

        if eid in _PROCESS_CREATE_EVENTS:
            proc_by_host[host].append(ev.id)
        elif any(s in pname for s in ('powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta')):
            proc_by_host[host].append(ev.id)

    results = []
    for host, fail_ids in failed_by_host.items():
        if len(fail_ids) < 3 or host not in success_by_host:
            continue

        has_proc = host in proc_by_host
        conf = 'high' if len(fail_ids) >= 5 else 'medium'

        ev_ids = fail_ids[:5] + success_by_host[host][:2]
        if has_proc:
            ev_ids += proc_by_host[host][:2]

        summary = (
            f'{len(fail_ids)} failed logon attempt{"s" if len(fail_ids) > 1 else ""} '
            f'on host "{host}", followed by a successful authentication.'
        )
        if has_proc:
            summary += ' Process execution also observed on the same host.'

        results.append({
            'title': 'Repeated Failed Logons Followed by Successful Authentication',
            'severity': 'high',
            'confidence': conf,
            'entities': [{'type': 'hostname', 'value': host}],
            'related_event_ids': ev_ids,
            'related_finding_ids': [],
            'summary': summary,
            'recommended_action': (
                'Review Active Directory for account lockout events on this host. '
                'Identify the source IP of the successful logon. '
                'Inspect processes launched after authentication.'
            ),
        })

    return results


# ── Pattern 2: Scripting Interpreter → Suspicious Network ────────────────────

def _pattern_scripting_network(
    events: List[NormalizedEvent],
    net_results: List[NetworkAnalysisResult],
) -> List[Dict[str, Any]]:
    scripting_event_ids: List[int] = []
    scripting_hosts: set = set()
    process_names: List[str] = []

    for ev in events:
        pname_lower = (ev.process_name or '').lower()
        if any(s in pname_lower for s in _SCRIPTING_PROCESSES):
            scripting_event_ids.append(ev.id)
            if ev.host:
                scripting_hosts.add(ev.host)
            p = (ev.process_name or '').strip()
            if p and p not in process_names:
                process_names.append(p)

    net_with_findings = [r for r in net_results if r.risk_score > 0]

    if not scripting_event_ids or not net_with_findings:
        return []

    # Collect hosts mentioned in Zeek findings
    net_hosts: set = set()
    for nr in net_with_findings:
        for f in json.loads(nr.findings or '[]'):
            h = f.get('host')
            if h:
                net_hosts.add(h)

    common = scripting_hosts & net_hosts
    conf = 'high' if common else 'medium'

    entities = [{'type': 'process', 'value': p} for p in process_names[:3]]
    for h in sorted(common)[:2]:
        entities.append({'type': 'hostname', 'value': h})

    net_finding_count = sum(len(json.loads(r.findings or '[]')) for r in net_with_findings)

    summary = (
        f'Script interpreter activity detected'
        f' ({", ".join(process_names[:2]) if process_names else "unknown"}). '
        f'{net_finding_count} suspicious network indicator{"s" if net_finding_count != 1 else ""} '
        f'found across {len(net_with_findings)} network log file{"s" if len(net_with_findings) != 1 else ""}.'
    )
    if common:
        summary += f' Common host{"s" if len(common) > 1 else ""}: {", ".join(sorted(common)[:2])}.'
    else:
        summary += ' No exact host overlap confirmed — correlation is case-level.'

    return [{
        'title': 'Script Interpreter Execution Correlated with Suspicious Network Activity',
        'severity': 'high',
        'confidence': conf,
        'entities': entities,
        'related_event_ids': scripting_event_ids[:5],
        'related_finding_ids': [r.id for r in net_with_findings[:3]],
        'summary': summary,
        'recommended_action': (
            'Review command-line arguments for encoded payloads or download cradles '
            '(e.g., -EncodedCommand, IEX, DownloadString). '
            'Cross-reference network destinations with threat intelligence. '
            'Inspect process parent-child chains for anomalous spawning.'
        ),
    }]


# ── Pattern 3: YARA Hit → Process Execution ───────────────────────────────────

def _pattern_yara_process(
    yara_results: List[MalwareTriageResult],
    events: List[NormalizedEvent],
) -> List[Dict[str, Any]]:
    suspicious_yara = [
        r for r in yara_results
        if r.risk_score > 0 and r.yara_matches and r.yara_matches != '[]'
    ]
    proc_events = [
        e for e in events
        if (e.event_id or '') in _PROCESS_CREATE_EVENTS or (e.process_name or '').strip()
    ]

    if not suspicious_yara or not proc_events:
        return []

    hashes = [r.sha256[:16] + '…' for r in suspicious_yara if r.sha256]

    rule_names: List[str] = []
    for r in suspicious_yara:
        for m in json.loads(r.yara_matches or '[]'):
            if isinstance(m, dict):
                rn = m.get('rule') or m.get('rule_name', '')
                if rn and rn not in rule_names:
                    rule_names.append(rn)

    proc_names: List[str] = []
    for e in proc_events:
        p = (e.process_name or '').strip()
        if p and p not in proc_names:
            proc_names.append(p)

    entities = [{'type': 'hash', 'value': h} for h in hashes[:3]]
    entities += [{'type': 'process', 'value': p} for p in proc_names[:3]]

    summary = (
        f'YARA analysis identified {len(suspicious_yara)} '
        f'file{"s" if len(suspicious_yara) > 1 else ""} with malicious indicators'
        + (f' (rules: {", ".join(rule_names[:2])})' if rule_names else '')
        + f'. {len(proc_events)} process execution event{"s" if len(proc_events) != 1 else ""}'
        f' present in the same case.'
    )

    return [{
        'title': 'Malicious File Indicator Correlated with Process Execution',
        'severity': 'high',
        'confidence': 'medium',
        'entities': entities,
        'related_event_ids': [e.id for e in proc_events[:5]],
        'related_finding_ids': [r.id for r in suspicious_yara[:3]],
        'summary': summary,
        'recommended_action': (
            'Quarantine files matching YARA signatures. '
            'Investigate processes launched from unusual paths (temp directories, user profiles). '
            'Check file hashes against threat intelligence databases.'
        ),
    }]


# ── Pattern 4: IDS Alert → Zeek Network ──────────────────────────────────────

def _pattern_ids_network(
    events: List[NormalizedEvent],
    net_results: List[NetworkAnalysisResult],
) -> List[Dict[str, Any]]:
    suricata_events = [e for e in events if e.source == 'suricata']
    net_with_findings = [r for r in net_results if r.risk_score > 0]

    if not suricata_events or not net_with_findings:
        return []

    suricata_ips: set = set()
    for e in suricata_events:
        if e.source_ip:
            suricata_ips.add(e.source_ip)
        if e.destination_ip:
            suricata_ips.add(e.destination_ip)

    zeek_hosts: set = set()
    for nr in net_with_findings:
        for f in json.loads(nr.findings or '[]'):
            h = f.get('host')
            if h:
                zeek_hosts.add(h)
        sd = json.loads(nr.summary_data or '{}')
        for t in sd.get('top_talkers', []):
            if t.get('host'):
                zeek_hosts.add(t['host'])

    common = suricata_ips & zeek_hosts
    conf = 'high' if common else 'medium'

    net_finding_count = sum(len(json.loads(r.findings or '[]')) for r in net_with_findings)

    entities: List[Dict[str, Any]] = []
    for ip in sorted(common)[:3]:
        entities.append({'type': 'ip', 'value': ip})
    if not entities:
        for ip in sorted(suricata_ips)[:2]:
            entities.append({'type': 'ip', 'value': ip})

    summary = (
        f'{len(suricata_events)} Suricata IDS alert{"s" if len(suricata_events) > 1 else ""} '
        f'correlated with {net_finding_count} network finding{"s" if net_finding_count != 1 else ""} '
        f'from Zeek log analysis.'
    )
    if common:
        summary += f' Overlapping host{"s" if len(common) > 1 else ""}: {", ".join(sorted(common)[:3])}.'

    return [{
        'title': 'IDS Alert Correlated with Suspicious Network Log Activity',
        'severity': 'high',
        'confidence': conf,
        'entities': entities,
        'related_event_ids': [e.id for e in suricata_events[:5]],
        'related_finding_ids': [r.id for r in net_with_findings[:3]],
        'summary': summary,
        'recommended_action': (
            'Review IDS signatures against Zeek connection logs to confirm attack traffic. '
            'Identify whether flagged hosts initiated or received the suspicious traffic. '
            'Check connection byte counts for data exfiltration indicators.'
        ),
    }]


# ── Pattern 5: Suspicious DNS → Suspicious HTTP ───────────────────────────────

def _pattern_dns_http(net_results: List[NetworkAnalysisResult]) -> List[Dict[str, Any]]:
    dns_with_findings = [r for r in net_results if r.log_type == 'dns' and r.risk_score > 0]
    http_with_findings = [r for r in net_results if r.log_type == 'http' and r.risk_score > 0]

    if not dns_with_findings or not http_with_findings:
        return []

    susp_domains: List[str] = []
    for r in dns_with_findings:
        sd = json.loads(r.summary_data or '{}')
        susp_domains += sd.get('dns_summary', {}).get('suspicious_domains', [])
    susp_domains = list(dict.fromkeys(susp_domains))

    susp_uris: List[str] = []
    http_finding_count = 0
    for r in http_with_findings:
        for f in json.loads(r.findings or '[]'):
            http_finding_count += 1
            if f.get('category') == 'suspicious_uri' and f.get('details'):
                susp_uris.append(f['details'])

    # Check if any suspicious domain appears in a flagged URI
    common_domains: List[str] = []
    for domain in susp_domains:
        for uri in susp_uris:
            if domain.lower() in uri.lower():
                if domain not in common_domains:
                    common_domains.append(domain)
                break

    conf = 'high' if common_domains else 'medium'
    entities = [{'type': 'domain', 'value': d} for d in susp_domains[:3]]

    dns_finding_count = sum(len(json.loads(r.findings or '[]')) for r in dns_with_findings)

    summary = (
        f'Suspicious DNS activity ({len(susp_domains)} suspicious domain{"s" if len(susp_domains) != 1 else ""}, '
        f'{dns_finding_count} DNS finding{"s" if dns_finding_count != 1 else ""}) '
        f'correlated with suspicious HTTP activity '
        f'({http_finding_count} HTTP finding{"s" if http_finding_count != 1 else ""}).'
    )
    if common_domains:
        summary += f' Common domain{"s" if len(common_domains) > 1 else ""}: {", ".join(common_domains[:2])}.'

    return [{
        'title': 'Suspicious DNS Queries Correlated with Suspicious HTTP Activity',
        'severity': 'high',
        'confidence': conf,
        'entities': entities,
        'related_event_ids': [],
        'related_finding_ids': [r.id for r in dns_with_findings[:2]] + [r.id for r in http_with_findings[:2]],
        'summary': summary,
        'recommended_action': (
            'Investigate resolved IP addresses for flagged DNS domains. '
            'Review HTTP request payloads and response codes for command-and-control indicators. '
            'Block suspicious domains at the DNS resolver and perimeter firewall.'
        ),
    }]


# ── Pattern 6: Service Installation → Privileged Access ──────────────────────

def _pattern_service_privilege(events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
    service_by_host: Dict[str, List[int]] = defaultdict(list)
    priv_by_host: Dict[str, List[int]] = defaultdict(list)
    service_desc_by_host: Dict[str, List[str]] = defaultdict(list)

    for ev in events:
        if ev.source != 'windows_logs':
            continue
        host = (ev.host or '').strip()
        if not host:
            continue
        eid = (ev.event_id or '').strip()
        ename = (ev.event_name or '').lower()
        desc = (ev.description or '').lower()

        if eid in _SERVICE_INSTALL_EVENTS or 'service' in ename:
            service_by_host[host].append(ev.id)
            if ev.description:
                service_desc_by_host[host].append(ev.description[:50])

        if eid in _PRIVILEGE_EVENTS or ('privilege' in desc and 'logon' in desc):
            priv_by_host[host].append(ev.id)

    results = []
    for host in set(service_by_host) & set(priv_by_host):
        entities: List[Dict[str, Any]] = [{'type': 'hostname', 'value': host}]
        if service_desc_by_host.get(host):
            entities.append({'type': 'service', 'value': service_desc_by_host[host][0]})

        summary = (
            f'New service installation detected on host "{host}" '
            f'({len(service_by_host[host])} service event{"s" if len(service_by_host[host]) > 1 else ""}) '
            f'alongside privileged account activity '
            f'({len(priv_by_host[host])} privilege event{"s" if len(priv_by_host[host]) > 1 else ""}).'
        )

        results.append({
            'title': 'Service Installation with Privileged Account Activity',
            'severity': 'medium',
            'confidence': 'medium',
            'entities': entities,
            'related_event_ids': service_by_host[host][:3] + priv_by_host[host][:3],
            'related_finding_ids': [],
            'summary': summary,
            'recommended_action': (
                'Review the service binary path for unsigned or unusual executables. '
                'Verify whether the service was installed by a legitimate administrator. '
                'Check for persistence mechanisms such as auto-start entries or scheduled tasks.'
            ),
        })

    return results
