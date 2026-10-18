"""
MITRE ATT&CK mapping engine for SOC Copilot Workbench.

Maps case evidence (normalized events, Sigma findings, YARA results,
network analysis, correlated findings) to MITRE ATT&CK techniques
using a local catalog at data/mitre_mapping.json.

All mapping is deterministic and evidence-backed — no AI, no guessing.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.correlated_finding import CorrelatedFinding

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_CATALOG_PATH = _REPO_ROOT / "data" / "mitre_mapping.json"

# Windows Event IDs
_FAILED_LOGON_EIDS = {'4625', '4776', '4771'}
_SERVICE_INSTALL_EIDS = {'4697', '7045'}
_SCHED_TASK_EIDS = {'4698', '4699', '4700', '4701'}
_CRED_ACCESS_EIDS = {'4648'}

# Encoded command indicators (matched against lowercased command line)
_ENCODED_INDICATORS = {'-encodedcommand', '-enc ', ' -ec ', 'encodedcommand'}

# Technique IDs — kept as constants to avoid magic strings
T_BRUTE_FORCE = 'T1110'
T_POWERSHELL = 'T1059.001'
T_SCRIPT_INTERP = 'T1059'
T_WIN_SERVICE = 'T1543.003'
T_OBFUSCATION = 'T1027'
T_DNS_C2 = 'T1071.004'
T_HTTP_C2 = 'T1071.001'
T_CRED_DUMP = 'T1003'
T_SCHED_TASK = 'T1053.005'

# Sigma tag prefix for ATT&CK technique references
_SIGMA_ATTACK_PREFIX = 'attack.t'


def _load_catalog() -> Dict[str, Dict[str, Any]]:
    """Load local ATT&CK technique catalog. Returns dict keyed by technique_id."""
    if not _CATALOG_PATH.exists():
        return {}
    with open(_CATALOG_PATH, encoding='utf-8') as f:
        return {e['technique_id']: e for e in json.load(f)}


def _conf_rank(c: str) -> int:
    return {'low': 0, 'medium': 1, 'high': 2}.get(c, 0)


def _add(
    evidence_map: Dict[str, List[Dict[str, str]]],
    confidence_map: Dict[str, str],
    tid: str,
    source: str,
    detail: str,
    confidence: str = 'medium',
) -> None:
    """Record a technique hit and upgrade confidence if the new value is higher."""
    evidence_map[tid].append({'source': source, 'detail': detail})
    if _conf_rank(confidence) > _conf_rank(confidence_map.get(tid, 'low')):
        confidence_map[tid] = confidence


def run_mitre_mapping(db: Session, case_id: int) -> List[Dict[str, Any]]:
    """Map all case evidence to MITRE ATT&CK techniques. Returns list of mapping dicts."""
    catalog = _load_catalog()

    evidence_map: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    confidence_map: Dict[str, str] = {}

    norm_events = db.query(NormalizedEvent).filter(NormalizedEvent.case_id == case_id).all()
    det_findings = db.query(DetectionFinding).filter(DetectionFinding.case_id == case_id).all()
    yara_results = db.query(MalwareTriageResult).filter(MalwareTriageResult.case_id == case_id).all()
    net_results = db.query(NetworkAnalysisResult).filter(NetworkAnalysisResult.case_id == case_id).all()
    corr_findings = db.query(CorrelatedFinding).filter(CorrelatedFinding.case_id == case_id).all()

    _map_normalized_events(norm_events, evidence_map, confidence_map)
    _map_sigma_findings(det_findings, evidence_map, confidence_map)
    _map_yara_results(yara_results, evidence_map, confidence_map)
    _map_network_results(net_results, evidence_map, confidence_map)
    _map_correlated_findings(corr_findings, evidence_map, confidence_map)

    results = []
    for tid, refs in evidence_map.items():
        tech = catalog.get(tid)
        if not tech:
            continue
        results.append({
            'tactic': tech['tactic'],
            'technique_id': tid,
            'technique_name': tech['technique_name'],
            'evidence_reference': refs[:8],
            'confidence': confidence_map.get(tid, 'medium'),
        })

    results.sort(key=lambda r: (r['tactic'], r['technique_id']))
    return results


# ── Per-source mapping helpers ─────────────────────────────────────────────────

def _map_normalized_events(
    events: List[NormalizedEvent],
    evidence_map: Dict,
    confidence_map: Dict,
) -> None:
    failed_logon_count = 0
    failed_logon_hosts: set = set()
    ps_hosts: set = set()
    script_procs: set = set()
    encoded_hosts: set = set()
    service_hosts: set = set()
    task_hosts: set = set()
    cred_hosts: set = set()
    suricata_descs: List[str] = []

    for ev in events:
        eid = (ev.event_id or '').strip()
        pname_lower = (ev.process_name or '').lower()
        cmdline_lower = (ev.command_line or '').lower()
        ename_lower = (ev.event_name or '').lower()
        host = ev.host or 'unknown'

        if eid in _FAILED_LOGON_EIDS:
            failed_logon_count += 1
            failed_logon_hosts.add(host)

        if any(p in pname_lower for p in ('powershell', 'pwsh')):
            ps_hosts.add(host)
        elif any(p in pname_lower for p in ('cmd.exe', 'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32', 'bitsadmin')):
            script_procs.add(ev.process_name or pname_lower)

        if any(ind in cmdline_lower for ind in _ENCODED_INDICATORS):
            encoded_hosts.add(host)

        if eid in _SERVICE_INSTALL_EIDS or 'service' in ename_lower:
            service_hosts.add(host)

        if eid in _SCHED_TASK_EIDS or 'scheduled task' in ename_lower:
            task_hosts.add(host)

        if eid in _CRED_ACCESS_EIDS:
            cred_hosts.add(host)

        if ev.source == 'suricata' and ev.description:
            suricata_descs.append(ev.description)

    if failed_logon_count:
        hosts_str = ', '.join(sorted(failed_logon_hosts)[:3])
        conf = 'high' if failed_logon_count >= 5 else 'medium'
        _add(evidence_map, confidence_map, T_BRUTE_FORCE, 'windows_event',
             f'{failed_logon_count} failed logon event{"s" if failed_logon_count != 1 else ""} on hosts: {hosts_str}',
             conf)

    for h in sorted(ps_hosts)[:3]:
        _add(evidence_map, confidence_map, T_POWERSHELL, 'windows_event',
             f'PowerShell execution on host {h}', 'high')

    for p in sorted(script_procs)[:3]:
        _add(evidence_map, confidence_map, T_SCRIPT_INTERP, 'windows_event',
             f'Scripting process: {p}')

    for h in sorted(encoded_hosts)[:3]:
        _add(evidence_map, confidence_map, T_OBFUSCATION, 'windows_event',
             f'Encoded command flag detected on host {h}', 'high')

    for h in sorted(service_hosts)[:3]:
        _add(evidence_map, confidence_map, T_WIN_SERVICE, 'windows_event',
             f'Service installation event on host {h}')

    for h in sorted(task_hosts)[:3]:
        _add(evidence_map, confidence_map, T_SCHED_TASK, 'windows_event',
             f'Scheduled task event on host {h}')

    for h in sorted(cred_hosts)[:3]:
        _add(evidence_map, confidence_map, T_CRED_DUMP, 'windows_event',
             f'Credential use event (EID 4648) on host {h}')

    for desc in suricata_descs[:10]:
        desc_lower = desc.lower()
        if 'brute' in desc_lower or 'login fail' in desc_lower:
            _add(evidence_map, confidence_map, T_BRUTE_FORCE, 'suricata', desc[:80])
        if 'dns' in desc_lower and ('tunnel' in desc_lower or 'suspicious' in desc_lower):
            _add(evidence_map, confidence_map, T_DNS_C2, 'suricata', desc[:80])
        if any(w in desc_lower for w in ('c2', 'beacon', 'command and control')):
            _add(evidence_map, confidence_map, T_HTTP_C2, 'suricata', desc[:80])


def _map_sigma_findings(
    det_findings: List[DetectionFinding],
    evidence_map: Dict,
    confidence_map: Dict,
) -> None:
    try:
        from socmat.integrations.sigma.loader import get_rule_by_id
    except ImportError:
        return

    for df in det_findings:
        rule = get_rule_by_id(df.rule_id)
        if not rule:
            continue
        for tag in rule.get('tags', []):
            if tag.lower().startswith(_SIGMA_ATTACK_PREFIX):
                tid = tag[len('attack.'):].upper()   # 'attack.t1059.001' → 'T1059.001'
                _add(evidence_map, confidence_map, tid, 'sigma_rule',
                     f'Sigma rule: {df.rule_title} (matched event {df.matched_event_id})', 'high')


def _map_yara_results(
    yara_results: List[MalwareTriageResult],
    evidence_map: Dict,
    confidence_map: Dict,
) -> None:
    for r in yara_results:
        if r.risk_score <= 0:
            continue
        rule_names: List[str] = []
        for m in json.loads(r.yara_matches or '[]'):
            if isinstance(m, dict):
                rn = m.get('rule') or m.get('rule_name', '')
                if rn and rn not in rule_names:
                    rule_names.append(rn)

        detail = f'YARA match on file {r.sha256[:16] if r.sha256 else "unknown"}…'
        if rule_names:
            detail += f' Rules: {", ".join(rule_names[:2])}'
        _add(evidence_map, confidence_map, T_OBFUSCATION, 'yara', detail)


def _map_network_results(
    net_results: List[NetworkAnalysisResult],
    evidence_map: Dict,
    confidence_map: Dict,
) -> None:
    for r in net_results:
        if r.risk_score <= 0:
            continue
        if r.log_type == 'dns':
            _add(evidence_map, confidence_map, T_DNS_C2, 'zeek',
                 f'Zeek DNS log: {r.risk_score} risk score, {r.total_records} records analysed')
        elif r.log_type == 'http':
            _add(evidence_map, confidence_map, T_HTTP_C2, 'zeek',
                 f'Zeek HTTP log: {r.risk_score} risk score, {r.total_records} records analysed')


def _map_correlated_findings(
    corr_findings: List[CorrelatedFinding],
    evidence_map: Dict,
    confidence_map: Dict,
) -> None:
    for cf in corr_findings:
        title_lower = (cf.title or '').lower()
        conf = cf.confidence

        if 'brute force' in title_lower or 'failed logon' in title_lower:
            _add(evidence_map, confidence_map, T_BRUTE_FORCE, 'correlation',
                 f'Correlated finding: {cf.title}', conf)

        if 'script' in title_lower or 'powershell' in title_lower:
            _add(evidence_map, confidence_map, T_POWERSHELL, 'correlation',
                 f'Correlated finding: {cf.title}', conf)
            _add(evidence_map, confidence_map, T_SCRIPT_INTERP, 'correlation',
                 f'Correlated finding: {cf.title}', conf)

        if 'service' in title_lower:
            _add(evidence_map, confidence_map, T_WIN_SERVICE, 'correlation',
                 f'Correlated finding: {cf.title}', conf)

        if 'dns' in title_lower:
            _add(evidence_map, confidence_map, T_DNS_C2, 'correlation',
                 f'Correlated finding: {cf.title}', conf)

        if 'http' in title_lower or 'ids alert' in title_lower:
            _add(evidence_map, confidence_map, T_HTTP_C2, 'correlation',
                 f'Correlated finding: {cf.title}', conf)

        if 'yara' in title_lower or 'malicious file' in title_lower:
            _add(evidence_map, confidence_map, T_OBFUSCATION, 'correlation',
                 f'Correlated finding: {cf.title}', conf)
