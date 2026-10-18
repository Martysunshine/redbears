"""
Security Incident Report generator for SOC Copilot Workbench.

Produces a structured 23-section Markdown report from all case data.
Reports are saved to reports/generated/ at the repository root.
All content is derived from stored case data — no AI or invention.
"""

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

from sqlalchemy.orm import Session

from socmat.services.api.models.analyst_note import AnalystNote
from socmat.services.api.models.case import Case
from socmat.services.api.models.case_playbook import CasePlaybook
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.ioc import Ioc
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.pcap_analysis_result import PcapAnalysisResult
from socmat.services.api.models.correlated_finding import CorrelatedFinding
from socmat.services.api.models.case_mitre_mapping import CaseMitreMapping
from socmat.services.api.models.finding_disposition import FindingDisposition
from socmat.services.api.report_readiness import compute_readiness

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_REPORTS_DIR = _REPO_ROOT / "reports" / "generated"

# Technique-level recommended actions
_TECH_RECS = {
    'T1110': 'Enforce account lockout policies and review privileged account activity for signs of compromise.',
    'T1003': 'Check for credential dumping tools (e.g. Mimikatz, ProcDump) and rotate any exposed credentials immediately.',
    'T1059': 'Review scripting engine usage policies; enable Script Block Logging and process creation auditing (EID 4688).',
    'T1059.001': 'Enable PowerShell Constrained Language Mode and Script Block Logging (EID 4103/4104).',
    'T1543.003': 'Audit newly installed services; verify binary paths against known-good baselines.',
    'T1053.005': 'Review scheduled tasks for unauthorized entries, especially those running as SYSTEM.',
    'T1027': 'Submit suspicious files to sandbox analysis and expand YARA/AV signature coverage.',
    'T1071.004': 'Investigate DNS query anomalies; consider DNS sinkholing or blocking of high-entropy domains.',
    'T1071.001': 'Review proxy/firewall logs for suspicious HTTP/HTTPS connections to uncategorized destinations.',
}

# Technique-level detection improvement suggestions
_TECH_DETECTION = {
    'T1110': 'Add Sigma rules for repeated failed authentication (EID 4625/4776). Alert on > 5 failures within 1 minute.',
    'T1003': 'Monitor for LSASS memory access (EID 4663) and known credential dumping tool process names.',
    'T1059': 'Ensure full command-line logging is enabled in process creation auditing (EID 4688).',
    'T1059.001': 'Enable PowerShell Module Logging (EID 4103) and Script Block Logging (EID 4104) via Group Policy.',
    'T1543.003': 'Alert on new service creation (EID 7045) from non-administrator accounts or unusual binary paths.',
    'T1053.005': 'Monitor scheduled task creation (EID 4698) especially with SYSTEM or privileged principal.',
    'T1027': 'Expand YARA ruleset to cover common obfuscation and packing techniques; tune string entropy detection.',
    'T1071.004': 'Deploy DNS monitoring; alert on high-entropy domain queries and unusually high query volumes.',
    'T1071.001': 'Implement TLS/SSL inspection on egress traffic; alert on connections to newly registered or uncategorized domains.',
}


def generate_report(db: Session, case_id: int) -> Tuple[str, str]:
    """Generate a Markdown incident report. Returns (relative_report_path, summary)."""
    case = db.query(Case).filter(Case.id == case_id).first()
    evidence = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id)
        .order_by(Evidence.uploaded_at)
        .all()
    )
    timeline = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp)
        .all()
    )
    norm_events = db.query(NormalizedEvent).filter(NormalizedEvent.case_id == case_id).all()
    det_findings = (
        db.query(DetectionFinding)
        .filter(DetectionFinding.case_id == case_id)
        .order_by(DetectionFinding.created_at)
        .all()
    )
    yara_results = (
        db.query(MalwareTriageResult)
        .filter(MalwareTriageResult.case_id == case_id)
        .order_by(MalwareTriageResult.created_at)
        .all()
    )
    net_results = (
        db.query(NetworkAnalysisResult)
        .filter(NetworkAnalysisResult.case_id == case_id)
        .order_by(NetworkAnalysisResult.created_at)
        .all()
    )
    corr_findings = (
        db.query(CorrelatedFinding)
        .filter(CorrelatedFinding.case_id == case_id)
        .order_by(CorrelatedFinding.created_at)
        .all()
    )
    mitre_mappings = (
        db.query(CaseMitreMapping)
        .filter(CaseMitreMapping.case_id == case_id)
        .order_by(CaseMitreMapping.tactic, CaseMitreMapping.technique_id)
        .all()
    )
    playbooks = (
        db.query(CasePlaybook)
        .filter(CasePlaybook.case_id == case_id)
        .order_by(CasePlaybook.created_at)
        .all()
    )
    notes = (
        db.query(AnalystNote)
        .filter(AnalystNote.case_id == case_id)
        .order_by(AnalystNote.created_at)
        .all()
    )
    iocs = (
        db.query(Ioc)
        .filter(Ioc.case_id == case_id)
        .order_by(Ioc.ioc_type, Ioc.normalized_value)
        .all()
    )
    dispositions = (
        db.query(FindingDisposition)
        .filter(FindingDisposition.case_id == case_id)
        .order_by(FindingDisposition.created_at)
        .all()
    )

    readiness = compute_readiness(db, case_id)

    md = _build_report(
        case, evidence, timeline, norm_events,
        det_findings, yara_results, net_results, corr_findings, mitre_mappings,
        playbooks, notes, iocs, dispositions=dispositions, readiness=readiness, db=db,
    )

    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"case_{case_id}_report_{ts}.md"
    report_path = _REPORTS_DIR / filename
    report_path.write_text(md, encoding='utf-8')

    relative_path = str(report_path.relative_to(_REPO_ROOT)).replace('\\', '/')
    summary = _build_summary(case, det_findings, yara_results, corr_findings, mitre_mappings)
    return relative_path, summary


# ── Formatting helpers ──────────────────────────────────────────────────────────

def _fmt_dt(dt_or_str) -> str:
    """Format a datetime or ISO string to readable form."""
    if dt_or_str is None:
        return 'Unknown'
    if isinstance(dt_or_str, str):
        try:
            dt_or_str = datetime.fromisoformat(dt_or_str)
        except Exception:
            return dt_or_str
    try:
        return dt_or_str.strftime('%d %b %Y %H:%M UTC')
    except Exception:
        return str(dt_or_str)


def _load_json(value, fallback=None):
    if fallback is None:
        fallback = []
    if value is None:
        return fallback
    if isinstance(value, (list, dict)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return fallback


# ── Section builders ────────────────────────────────────────────────────────────

def _build_report(
    case, evidence, timeline, norm_events,
    det_findings, yara_results, net_results, corr_findings, mitre_mappings,
    playbooks=None, notes=None, iocs=None, dispositions=None, readiness=None, db=None,
) -> str:
    lines: List[str] = []

    def add(text: str = '') -> None:
        lines.append(text)

    now_str = datetime.utcnow().strftime('%d %b %Y %H:%M UTC')
    yara_hits = [r for r in yara_results if r.risk_score > 0]
    high_det = [f for f in det_findings if f.severity in ('high', 'critical')]
    high_corr = [c for c in corr_findings if c.confidence == 'high']

    # ── Header ──────────────────────────────────────────────────────────────────
    add('# Security Incident Report')
    add('')
    add(f'**Case ID:** #{case.id}  ')
    add(f'**Generated:** {now_str}  ')
    add(f'**Report Format:** Markdown')
    add('')
    add('---')

    # ── 1. Executive Summary ────────────────────────────────────────────────────
    add('')
    add('## 1. Executive Summary')
    add('')
    summary_parts = [
        f'This report covers investigation case **{case.title}** (#{case.id}), '
        f'opened on {_fmt_dt(case.created_at)} with a **{case.severity.upper()}** '
        f'severity classification.',
    ]
    if case.description:
        summary_parts.append(f' {case.description}')
    summary_parts.append(
        f'\n\nAs of {now_str}, the case status is **{case.status.upper()}**. '
        f'The investigation reviewed {len(evidence)} evidence file{"s" if len(evidence) != 1 else ""}, '
        f'identified {len(det_findings)} Sigma detection finding{"s" if len(det_findings) != 1 else ""}, '
    )
    if yara_hits:
        summary_parts.append(
            f'{len(yara_hits)} YARA triage hit{"s" if len(yara_hits) != 1 else ""}, '
        )
    summary_parts.append(
        f'and correlated {len(corr_findings)} finding{"s" if len(corr_findings) != 1 else ""}. '
    )
    if mitre_mappings:
        tactics = len({m.tactic for m in mitre_mappings})
        summary_parts.append(
            f'MITRE ATT&CK mapping identified {len(mitre_mappings)} '
            f'technique{"s" if len(mitre_mappings) != 1 else ""} across '
            f'{tactics} tactic{"s" if tactics != 1 else ""}.'
        )
    add(''.join(summary_parts))

    # ── 2. Incident Classification ──────────────────────────────────────────────
    add('')
    add('## 2. Incident Classification')
    add('')
    add('| Field | Value |')
    add('|-------|-------|')
    add(f'| Case Title | {case.title} |')
    add(f'| Case ID | #{case.id} |')
    add(f'| Source | {case.source.replace("_", " ").title()} |')
    add(f'| Status | {case.status.upper()} |')
    add(f'| Created | {_fmt_dt(case.created_at)} |')
    add(f'| Last Updated | {_fmt_dt(case.updated_at)} |')

    # ── 3. Severity ─────────────────────────────────────────────────────────────
    add('')
    add('## 3. Severity')
    add('')
    sev_icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(case.severity, '⚪')
    add(f'**Overall Severity:** {sev_icon} {case.severity.upper()}')
    add('')
    if high_det:
        add(f'- High/critical Sigma detections: {len(high_det)}')
    if yara_hits:
        add(f'- Positive YARA triage results: {len(yara_hits)}')
    if high_corr:
        add(f'- High-confidence correlated findings: {len(high_corr)}')
    high_mitre = [m for m in mitre_mappings if m.confidence == 'high']
    if high_mitre:
        add(f'- High-confidence MITRE technique mappings: {len(high_mitre)}')
    if not any([high_det, yara_hits, high_corr, high_mitre]):
        add('No high-confidence indicators present at time of report generation.')

    # ── 4. Affected Assets ──────────────────────────────────────────────────────
    add('')
    add('## 4. Affected Assets')
    add('')
    add('| Asset | Value |')
    add('|-------|-------|')
    add(f'| Host | {case.affected_host or "Not specified"} |')
    add(f'| User | {case.affected_user or "Not specified"} |')
    add(f'| IP Address | {case.affected_ip or "Not specified"} |')

    # ── 5. Timeline of Events ───────────────────────────────────────────────────
    add('')
    add('## 5. Timeline of Events')
    add('')
    if timeline:
        for te in timeline:
            sev_tag = f'[{te.severity.upper()}] ' if te.severity else ''
            add(f'- **{_fmt_dt(te.timestamp)}** — {sev_tag}[{te.source}/{te.event_type}] {te.description}')
    else:
        add('No timeline events recorded.')

    # ── 6. Attack Narrative ─────────────────────────────────────────────────────
    add('')
    add('## 6. Attack Narrative')
    add('')
    if timeline:
        narrative = _build_attack_narrative(timeline)
        add(narrative)
        add('')
        add('*This narrative is derived from recorded timeline events only. No events were inferred or fabricated.*')
    else:
        add('No timeline events recorded. Run analysis modules to populate timeline data.')

    # ── 7. Evidence Reviewed ────────────────────────────────────────────────────
    add('')
    add('## 7. Evidence Reviewed')
    add('')
    if evidence:
        add('| # | Original Filename | Type | Size | SHA-256 (prefix) | Uploaded |')
        add('|---|-------------------|------|------|------------------|----------|')
        for i, ev in enumerate(evidence, 1):
            size_kb = f'{ev.file_size // 1024} KB' if ev.file_size else '—'
            sha_prefix = (ev.sha256[:16] + '…') if ev.sha256 else '—'
            add(f'| {i} | `{ev.original_filename}` | {ev.file_type or "—"} | {size_kb} | `{sha_prefix}` | {_fmt_dt(ev.uploaded_at)} |')
    else:
        add('No evidence files uploaded.')

    # ── 8. Detection Findings ───────────────────────────────────────────────────
    add('')
    add('## 8. Detection Findings (Sigma)')
    add('')
    if det_findings:
        for df in det_findings:
            sev_label = f'[{df.severity.upper()}] ' if df.severity else ''
            add(f'### {sev_label}{df.rule_title}')
            add('')
            add(f'- **Rule ID:** `{df.rule_id}`')
            if df.event_id_str:
                add(f'- **Windows Event ID:** {df.event_id_str}')
            if df.event_timestamp:
                add(f'- **Event Time:** {_fmt_dt(df.event_timestamp)}')
            if df.match_reason:
                add(f'- **Match Reason:** {df.match_reason}')
            add('')
    else:
        add('No Sigma detection findings.')

    # ── 9. Malware Triage Findings ──────────────────────────────────────────────
    add('')
    add('## 9. Malware Triage Findings (YARA)')
    add('')
    if yara_results:
        for r in yara_results:
            label = f'`{r.sha256[:16]}…`' if r.sha256 else f'Evidence ID {r.evidence_id}'
            add(f'### File: {label}')
            add('')
            add(f'- **Risk Score:** {r.risk_score}')
            if r.sha256:
                add(f'- **SHA-256:** `{r.sha256}`')
            if r.file_type:
                add(f'- **File Type:** {r.file_type}')
            if r.file_size:
                add(f'- **File Size:** {r.file_size // 1024} KB')
            matches = _load_json(r.yara_matches, [])
            if matches:
                rule_names = [
                    m.get('rule') or m.get('rule_name', '')
                    for m in matches if isinstance(m, dict)
                ]
                rule_names = [n for n in rule_names if n]
                if rule_names:
                    add(f'- **Matched Rules:** {", ".join(rule_names)}')
            if r.summary:
                add(f'- **Summary:** {r.summary}')
            add('')
    else:
        add('No YARA triage findings.')

    # ── 10. Network Analysis Findings ───────────────────────────────────────────
    add('')
    add('## 10. Network Analysis Findings (Zeek)')
    add('')
    if net_results:
        for r in net_results:
            add(f'### {r.log_type.upper()} Log Analysis')
            add('')
            add(f'- **Risk Score:** {r.risk_score}')
            add(f'- **Total Records:** {r.total_records}')
            summary_data = _load_json(r.summary_data, {})
            if isinstance(summary_data, dict):
                for k, v in list(summary_data.items())[:6]:
                    add(f'- **{k.replace("_", " ").title()}:** {v}')
            if r.summary:
                add(f'- **Analysis Notes:** {r.summary}')
            findings = _load_json(r.findings, [])
            if findings:
                add(f'- **Notable Findings:**')
                for f_item in findings[:5]:
                    if isinstance(f_item, dict):
                        desc = f_item.get('description') or f_item.get('detail') or str(f_item)
                        add(f'  - {desc}')
            add('')
    else:
        add('No network analysis results.')

    # ── 11. Correlated Findings ─────────────────────────────────────────────────
    add('')
    add('## 11. Correlated Findings')
    add('')
    if corr_findings:
        for cf in corr_findings:
            add(f'### [{cf.confidence.upper()}] {cf.title}')
            add('')
            if cf.summary:
                add(cf.summary)
                add('')
            entities = _load_json(cf.entities, [])
            if entities:
                ent_parts = []
                for e in entities[:6]:
                    if isinstance(e, dict):
                        ent_parts.append(f'{e.get("type", "entity")}: `{e.get("value", "")}`')
                if ent_parts:
                    add(f'**Entities:** {", ".join(ent_parts)}')
                    add('')
            if cf.recommended_action:
                add(f'**Recommended Action:** {cf.recommended_action}')
                add('')
    else:
        add('No correlated findings.')

    # ── 12. MITRE ATT&CK Mapping ────────────────────────────────────────────────
    add('')
    add('## 12. MITRE ATT&CK Mapping')
    add('')
    if mitre_mappings:
        tactic_groups: dict = defaultdict(list)
        for m in mitre_mappings:
            tactic_groups[m.tactic].append(m)

        for tactic, techniques in tactic_groups.items():
            add(f'### {tactic}')
            add('')
            add('| Technique ID | Technique Name | Confidence |')
            add('|-------------|----------------|------------|')
            for t in techniques:
                add(f'| `{t.technique_id}` | {t.technique_name} | {t.confidence.upper()} |')
            add('')
    else:
        add('No MITRE ATT&CK mappings generated. Run ATT&CK mapping on the case first.')

    # ── 13. Investigation Entity Map Summary ───────────────────────────────────
    add('')
    add('## 13. Investigation Entity Map Summary')
    add('')
    _graph_hosts: list = []
    _graph_users: list = []
    _graph_ips: list = []
    _graph_processes: list = []
    _graph_techs: list = []

    from collections import Counter as _Counter

    _host_ctr: _Counter = _Counter()
    _user_ctr: _Counter = _Counter()
    _ip_ctr: _Counter = _Counter()
    _proc_ctr: _Counter = _Counter()
    for _ev in norm_events:
        if _ev.host:
            _host_ctr[_ev.host] += 1
        if _ev.user:
            _user_ctr[_ev.user] += 1
        for _ip in [_ev.source_ip, _ev.destination_ip]:
            if _ip:
                _ip_ctr[_ip] += 1
        if _ev.process_name:
            _proc_ctr[_ev.process_name] += 1
    _graph_hosts = [h for h, _ in _host_ctr.most_common(10)]
    _graph_users = [u for u, _ in _user_ctr.most_common(10)]
    _graph_ips = [ip for ip, _ in _ip_ctr.most_common(10)]
    _graph_processes = [p for p, _ in _proc_ctr.most_common(8)]
    _graph_techs = [(m.technique_id, m.technique_name, m.tactic) for m in mitre_mappings]

    if any([_graph_hosts, _graph_users, _graph_ips, _graph_processes, _graph_techs, corr_findings]):
        if _graph_hosts:
            add(f'**Key Affected Hosts:** {", ".join(f"`{h}`" for h in _graph_hosts)}')
            add('')
        if _graph_users:
            add(f'**Key Users:** {", ".join(f"`{u}`" for u in _graph_users)}')
            add('')
        if _graph_ips:
            add(f'**Key IP Addresses:** {", ".join(f"`{ip}`" for ip in _graph_ips)}')
            add('')
        if _graph_processes:
            add(f'**Key Processes:** {", ".join(f"`{p}`" for p in _graph_processes)}')
            add('')
        if _graph_techs:
            add('**Key MITRE Techniques:**')
            add('')
            for tid, tname, tactic in _graph_techs[:10]:
                add(f'- `{tid}` {tname} ({tactic})')
            add('')
        if corr_findings:
            add('**Key Relationships (from correlation engine):**')
            add('')
            for cf in corr_findings[:5]:
                add(f'- {cf.title}: {cf.summary or "See correlated findings section."}')
            add('')
    else:
        add('No entity data available. Run analysis modules to populate the investigation map.')

    # ── 14. Indicators of Compromise ───────────────────────────────────────────
    add('')
    add('## 14. Indicators of Compromise')
    add('')
    reportable_iocs = [i for i in (iocs or []) if "benign" not in (json.loads(i.tags_json) if i.tags_json else [])]
    if reportable_iocs:
        _IOC_GROUP_LABELS = [
            ("IP Addresses",      {"ipv4", "ipv6"}),
            ("Domains",           {"domain"}),
            ("URLs",              {"url"}),
            ("File Hashes",       {"md5", "sha1", "sha256"}),
            ("Hosts / Users",     {"hostname", "username", "email"}),
            ("Processes & Paths", {"process_name", "file_path", "registry_path"}),
            ("Other",             {"port", "user_agent", "mutex"}),
        ]
        shown_any = False
        for group_label, group_types in _IOC_GROUP_LABELS:
            group_items = [i for i in reportable_iocs if i.ioc_type in group_types]
            if not group_items:
                continue
            add(f'### {group_label}')
            add('')
            add('| Type | Value | Confidence | Tags | Source |')
            add('|------|-------|------------|------|--------|')
            for i in group_items[:30]:
                tags = json.loads(i.tags_json) if i.tags_json else []
                tag_str = ", ".join(tags) if tags else "—"
                src = i.source_type.replace("_", " ").title() if i.source_type else "manual"
                add(f'| `{i.ioc_type}` | `{i.value}` | {i.confidence} | {tag_str} | {src} |')
            if len(group_items) > 30:
                add(f'*…{len(group_items) - 30} more {group_label.lower()} not shown.*')
            add('')
            shown_any = True
        if not shown_any:
            add('No non-benign IOCs recorded.')
    else:
        add('No IOCs extracted. Run "Extract IOCs" on the case to populate this section.')

    # ── 15. Analyst Playbook Progress ──────────────────────────────────────────
    add('')
    add('## 15. Analyst Playbook Progress')
    add('')
    if playbooks:
        for pb in playbooks:
            status_label = pb.status.replace("_", " ").title()
            add(f'### {pb.name}')
            add('')
            add(f'- **Status:** {status_label}')
            add(f'- **Progress:** {pb.progress_percent}%')
            add('')
            if pb.steps:
                for step in sorted(pb.steps, key=lambda s: s.step_order):
                    icon = {'done': '✓', 'skipped': '⏭', 'needs_review': '🔍'}.get(step.status, '○')
                    add(f'  {icon} **{step.step_order}. {step.title}** `[{step.status}]`')
                    if step.analyst_notes:
                        add(f'     - *Analyst notes:* {step.analyst_notes}')
                add('')
    else:
        add('No investigation playbooks were used for this case.')

    # ── 16. Analyst Notes and Observations ─────────────────────────────────────
    add('')
    add('## 16. Analyst Notes and Observations')
    add('')
    if notes:
        # Priority order for report inclusion
        _PRIORITY = ["escalation_note", "decision", "false_positive_reason", "report_note",
                     "hypothesis", "observation", "general"]
        _LABEL = {
            "escalation_note": "Escalation",
            "decision": "Decision",
            "false_positive_reason": "False Positive",
            "report_note": "Report Note",
            "hypothesis": "Hypothesis",
            "observation": "Observation",
            "general": "General",
        }
        sorted_notes = sorted(notes, key=lambda n: (_PRIORITY.index(n.note_type) if n.note_type in _PRIORITY else 99, n.created_at))
        for n in sorted_notes[:20]:
            label = _LABEL.get(n.note_type, n.note_type.replace("_", " ").title())
            author = n.author_name or "Analyst"
            entity_ref = f" ({n.entity_type.replace('_', ' ')} #{n.entity_id})" if n.entity_id else ""
            add(f'**[{label}]{entity_ref}** — *{author}* ({_fmt_dt(n.created_at)})')
            add('')
            add(f'> {n.body}')
            add('')
        if len(notes) > 20:
            add(f'*{len(notes) - 20} additional note(s) not shown. Review all notes in the case detail view.*')
            add('')
    else:
        add('No analyst notes recorded for this case.')

    # ── 17. Finding Review and Disposition ─────────────────────────────────────
    add('')
    add('## 17. Finding Review and Disposition')
    add('')
    if dispositions:
        _disp_label = {
            "true_positive": "True Positive",
            "false_positive": "False Positive",
            "benign": "Benign",
            "suspicious": "Suspicious",
            "needs_review": "Needs Review",
            "escalated": "Escalated",
            "duplicate": "Duplicate",
            "insufficient_data": "Insufficient Data",
        }
        _disp_groups: dict = {}
        for _d in dispositions:
            _disp_groups.setdefault(_d.disposition, []).append(_d)

        _order = ["true_positive", "false_positive", "benign", "suspicious",
                  "escalated", "duplicate", "insufficient_data", "needs_review"]
        for _key in _order:
            if _key not in _disp_groups:
                continue
            _group = _disp_groups[_key]
            _lbl = _disp_label.get(_key, _key.replace("_", " ").title())
            add(f'**{_lbl} ({len(_group)})**')
            add('')
            for _d in _group:
                _ft = _d.finding_type.replace("_", " ").title()
                _who = f" — *{_d.analyst_name}*" if _d.analyst_name else ""
                _conf = f" [confidence: {_d.confidence}]"
                add(f'- {_ft} #{_d.finding_id}{_conf}{_who}')
                if _d.reason:
                    add(f'  - Reason: {_d.reason}')
                if _d.follow_up_action:
                    add(f'  - Follow-up: {_d.follow_up_action}')
            add('')

        _fp_count = len(_disp_groups.get("false_positive", []))
        _nr_count = len(_disp_groups.get("needs_review", []))
        if _fp_count > 0:
            add(
                f'*{_fp_count} finding(s) marked as false positive. '
                'These are documented here for auditing purposes and excluded from severity analysis.*'
            )
            add('')
        if _nr_count > 0:
            add(f'*{_nr_count} finding(s) still require analyst review before this case can be closed.*')
            add('')
    else:
        add('No findings have been dispositioned for this case. Review all detection findings and record analyst judgment.')

    # ── 18. Analyst Assessment ──────────────────────────────────────────────────
    add('')
    add('## 18. Analyst Assessment')
    add('')
    has_data = any([det_findings, yara_hits, net_results, corr_findings, mitre_mappings])
    if not has_data:
        add(
            'Insufficient evidence has been analyzed to form a definitive assessment. '
            'Upload evidence files and run analysis modules before generating a final report.'
        )
    else:
        assessment: List[str] = []
        if case.severity in ('high', 'critical'):
            assessment.append(
                f'This is a **{case.severity.upper()} severity** incident requiring prompt investigation and response. '
            )
        if high_det:
            assessment.append(
                f'Sigma detection rules flagged {len(high_det)} high-severity '
                f'event{"s" if len(high_det) != 1 else ""}, indicating active malicious activity patterns. '
            )
        if yara_hits:
            assessment.append(
                f'YARA static triage identified {len(yara_hits)} suspicious '
                f'file{"s" if len(yara_hits) != 1 else ""} matching malware signatures. '
            )
        tactic_names = sorted({m.tactic for m in mitre_mappings})
        if tactic_names:
            assessment.append(
                f'Attack activity spans the following ATT&CK tactics: **{", ".join(tactic_names)}**. '
            )
        if high_corr:
            assessment.append(
                f'High-confidence correlation indicates multi-stage activity: '
                f'{"; ".join(c.title for c in high_corr[:3])}. '
            )
        if not assessment:
            assessment.append(
                'Evidence reviewed. No high-confidence indicators detected at this time. '
                'Manual analyst review is recommended before closing.'
            )
        add(''.join(assessment))

    # ── 19. Recommended Actions ─────────────────────────────────────────────────
    add('')
    add('## 19. Recommended Actions')
    add('')
    rec_actions: List[str] = []
    seen_recs: set = set()

    for cf in corr_findings:
        if cf.recommended_action and cf.recommended_action not in seen_recs:
            rec_actions.append(cf.recommended_action)
            seen_recs.add(cf.recommended_action)

    for tid, rec in _TECH_RECS.items():
        if any(m.technique_id == tid for m in mitre_mappings) and rec not in seen_recs:
            rec_actions.append(rec)
            seen_recs.add(rec)

    if rec_actions:
        for rec in rec_actions[:12]:
            add(f'- {rec}')
    else:
        add('- Review all findings and apply appropriate containment measures based on case severity.')
        add('- Escalate to senior analyst or IR team if indicators of compromise are confirmed.')
        add('- Preserve evidence and document all investigative steps taken.')

    # ── 20. Detection Opportunities ─────────────────────────────────────────────
    add('')
    add('## 20. Detection Opportunities')
    add('')
    if mitre_mappings:
        add('Based on ATT&CK techniques identified in this case, the following monitoring improvements are recommended:')
        add('')
        shown = False
        for m in mitre_mappings:
            suggestion = _TECH_DETECTION.get(m.technique_id)
            if suggestion:
                add(f'- **{m.technique_id}** ({m.technique_name}): {suggestion}')
                shown = True
        if not shown:
            add('No specific detection improvements identified for the mapped techniques.')
    else:
        add('Run MITRE ATT&CK mapping first to identify detection coverage gaps.')

    # ── 21. Detection Coverage and Telemetry Gaps ───────────────────────────────
    add('')
    add('## 21. Detection Coverage and Telemetry Gaps')
    add('')
    _triggered_rule_ids = {df.rule_id for df in det_findings}
    _total_sigma = 0
    _all_mitre_techniques: set = set()
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _rr = _Path(__file__).resolve().parent.parent.parent
        if str(_rr) not in _sys.path:
            _sys.path.insert(0, str(_rr))
        from socmat.integrations.sigma.loader import get_cached_rules as _get_sigma
        _sigma_rules = _get_sigma()
        _total_sigma = len(_sigma_rules)
        for _sr in _sigma_rules:
            for _tag in _sr.get("tags", []):
                if _tag.lower().startswith("attack.t"):
                    _all_mitre_techniques.add(_tag.replace("attack.", "").upper())
    except Exception:
        _sigma_rules = []

    _covered_mitre: set = set()
    for _df in det_findings:
        _rule_obj = next((r for r in _sigma_rules if r["id"] == _df.rule_id), None)
        if _rule_obj:
            for _tag in _rule_obj.get("tags", []):
                if _tag.lower().startswith("attack.t"):
                    _covered_mitre.add(_tag.replace("attack.", "").upper())

    _cov_pct = round(len(_covered_mitre) / len(_all_mitre_techniques) * 100, 1) if _all_mitre_techniques else 0.0

    add(f'**Rules Triggered:** {len(_triggered_rule_ids)} of {_total_sigma} loaded Sigma rules fired on case evidence.')
    add('')
    add(f'**MITRE Coverage:** {len(_covered_mitre)} of {len(_all_mitre_techniques)} technique(s) covered by triggered rules ({_cov_pct}%).')
    add('')

    _available_log_sources: List[str] = []
    if norm_events:
        _available_log_sources.append('Windows Event Logs')
    _net_log_types = {r.log_type for r in net_results} if net_results else set()
    if any(lt in ("conn", "dns", "http") or "zeek" in lt for lt in _net_log_types):
        _available_log_sources.append('Zeek Network Logs')
    if any("suricata" in lt for lt in _net_log_types):
        _available_log_sources.append('Suricata IDS Alerts')
    _has_pcap = (
        db.query(PcapAnalysisResult.id).filter(PcapAnalysisResult.case_id == case.id).first()
        if db else None
    )
    if _has_pcap:
        _available_log_sources.append('PCAP Network Capture')
    if yara_results:
        _available_log_sources.append('YARA Static Analysis')

    if _available_log_sources:
        add('**Available Log Sources:**')
        add('')
        for _src in sorted(_available_log_sources):
            add(f'- {_src}')
        add('')
    else:
        add('No log sources collected for this case.')
        add('')

    _all_expected_sources = {
        'Windows Event Logs', 'Zeek Network Logs', 'Suricata IDS Alerts',
        'PCAP Network Capture', 'YARA Static Analysis',
    }
    _missing_sources = sorted(_all_expected_sources - set(_available_log_sources))
    if _missing_sources:
        add('**Missing Log Sources:**')
        add('')
        for _ms in _missing_sources:
            add(f'- {_ms} — not collected for this case')
        add('')

    _event_ids: set = {str(e.event_id) for e in norm_events if e.event_id}
    _has_dns_logs = any("dns" in (lt or "").lower() for lt in _net_log_types)
    _has_http_logs = any("http" in (lt or "").lower() for lt in _net_log_types)
    if _has_pcap and db:
        _pcap_r = db.query(PcapAnalysisResult).filter(
            PcapAnalysisResult.case_id == case.id
        ).first()
        if _pcap_r and _pcap_r.dns_queries:
            _has_dns_logs = True
        if _pcap_r and _pcap_r.http_requests:
            _has_http_logs = True

    _GAP_CHECKS = [
        ("PowerShell Script Block Logs (EID 4103/4104)", not {"4103", "4104"}.intersection(_event_ids), "T1059.001, T1027"),
        ("Sysmon EID 1 / Windows EID 4688 (Process Creation)", not {"1", "4688"}.intersection(_event_ids), "T1059, T1036, T1055"),
        ("Sysmon EID 3 (Network Connections)", "3" not in _event_ids, "T1071, T1021, T1090"),
        ("DNS Query Logs", not _has_dns_logs, "T1071.004, T1568.002"),
        ("Proxy / HTTP Logs", not _has_http_logs, "T1071.001, T1041"),
        ("EDR Process Tree / Memory Telemetry", True, "T1055, T1027.002"),
        ("Authentication Logs (EID 4624/4625/4768/4769)", not {"4624", "4625", "4768", "4769", "4776"}.intersection(_event_ids), "T1110, T1078, T1558"),
    ]
    _gaps = [(name, techs) for name, absent, techs in _GAP_CHECKS if absent]
    if _gaps:
        add('**Telemetry Gaps Identified:**')
        add('')
        add('| Missing Log Source | Related MITRE Techniques |')
        add('|--------------------|--------------------------|')
        for _gap_name, _gap_techs in _gaps:
            add(f'| {_gap_name} | {_gap_techs} |')
        add('')
        add(
            '*These gaps represent log sources not present in this case. '
            'Collecting them would improve detection confidence for future investigations. '
            'This assessment reflects available case data only — absence of evidence '
            'does not indicate absence of compromise.*'
        )
    else:
        add('No major telemetry gaps identified based on available case data.')
    add('')

    # ── 22. Final Status ────────────────────────────────────────────────────────
    add('')
    add('## 22. Final Status')
    add('')
    status_desc = {
        'open': 'Investigation has been opened. Initial triage is pending.',
        'investigating': 'Active investigation is in progress. Evidence collection and analysis is ongoing.',
        'contained': 'The incident has been contained. Post-incident review and lessons-learned documentation is recommended.',
        'escalated': 'The incident has been escalated to senior analyst or IR team for further action.',
        'closed': 'The investigation is closed. Evidence and findings have been fully documented.',
    }
    add(f'**Case Status:** {case.status.upper()}')
    add('')
    add(status_desc.get(case.status, 'Status not recognized.'))
    add('')
    add(f'*Report generated on {now_str} by SOC Copilot Workbench.*')

    # ── 23. Known Limitations ───────────────────────────────────────────────────
    add('')
    add('## 23. Known Limitations')
    add('')
    add(
        'This report was generated by SOC Copilot Workbench, a local-first defensive analysis tool. '
        'The following limitations apply to this report:'
    )
    add('')
    add('- **Local-first scope:** All analysis runs on locally uploaded evidence. '
        'No live SIEM, EDR, or threat intelligence integrations were used unless explicitly configured.')
    add('- **Static evidence only:** Uploaded files are analysed statically; '
        'no dynamic execution, sandbox detonation, or live network capture was performed.')
    add('- **AI-generated content:** The AI assistant context is advisory only. '
        'All findings, dispositions, and analyst notes in this report were produced by '
        'deterministic analysis modules or human analyst input — not by AI inference.')
    add('- **Detection coverage:** Sigma and YARA rules are bundled with the tool. '
        'Rule gaps may cause missed detections; refer to the Detection Coverage section for identified gaps.')
    add('- **Correlation engine:** Correlation findings are based on heuristics applied '
        'to evidence in this case only. Cross-case or environment-wide correlation is not performed.')
    add('- **Timeline completeness:** The timeline reflects only events parsed from uploaded evidence. '
        'Events not present in submitted files will not appear in this report.')
    add('- **No external validation:** IOC values, IP addresses, and domains are extracted from '
        'local evidence and are not validated against live threat intelligence feeds.')
    add('')

    # ── 24. Report Completeness ─────────────────────────────────────────────────
    add('')
    add('## 24. Report Completeness')
    add('')
    if readiness:
        _score = readiness.get("total_score", 0)
        _grade = readiness.get("grade", "unknown")
        _grade_upper = _grade.upper()
        add(f'**Readiness Score:** {_score}% — {_grade_upper}')
        add('')
        _missing = readiness.get("missing_checks", [])
        if _missing:
            add('**Missing or incomplete items:**')
            add('')
            for _m in _missing:
                add(f'- {_m["name"]}: {_m["description"]}')
            add('')
        _warns = readiness.get("warnings", [])
        if _warns:
            add('**Limitations and warnings:**')
            add('')
            for _w in _warns:
                add(f'- {_w}')
            add('')
        _recs = readiness.get("recommendations", [])
        if _recs:
            add('**Recommended improvements:**')
            add('')
            for _r in _recs:
                add(f'- {_r}')
            add('')
        if not _missing and not _warns:
            add('All major report completeness checks passed.')
            add('')
        add(
            '*This completeness assessment is based on what data was present in the case '
            'at report generation time. Missing items do not imply absence of threat — '
            'investigation may still be in progress.*'
        )
    else:
        add('Readiness score not available for this report.')
    add('')

    return '\n'.join(lines)


def _build_attack_narrative(timeline: list) -> str:
    """Generate a prose attack narrative from timeline events."""
    if not timeline:
        return ""

    first_ts = _fmt_dt(timeline[0].timestamp)
    last_ts = _fmt_dt(timeline[-1].timestamp)
    segments = [
        f"The investigation timeline spans from **{first_ts}** to **{last_ts}** "
        f"and contains **{len(timeline)}** recorded event(s)."
    ]

    auth_events = [
        e for e in timeline
        if any(k in (e.event_type or "").lower() for k in ("logon", "login", "authentication", "4624", "4625"))
        or any(k in (e.description or "").lower() for k in ("login", "logon", "authentication failure"))
    ]
    exec_events = [
        e for e in timeline
        if any(k in (e.event_type or "").lower() for k in ("process", "exec", "powershell", "4688"))
        or "powershell" in (e.description or "").lower()
    ]
    net_events = [
        e for e in timeline
        if e.source in ("zeek", "suricata", "pcap")
        or any(k in (e.event_type or "").lower() for k in ("network", "dns", "http", "c2", "beacon"))
    ]
    detect_events = [e for e in timeline if e.source in ("sigma", "yara", "correlation")]

    if auth_events:
        first_auth = auth_events[0]
        segments.append(
            f"Authentication activity was first recorded at **{_fmt_dt(first_auth.timestamp)}**: "
            f"{first_auth.description}"
        )
        failed = [e for e in auth_events if "fail" in (e.description or "").lower() or "4625" in (e.event_type or "")]
        success = [e for e in auth_events if "success" in (e.description or "").lower() or "4624" in (e.event_type or "")]
        if failed and success:
            segments.append(
                f"Failed authentication attempts ({len(failed)}) were followed by a successful logon, "
                "which may indicate a successful account compromise."
            )

    if exec_events:
        first_exec = exec_events[0]
        connector = "Shortly after authentication," if auth_events else "Execution activity was observed:"
        segments.append(
            f"{connector} process or script execution was recorded at **{_fmt_dt(first_exec.timestamp)}**: "
            f"{first_exec.description}"
        )

    if net_events:
        first_net = net_events[0]
        connector = "Network telemetry then showed" if (auth_events or exec_events) else "Network activity was recorded:"
        segments.append(
            f"{connector} outbound communication or network alerts beginning at "
            f"**{_fmt_dt(first_net.timestamp)}**: {first_net.description}"
        )

    if detect_events:
        sources_used = sorted({e.source for e in detect_events})
        segments.append(
            f"Detection analysis flagged **{len(detect_events)}** event(s) via "
            f"{', '.join(s.upper() for s in sources_used)} rules, indicating patterns consistent "
            "with known attack techniques."
        )

    uncategorised = [
        e for e in timeline
        if e not in auth_events and e not in exec_events and e not in net_events and e not in detect_events
    ]
    if uncategorised:
        segments.append(
            f"An additional **{len(uncategorised)}** event(s) were recorded across other sources "
            "and are detailed in the Timeline of Events section above."
        )

    return "  \n".join(segments)


def _build_summary(case, det_findings, yara_results, corr_findings, mitre_mappings) -> str:
    yara_hits = len([r for r in yara_results if r.risk_score > 0])
    tactics = len({m.tactic for m in mitre_mappings})
    return (
        f'{case.severity.upper()} severity incident. '
        f'{len(det_findings)} Sigma detection(s), '
        f'{yara_hits} YARA hit(s), '
        f'{len(corr_findings)} correlated finding(s), '
        f'{len(mitre_mappings)} ATT&CK technique(s) across {tactics} tactic(s).'
    )
