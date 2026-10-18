"""
PDF incident report generator for SOC Copilot Workbench.

Generates a styled PDF from case data using fpdf2.
PDFs are generated on demand and returned as bytes — not saved to disk.
Markdown report generation remains the source of truth; this mirrors that content.
"""

from collections import defaultdict
from datetime import datetime

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from sqlalchemy.orm import Session

from socmat.services.api.models.case import Case
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.timeline_event import TimelineEvent
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.correlated_finding import CorrelatedFinding
from socmat.services.api.models.case_mitre_mapping import CaseMitreMapping
from socmat.services.api.report_generator import _TECH_RECS, _TECH_DETECTION, _load_json, _fmt_dt

_SEV_COLORS = {
    'critical': (200, 30, 30),
    'high': (210, 90, 0),
    'medium': (170, 130, 0),
    'low': (30, 130, 30),
}


class _ReportPDF(FPDF):
    def __init__(self, case_id: int, generated_at: str):
        super().__init__()
        self._case_id = case_id
        self._generated_at = generated_at

    def header(self):
        self.set_font('Helvetica', 'B', 8)
        self.set_text_color(120, 120, 140)
        self.cell(0, 6, f'SOC Copilot Workbench  —  Security Incident Report  —  Case #{self._case_id}',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(190, 190, 210)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def footer(self):
        self.set_y(-13)
        self.set_draw_color(190, 190, 210)
        self.set_line_width(0.3)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(1)
        self.set_font('Helvetica', '', 8)
        self.set_text_color(130, 130, 150)
        self.cell(0, 5, f'Page {self.page_no()}  —  Generated {self._generated_at}', align='C')
        self.set_text_color(0, 0, 0)


# ── Rendering helpers ──────────────────────────────────────────────────────────

def _h2(pdf: FPDF, text: str) -> None:
    pdf.ln(3)
    pdf.set_fill_color(225, 230, 245)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(25, 30, 90)
    pdf.cell(0, 7, text, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def _h3(pdf: FPDF, text: str) -> None:
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(40, 40, 60)
    pdf.multi_cell(0, 6, text)
    pdf.set_text_color(0, 0, 0)


def _body(pdf: FPDF, text: str) -> None:
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(0, 6, text)
    pdf.set_text_color(0, 0, 0)


def _bullet(pdf: FPDF, text: str) -> None:
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(0, 6, f'  - {text}')
    pdf.set_text_color(0, 0, 0)


def _kv(pdf: FPDF, label: str, value: str) -> None:
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(70, 70, 90)
    pdf.cell(52, 6, f'{label}:')
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 6, str(value)[:120], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)


def _table_header(pdf: FPDF, widths: list, labels: list) -> None:
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(210, 215, 235)
    pdf.set_text_color(25, 30, 90)
    for i, (w, label) in enumerate(zip(widths, labels)):
        last = i == len(widths) - 1
        kw = dict(new_x=XPos.LMARGIN, new_y=YPos.NEXT) if last else {}
        pdf.cell(w, 6, label, border=1, fill=True, align='C', **kw)
    pdf.set_text_color(0, 0, 0)


def _table_row(pdf: FPDF, widths: list, values: list, row_idx: int) -> None:
    pdf.set_font('Helvetica', '', 8)
    fill = row_idx % 2 == 0
    pdf.set_fill_color(245, 247, 253) if fill else pdf.set_fill_color(255, 255, 255)
    for i, (w, val) in enumerate(zip(widths, values)):
        last = i == len(widths) - 1
        kw = dict(new_x=XPos.LMARGIN, new_y=YPos.NEXT) if last else {}
        pdf.cell(w, 5, str(val), border=1, fill=fill, **kw)


# ── Main generator ─────────────────────────────────────────────────────────────

def generate_pdf(db: Session, case_id: int) -> bytes:
    """Generate a PDF incident report. Returns raw PDF bytes."""
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

    now_str = datetime.utcnow().strftime('%d %b %Y %H:%M UTC')
    yara_hits = [r for r in yara_results if r.risk_score > 0]
    high_det = [f for f in det_findings if f.severity in ('high', 'critical')]
    high_corr = [c for c in corr_findings if c.confidence == 'high']
    sev_rgb = _SEV_COLORS.get(case.severity, (80, 80, 80))

    pdf = _ReportPDF(case_id=case_id, generated_at=now_str)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── Cover block ────────────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 20)
    pdf.set_text_color(20, 25, 70)
    pdf.multi_cell(0, 11, 'Security Incident Report')
    pdf.set_text_color(0, 0, 0)

    pdf.set_font('Helvetica', '', 13)
    pdf.set_text_color(60, 60, 80)
    pdf.multi_cell(0, 8, f'Case #{case_id}: {case.title}')

    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(*sev_rgb)
    pdf.multi_cell(0, 7, f'Severity: {case.severity.upper()}   |   Status: {case.status.upper()}')
    pdf.set_text_color(0, 0, 0)

    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(110, 110, 130)
    pdf.multi_cell(0, 6, f'Generated: {now_str}')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)
    pdf.set_draw_color(170, 175, 210)
    pdf.set_line_width(0.6)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(5)

    # ── 1. Executive Summary ───────────────────────────────────────────────────
    _h2(pdf, '1. Executive Summary')
    summary = (
        f'This report covers investigation case "{case.title}" (#{case_id}), '
        f'opened {_fmt_dt(case.created_at)} with {case.severity.upper()} severity. '
    )
    if case.description:
        summary += case.description + ' '
    summary += (
        f'As of {now_str}, status is {case.status.upper()}. '
        f'The investigation reviewed {len(evidence)} evidence file(s), '
        f'identified {len(det_findings)} Sigma detection finding(s), '
    )
    if yara_hits:
        summary += f'{len(yara_hits)} YARA triage hit(s), '
    summary += f'and {len(corr_findings)} correlated finding(s). '
    if mitre_mappings:
        tactics_count = len({m.tactic for m in mitre_mappings})
        summary += (
            f'MITRE ATT&CK mapping identified {len(mitre_mappings)} technique(s) '
            f'across {tactics_count} tactic(s).'
        )
    _body(pdf, summary)

    # ── 2. Incident Classification ─────────────────────────────────────────────
    _h2(pdf, '2. Incident Classification')
    _kv(pdf, 'Case Title', case.title)
    _kv(pdf, 'Case ID', f'#{case_id}')
    _kv(pdf, 'Source', case.source.replace('_', ' ').title())
    _kv(pdf, 'Status', case.status.upper())
    _kv(pdf, 'Created', _fmt_dt(case.created_at))
    _kv(pdf, 'Last Updated', _fmt_dt(case.updated_at))

    # ── 3. Severity ────────────────────────────────────────────────────────────
    _h2(pdf, '3. Severity')
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(*sev_rgb)
    pdf.multi_cell(0, 7, f'Overall Severity: {case.severity.upper()}')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)
    if high_det:
        _bullet(pdf, f'High/critical Sigma detections: {len(high_det)}')
    if yara_hits:
        _bullet(pdf, f'Positive YARA triage results: {len(yara_hits)}')
    if high_corr:
        _bullet(pdf, f'High-confidence correlated findings: {len(high_corr)}')
    high_mitre = [m for m in mitre_mappings if m.confidence == 'high']
    if high_mitre:
        _bullet(pdf, f'High-confidence MITRE technique mappings: {len(high_mitre)}')
    if not any([high_det, yara_hits, high_corr, high_mitre]):
        _body(pdf, 'No high-confidence indicators present at time of report generation.')

    # ── 4. Affected Assets ─────────────────────────────────────────────────────
    _h2(pdf, '4. Affected Assets')
    _kv(pdf, 'Host', case.affected_host or 'Not specified')
    _kv(pdf, 'User', case.affected_user or 'Not specified')
    _kv(pdf, 'IP Address', case.affected_ip or 'Not specified')

    # ── 5. Timeline of Events ──────────────────────────────────────────────────
    _h2(pdf, '5. Timeline of Events')
    if timeline:
        for te in timeline:
            sev_tag = f'[{te.severity.upper()}] ' if te.severity else ''
            _bullet(pdf, f'{_fmt_dt(te.timestamp)} - {sev_tag}[{te.source}/{te.event_type}] {te.description}')
    else:
        _body(pdf, 'No timeline events recorded.')

    # ── 6. Evidence Reviewed ───────────────────────────────────────────────────
    _h2(pdf, '6. Evidence Reviewed')
    if evidence:
        widths = [10, 65, 25, 18, 42, 30]
        headers = ['#', 'Original Filename', 'Type', 'Size', 'SHA-256 (prefix)', 'Uploaded']
        _table_header(pdf, widths, headers)
        for idx, ev in enumerate(evidence, 1):
            size_kb = f'{ev.file_size // 1024} KB' if ev.file_size else '-'
            sha = (ev.sha256[:14] + '...') if ev.sha256 else '-'
            uploaded = _fmt_dt(ev.uploaded_at)[:12]
            _table_row(pdf, widths,
                       [str(idx), ev.original_filename[:32], (ev.file_type or '-')[:14],
                        size_kb, sha, uploaded],
                       idx - 1)
        pdf.ln(2)
    else:
        _body(pdf, 'No evidence files uploaded.')

    # ── 7. Detection Findings (Sigma) ──────────────────────────────────────────
    _h2(pdf, '7. Detection Findings (Sigma)')
    if det_findings:
        for df in det_findings:
            sev_label = f'[{df.severity.upper()}] ' if df.severity else ''
            _h3(pdf, f'{sev_label}{df.rule_title}')
            _kv(pdf, 'Rule ID', df.rule_id)
            if df.event_id_str:
                _kv(pdf, 'Windows Event ID', df.event_id_str)
            if df.event_timestamp:
                _kv(pdf, 'Event Time', _fmt_dt(df.event_timestamp))
            if df.match_reason:
                _kv(pdf, 'Match Reason', df.match_reason)
            pdf.ln(2)
    else:
        _body(pdf, 'No Sigma detection findings.')

    # ── 8. Malware Triage Findings (YARA) ──────────────────────────────────────
    _h2(pdf, '8. Malware Triage Findings (YARA)')
    if yara_results:
        for r in yara_results:
            label = (r.sha256[:16] + '...') if r.sha256 else f'Evidence ID {r.evidence_id}'
            _h3(pdf, f'File: {label}')
            _kv(pdf, 'Risk Score', str(r.risk_score))
            if r.sha256:
                _kv(pdf, 'SHA-256', r.sha256)
            if r.file_type:
                _kv(pdf, 'File Type', r.file_type)
            if r.file_size:
                _kv(pdf, 'File Size', f'{r.file_size // 1024} KB')
            matches = _load_json(r.yara_matches, [])
            if matches:
                rule_names = [m.get('rule') or m.get('rule_name', '') for m in matches if isinstance(m, dict)]
                rule_names = [n for n in rule_names if n]
                if rule_names:
                    _kv(pdf, 'Matched Rules', ', '.join(rule_names))
            if r.summary:
                _kv(pdf, 'Summary', r.summary)
            pdf.ln(2)
    else:
        _body(pdf, 'No YARA triage findings.')

    # ── 9. Network Analysis Findings (Zeek) ────────────────────────────────────
    _h2(pdf, '9. Network Analysis Findings (Zeek)')
    if net_results:
        for r in net_results:
            _h3(pdf, f'{r.log_type.upper()} Log Analysis')
            _kv(pdf, 'Risk Score', str(r.risk_score))
            _kv(pdf, 'Total Records', str(r.total_records))
            summary_data = _load_json(r.summary_data, {})
            if isinstance(summary_data, dict):
                for k, v in list(summary_data.items())[:6]:
                    _kv(pdf, k.replace('_', ' ').title(), str(v))
            if r.summary:
                _kv(pdf, 'Analysis Notes', r.summary)
            findings = _load_json(r.findings, [])
            if findings:
                _body(pdf, 'Notable Findings:')
                for f_item in findings[:5]:
                    if isinstance(f_item, dict):
                        desc = f_item.get('description') or f_item.get('detail') or str(f_item)
                        _bullet(pdf, str(desc))
            pdf.ln(2)
    else:
        _body(pdf, 'No network analysis results.')

    # ── 10. Correlated Findings ────────────────────────────────────────────────
    _h2(pdf, '10. Correlated Findings')
    if corr_findings:
        for cf in corr_findings:
            _h3(pdf, f'[{cf.confidence.upper()}] {cf.title}')
            if cf.summary:
                _body(pdf, cf.summary)
            entities = _load_json(cf.entities, [])
            if entities:
                ent_parts = [
                    f'{e.get("type", "entity")}: {e.get("value", "")}'
                    for e in entities[:6] if isinstance(e, dict)
                ]
                if ent_parts:
                    _kv(pdf, 'Entities', ', '.join(ent_parts))
            if cf.recommended_action:
                _kv(pdf, 'Recommended Action', cf.recommended_action)
            pdf.ln(2)
    else:
        _body(pdf, 'No correlated findings.')

    # ── 11. MITRE ATT&CK Mapping ───────────────────────────────────────────────
    _h2(pdf, '11. MITRE ATT&CK Mapping')
    if mitre_mappings:
        tactic_groups: dict = defaultdict(list)
        for m in mitre_mappings:
            tactic_groups[m.tactic].append(m)
        widths_m = [32, 112, 30]
        headers_m = ['Technique ID', 'Technique Name', 'Confidence']
        for tactic, techniques in tactic_groups.items():
            _h3(pdf, tactic)
            _table_header(pdf, widths_m, headers_m)
            for idx, t in enumerate(techniques):
                _table_row(pdf, widths_m,
                           [t.technique_id, t.technique_name[:58], t.confidence.upper()],
                           idx)
            pdf.ln(3)
    else:
        _body(pdf, 'No MITRE ATT&CK mappings generated. Run ATT&CK mapping on the case first.')

    # ── 12. Analyst Assessment ─────────────────────────────────────────────────
    _h2(pdf, '12. Analyst Assessment')
    has_data = any([det_findings, yara_hits, net_results, corr_findings, mitre_mappings])
    if not has_data:
        _body(pdf, 'Insufficient evidence has been analyzed. Upload evidence files and run analysis modules before generating a final report.')
    else:
        parts = []
        if case.severity in ('high', 'critical'):
            parts.append(f'This is a {case.severity.upper()} severity incident requiring prompt investigation and response. ')
        if high_det:
            parts.append(f'Sigma detection rules flagged {len(high_det)} high-severity event(s). ')
        if yara_hits:
            parts.append(f'YARA static triage identified {len(yara_hits)} suspicious file(s) matching malware signatures. ')
        tactic_names = sorted({m.tactic for m in mitre_mappings})
        if tactic_names:
            parts.append(f'Attack activity spans ATT&CK tactics: {", ".join(tactic_names)}. ')
        if high_corr:
            parts.append(f'High-confidence correlation: {"; ".join(c.title for c in high_corr[:3])}. ')
        if not parts:
            parts.append('Evidence reviewed. No high-confidence indicators detected. Manual analyst review is recommended.')
        _body(pdf, ''.join(parts))

    # ── 13. Recommended Actions ────────────────────────────────────────────────
    _h2(pdf, '13. Recommended Actions')
    rec_actions: list = []
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
            _bullet(pdf, rec)
    else:
        _bullet(pdf, 'Review all findings and apply appropriate containment measures based on case severity.')
        _bullet(pdf, 'Escalate to senior analyst or IR team if indicators of compromise are confirmed.')
        _bullet(pdf, 'Preserve evidence and document all investigative steps taken.')

    # ── 14. Detection Opportunities ────────────────────────────────────────────
    _h2(pdf, '14. Detection Opportunities')
    if mitre_mappings:
        _body(pdf, 'Based on ATT&CK techniques identified in this case, the following monitoring improvements are recommended:')
        pdf.ln(2)
        shown = False
        for m in mitre_mappings:
            suggestion = _TECH_DETECTION.get(m.technique_id)
            if suggestion:
                _bullet(pdf, f'{m.technique_id} ({m.technique_name}): {suggestion}')
                shown = True
        if not shown:
            _body(pdf, 'No specific detection improvements identified for the mapped techniques.')
    else:
        _body(pdf, 'Run MITRE ATT&CK mapping first to identify detection coverage gaps.')

    # ── 15. Final Status ───────────────────────────────────────────────────────
    _h2(pdf, '15. Final Status')
    status_desc = {
        'open': 'Investigation has been opened. Initial triage is pending.',
        'investigating': 'Active investigation is in progress. Evidence collection and analysis is ongoing.',
        'contained': 'The incident has been contained. Post-incident review and lessons-learned documentation is recommended.',
        'escalated': 'The incident has been escalated to senior analyst or IR team for further action.',
        'closed': 'The investigation is closed. Evidence and findings have been fully documented.',
    }
    pdf.set_font('Helvetica', 'B', 11)
    pdf.multi_cell(0, 7, f'Case Status: {case.status.upper()}')
    _body(pdf, status_desc.get(case.status, 'Status not recognized.'))
    pdf.ln(4)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(110, 110, 130)
    pdf.multi_cell(0, 6, f'Report generated on {now_str} by SOC Copilot Workbench.')
    pdf.set_text_color(0, 0, 0)

    return bytes(pdf.output())
