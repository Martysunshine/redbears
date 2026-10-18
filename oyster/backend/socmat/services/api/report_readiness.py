"""
Report Readiness Score module for SOC Copilot Workbench.

Evaluates 22 completeness checks across 10 sections and produces a
readiness score (0-100) and grade (poor / fair / good / excellent).
No data is fabricated — all checks query the case database only.
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session

from socmat.services.api.models.analyst_note import AnalystNote
from socmat.services.api.models.case import Case
from socmat.services.api.models.case_playbook import CasePlaybook
from socmat.services.api.models.case_mitre_mapping import CaseMitreMapping
from socmat.services.api.models.correlated_finding import CorrelatedFinding
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.finding_disposition import FindingDisposition
from socmat.services.api.models.ioc import Ioc
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.pcap_analysis_result import PcapAnalysisResult
from socmat.services.api.models.report import Report
from socmat.services.api.models.timeline_event import TimelineEvent

_GRADE_THRESHOLDS = [
    (90, "excellent"),
    (70, "good"),
    (50, "fair"),
    (0, "poor"),
]

_SECTION_LABELS = {
    "case_metadata":    "Case Metadata",
    "evidence":         "Evidence",
    "timeline":         "Timeline",
    "detections":       "Detections",
    "network_analysis": "Network Analysis",
    "malware_triage":   "Malware Triage",
    "correlation":      "Correlation",
    "mitre_mapping":    "MITRE ATT&CK",
    "analyst_review":   "Analyst Review",
    "report_content":   "Report Content",
}


def _grade(score: float) -> str:
    for threshold, label in _GRADE_THRESHOLDS:
        if score >= threshold:
            return label
    return "poor"


def _check(
    id_: str,
    section: str,
    name: str,
    description: str,
    weight: int,
    optional: bool,
    passed: bool,
    na: bool = False,
) -> dict:
    if na:
        status = "na"
    elif passed:
        status = "pass"
    else:
        status = "fail"
    return {
        "id": id_,
        "section": section,
        "name": name,
        "description": description,
        "status": status,
        "weight": weight,
        "optional": optional,
    }


def compute_readiness(db: Session, case_id: int) -> dict:
    """Run all 22 readiness checks. Returns a scored result dict or None if case missing."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return None

    # Gather raw counts once up front
    evidence_count  = db.query(Evidence).filter(Evidence.case_id == case_id).count()
    timeline_count  = db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).count()
    detection_count = db.query(DetectionFinding).filter(DetectionFinding.case_id == case_id).count()
    net_count       = db.query(NetworkAnalysisResult).filter(NetworkAnalysisResult.case_id == case_id).count()
    pcap_count      = db.query(PcapAnalysisResult).filter(PcapAnalysisResult.case_id == case_id).count()
    yara_count      = db.query(MalwareTriageResult).filter(MalwareTriageResult.case_id == case_id).count()
    corr_count      = db.query(CorrelatedFinding).filter(CorrelatedFinding.case_id == case_id).count()
    mitre_count     = db.query(CaseMitreMapping).filter(CaseMitreMapping.case_id == case_id).count()
    note_count      = db.query(AnalystNote).filter(AnalystNote.case_id == case_id).count()
    disp_count      = db.query(FindingDisposition).filter(FindingDisposition.case_id == case_id).count()
    ioc_count       = db.query(Ioc).filter(Ioc.case_id == case_id).count()
    report_count    = db.query(Report).filter(Report.case_id == case_id).count()
    playbook_count  = db.query(CasePlaybook).filter(CasePlaybook.case_id == case_id).count()

    assessment_count = db.query(AnalystNote).filter(
        AnalystNote.case_id == case_id,
        AnalystNote.note_type == "assessment",
    ).count()

    recs_count = db.query(CorrelatedFinding).filter(
        CorrelatedFinding.case_id == case_id,
        CorrelatedFinding.recommended_action.isnot(None),
        CorrelatedFinding.recommended_action != "",
    ).count()

    playbook_has_progress = False
    if playbook_count > 0:
        pb = db.query(CasePlaybook).filter(CasePlaybook.case_id == case_id).first()
        if pb and pb.progress_percent and pb.progress_percent > 0:
            playbook_has_progress = True

    # N/A conditions — checks not applicable when no related evidence exists
    na_network  = evidence_count == 0 and net_count == 0 and pcap_count == 0
    na_malware  = evidence_count == 0 and yara_count == 0
    na_playbook = playbook_count == 0

    checks = [
        # ── Case Metadata (checks 1–7) ──────────────────────────────────────────
        _check("title", "case_metadata",
               "Case title set",
               "Case has a non-empty descriptive title",
               5, False, bool(case.title and case.title.strip())),

        _check("description", "case_metadata",
               "Case description set",
               "Investigation context and initial observations are documented",
               5, False, bool(case.description and case.description.strip())),

        _check("severity", "case_metadata",
               "Severity classified",
               "Severity level has been assessed (low / medium / high / critical)",
               3, False, case.severity in {"low", "medium", "high", "critical"}),

        _check("status", "case_metadata",
               "Status progressed beyond Open",
               "Case status reflects investigation progress, not left as the default Open",
               3, False, case.status != "open"),

        _check("host", "case_metadata",
               "Affected host identified",
               "Source or affected host is documented in the case",
               4, False, bool(case.affected_host and case.affected_host.strip())),

        _check("user", "case_metadata",
               "Affected user identified",
               "User account involved in the incident is documented",
               3, True, bool(case.affected_user and case.affected_user.strip())),

        _check("ip", "case_metadata",
               "Affected IP identified",
               "IP address associated with the incident is recorded",
               3, True, bool(case.affected_ip and case.affected_ip.strip())),

        # ── Evidence (check 8) ──────────────────────────────────────────────────
        _check("evidence", "evidence",
               "Evidence files attached",
               "At least one evidence file has been uploaded to this case",
               8, False, evidence_count > 0),

        # ── Timeline (check 9) ──────────────────────────────────────────────────
        _check("timeline", "timeline",
               "Timeline events exist",
               "Investigation timeline has at least one recorded event",
               6, False, timeline_count > 0),

        # ── Detections (check 10) ───────────────────────────────────────────────
        _check("detections", "detections",
               "Detection findings produced",
               "Sigma or other detection rules have been run and produced findings",
               6, False, detection_count > 0),

        # ── Network Analysis (check 11) ─────────────────────────────────────────
        _check("network", "network_analysis",
               "Network analysis completed",
               "Network logs (Zeek, Suricata, PCAP) have been analysed for threats",
               5, True, (net_count + pcap_count) > 0, na=na_network),

        # ── Malware Triage (check 12) ───────────────────────────────────────────
        _check("malware", "malware_triage",
               "Malware triage completed",
               "Uploaded files have been scanned with YARA rules",
               5, True, yara_count > 0, na=na_malware),

        # ── Correlation (check 13) ──────────────────────────────────────────────
        _check("correlation", "correlation",
               "Correlation engine run",
               "Cross-source correlation has been performed to identify multi-source patterns",
               6, False, corr_count > 0),

        # ── MITRE ATT&CK (check 14) ─────────────────────────────────────────────
        _check("mitre", "mitre_mapping",
               "MITRE ATT&CK mapping done",
               "Findings have been mapped to MITRE ATT&CK techniques",
               6, False, mitre_count > 0),

        # ── Analyst Review (checks 15, 16, 22) ─────────────────────────────────
        _check("notes", "analyst_review",
               "Analyst notes recorded",
               "At least one analyst note is attached to the case",
               5, False, note_count > 0),

        _check("dispositions", "analyst_review",
               "Finding dispositions reviewed",
               "At least one finding has been reviewed and dispositioned (TP/FP/benign/etc.)",
               5, False, disp_count > 0),

        _check("assessment", "analyst_review",
               "Final analyst assessment written",
               "An 'assessment' type analyst note summarises the investigation conclusion",
               6, False, assessment_count > 0),

        # ── Report Content (checks 17–21) ───────────────────────────────────────
        _check("recommendations", "report_content",
               "Recommended actions documented",
               "Correlated findings or MITRE mappings include recommended response actions",
               4, False, recs_count > 0 or mitre_count > 0),

        _check("report_generated", "report_content",
               "Incident report generated",
               "A full incident report has been generated at least once for this case",
               4, True, report_count > 0),

        _check("iocs", "report_content",
               "IOCs extracted and catalogued",
               "Indicators of compromise have been identified and recorded in the IOC basket",
               5, False, ioc_count > 0),

        _check("playbooks", "report_content",
               "Investigation playbook in progress",
               "At least one investigation playbook is attached and has recorded step progress",
               4, True, playbook_has_progress, na=na_playbook),

        _check("telemetry_gaps", "report_content",
               "Detection coverage assessed",
               "MITRE ATT&CK mapping has been done to enable telemetry gap assessment",
               3, False, mitre_count > 0),
    ]

    # ── Scoring ─────────────────────────────────────────────────────────────────
    achieved        = sum(c["weight"] for c in checks if c["status"] == "pass")
    max_applicable  = sum(c["weight"] for c in checks if c["status"] in ("pass", "fail"))
    total_score     = round(achieved / max_applicable * 100, 1) if max_applicable > 0 else 0.0
    grade           = _grade(total_score)

    completed  = [c for c in checks if c["status"] == "pass"]
    missing    = [c for c in checks if c["status"] == "fail"]
    na_checks  = [c for c in checks if c["status"] == "na"]

    # ── Section scores ───────────────────────────────────────────────────────────
    section_scores: dict = {}
    for section_key, section_label in _SECTION_LABELS.items():
        s_checks   = [c for c in checks if c["section"] == section_key and c["status"] != "na"]
        s_achieved = sum(c["weight"] for c in s_checks if c["status"] == "pass")
        s_max      = sum(c["weight"] for c in s_checks)
        section_scores[section_key] = {
            "name":      section_label,
            "score":     round(s_achieved / s_max * 100, 1) if s_max > 0 else 100.0,
            "achieved":  s_achieved,
            "max_score": s_max,
        }

    # ── Warnings ─────────────────────────────────────────────────────────────────
    warnings: list = []
    missing_ids = {c["id"] for c in missing}

    if evidence_count == 0:
        warnings.append("No evidence files attached — analysis results will be limited.")
    if detection_count == 0 and evidence_count > 0:
        warnings.append("Evidence exists but no detection rules have been run yet.")
    if mitre_count == 0 and corr_count > 0:
        warnings.append("Correlation findings exist but MITRE ATT&CK mapping has not been performed.")
    if disp_count == 0 and detection_count > 0:
        warnings.append("Detection findings exist but none have been dispositioned (TP/FP/benign).")
    if assessment_count == 0 and note_count > 0:
        warnings.append(
            "Analyst notes exist but no 'assessment' note summarises the investigation conclusion."
        )
    if total_score < 50:
        warnings.append(
            "Report readiness is low — complete missing items before sharing this report externally."
        )

    # ── Recommendations ──────────────────────────────────────────────────────────
    recommendations: list = []
    if "description" in missing_ids:
        recommendations.append("Add a case description with initial observations and investigation context.")
    if "status" in missing_ids:
        recommendations.append("Update the case status to reflect current investigation progress.")
    if "host" in missing_ids:
        recommendations.append("Identify and record the affected host in Case Details.")
    if "evidence" in missing_ids:
        recommendations.append("Upload evidence files (event logs, PCAPs, suspicious files) to enable analysis.")
    if "timeline" in missing_ids:
        recommendations.append("Run log analysis or add manual timeline events to build an investigation timeline.")
    if "detections" in missing_ids:
        recommendations.append("Run the Sigma Detection panel to produce detection findings.")
    if "correlation" in missing_ids:
        recommendations.append("Run the Correlation Engine to identify multi-source attack patterns.")
    if "mitre" in missing_ids:
        recommendations.append("Run MITRE ATT&CK Mapping to classify findings and generate recommended actions.")
    if "notes" in missing_ids:
        recommendations.append("Add at least one Analyst Note to record observations and reasoning.")
    if "dispositions" in missing_ids and detection_count > 0:
        recommendations.append(
            "Review and disposition detection findings as true positive, false positive, or benign."
        )
    if "iocs" in missing_ids and evidence_count > 0:
        recommendations.append("Extract IOCs from case data using the IOC Basket panel.")
    if "assessment" in missing_ids:
        recommendations.append(
            "Write a final 'assessment' type Analyst Note summarising the investigation conclusion."
        )
    if "playbooks" in missing_ids and playbook_count == 0:
        recommendations.append("Attach an investigation playbook from the Analyst Playbooks panel.")

    return {
        "case_id":          case_id,
        "total_score":      total_score,
        "grade":            grade,
        "completed_checks": completed,
        "missing_checks":   missing,
        "na_checks":        na_checks,
        "warnings":         warnings,
        "recommendations":  recommendations,
        "section_scores":   section_scores,
        "checked_at":       datetime.now(timezone.utc).isoformat(),
    }
