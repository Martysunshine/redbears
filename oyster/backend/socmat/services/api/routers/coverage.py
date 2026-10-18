"""
Detection Coverage and Telemetry Gap Analysis endpoints.

GET /coverage/rules              — global rule library with coverage metadata
GET /cases/{id}/coverage         — per-case coverage analysis
GET /cases/{id}/telemetry-gaps   — telemetry gap analysis for a case
"""

import sys
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.sigma.loader import get_cached_rules  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.case import Case
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.normalized_event import NormalizedEvent
from socmat.services.api.models.pcap_analysis_result import PcapAnalysisResult
from socmat.services.api.schemas.coverage_schema import (
    CaseCoverageResponse,
    RuleCoverage,
    RuleCoverageListResponse,
    TelemetryGap,
    TelemetryGapListResponse,
)

router = APIRouter(tags=["coverage"])


# ── Static telemetry gap catalogue ────────────────────────────────────────────

_TELEMETRY_GAPS: List[dict] = [
    {
        "key": "powershell_script_block",
        "required_event_ids": {"4103", "4104"},
        "missing_log_source": "PowerShell Script Block Logs (EID 4103/4104)",
        "why_it_matters": (
            "Script block logging captures PowerShell code before obfuscation is applied, "
            "enabling detection of encoded and obfuscated attacks. Without it, encoded PowerShell "
            "commands appear only as base64 blobs in process creation logs."
        ),
        "affected_detection_rules": [
            "PowerShell encoded command execution",
            "PowerShell AMSI bypass",
            "PowerShell download cradle",
        ],
        "related_mitre_techniques": ["T1059.001", "T1027"],
        "recommendation": (
            "Enable PowerShell Script Block Logging via Group Policy: "
            "Computer Configuration → Administrative Templates → Windows Components → PowerShell → "
            "Turn on PowerShell Script Block Logging."
        ),
    },
    {
        "key": "sysmon_process_creation",
        "required_event_ids": {"1", "4688"},
        "missing_log_source": "Sysmon Event ID 1 / Windows EID 4688 (Process Creation)",
        "why_it_matters": (
            "Sysmon EID 1 and Windows EID 4688 capture full process command lines, "
            "parent-child relationships, and file hashes. They are required for most "
            "endpoint detection rules. Without process creation logs, most Sigma rules cannot run."
        ),
        "affected_detection_rules": [
            "Suspicious process creation",
            "Living-off-the-land binaries (LOLBins)",
            "Process injection",
            "Masquerading",
        ],
        "related_mitre_techniques": ["T1059", "T1036", "T1055", "T1204"],
        "recommendation": (
            "Deploy Sysmon with a configuration that enables Event ID 1 (ProcessCreate), "
            "or enable Windows Audit Process Creation (EID 4688) with command-line logging. "
            "Use the SwiftOnSecurity or Olaf Hartong Sysmon configuration as a baseline."
        ),
    },
    {
        "key": "sysmon_network_connections",
        "required_event_ids": {"3"},
        "missing_log_source": "Sysmon Event ID 3 (Network Connections)",
        "why_it_matters": (
            "Sysmon EID 3 logs outbound connections with the originating process, enabling "
            "correlation of network activity to the process that generated it. Without it, "
            "C2 and lateral movement detection is severely limited."
        ),
        "affected_detection_rules": [
            "C2 beaconing detection",
            "Lateral movement via network logon",
            "Suspicious outbound connections from unexpected processes",
        ],
        "related_mitre_techniques": ["T1071", "T1021", "T1090"],
        "recommendation": (
            "Enable Sysmon Event ID 3 (NetworkConnect) in your Sysmon configuration. "
            "Apply port and IP filters to reduce volume while preserving useful telemetry."
        ),
    },
    {
        "key": "dns_logs",
        "required_event_ids": set(),
        "missing_log_source": "DNS Query Logs",
        "why_it_matters": (
            "DNS logs expose C2 domain communication, DGA activity, and DNS tunneling. "
            "Many C2 frameworks rely on DNS for beaconing. Without DNS visibility, "
            "domain-based attacker infrastructure is invisible."
        ),
        "affected_detection_rules": [
            "DNS tunneling detection",
            "DGA domain detection",
            "C2 beaconing via DNS",
        ],
        "related_mitre_techniques": ["T1071.004", "T1568.002"],
        "recommendation": (
            "Enable DNS debug logging on Windows DNS servers or collect Zeek dns.log. "
            "Forward to SIEM for correlation with endpoint activity."
        ),
    },
    {
        "key": "proxy_http_logs",
        "required_event_ids": set(),
        "missing_log_source": "Proxy / HTTP Logs",
        "why_it_matters": (
            "Proxy or HTTP logs capture web traffic details including URLs, user agents, "
            "and response codes. They are essential for detecting web-based C2, "
            "malicious downloads, and data exfiltration over HTTP/S."
        ),
        "affected_detection_rules": [
            "C2 over HTTP/HTTPS",
            "Suspicious user agent strings",
            "Large HTTP data transfer (exfiltration)",
        ],
        "related_mitre_techniques": ["T1071.001", "T1041"],
        "recommendation": (
            "Deploy a web proxy and collect HTTP access logs. "
            "If using Zeek, ensure HTTP log collection is enabled. "
            "Forward to SIEM and correlate with endpoint process creation events."
        ),
    },
    {
        "key": "edr_process_tree",
        "required_event_ids": set(),
        "missing_log_source": "EDR Process Tree / Memory Telemetry",
        "why_it_matters": (
            "EDR solutions provide process tree visibility, memory injection detection, "
            "and behavioural analytics that go beyond event logs. Without EDR, "
            "process injection and living-off-the-land techniques are harder to detect."
        ),
        "affected_detection_rules": [
            "Process injection",
            "Hollowing / PE injection",
            "In-memory execution",
        ],
        "related_mitre_techniques": ["T1055", "T1027.002", "T1620"],
        "recommendation": (
            "Consider deploying an EDR solution (CrowdStrike, Microsoft Defender for Endpoint, "
            "SentinelOne, or equivalent) to gain process tree and memory telemetry."
        ),
    },
    {
        "key": "authentication_logs",
        "required_event_ids": {"4624", "4625", "4648", "4768", "4769", "4776"},
        "missing_log_source": "Authentication Logs (EID 4624/4625/4648/4768/4769)",
        "why_it_matters": (
            "Authentication event logs are essential for detecting brute force, "
            "credential stuffing, pass-the-hash, and Kerberoasting. "
            "Without them, account compromise activity goes undetected."
        ),
        "affected_detection_rules": [
            "Brute force / repeated authentication failures",
            "Pass-the-hash / Pass-the-ticket",
            "Kerberoasting (EID 4769)",
            "Credential stuffing",
        ],
        "related_mitre_techniques": ["T1110", "T1078", "T1558.003"],
        "recommendation": (
            "Enable Windows Security Event logging: Audit Logon/Logoff (success+failure), "
            "Audit Account Logon (EID 4768/4769/4776) for Kerberos events. "
            "Ensure these events are collected by your SIEM or this tool."
        ),
    },
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_sigma_fields(detection: dict) -> List[str]:
    """Heuristically extract field names from a Sigma detection condition dict."""
    fields: set = set()
    for key, val in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(val, dict):
            for field_key in val.keys():
                base = field_key.split("|")[0] if "|" in field_key else field_key
                fields.add(base)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    for field_key in item.keys():
                        base = field_key.split("|")[0] if "|" in field_key else field_key
                        fields.add(base)
    return sorted(fields)


def _sigma_to_rule_coverage(
    rule: dict,
    triggered_ids: set,
    available_sources: set,
) -> RuleCoverage:
    """Convert a Sigma rule dict into a RuleCoverage model."""
    rule_id = rule["id"]
    logsource = rule.get("logsource", {})

    product = logsource.get("product", "")
    category = logsource.get("category", "")
    service = logsource.get("service", "")
    ls_parts = [p for p in [product, category, service] if p]
    required_logsource = " / ".join(ls_parts) if ls_parts else "any"

    required_fields = _extract_sigma_fields(rule.get("detection", {}))

    mitre_techniques = [
        t.replace("attack.", "").upper()
        for t in rule.get("tags", [])
        if t.lower().startswith("attack.t")
    ]

    triggered = rule_id in triggered_ids

    blocked = False
    missing_fields: List[str] = []
    if product == "windows" and "windows_logs" not in available_sources:
        blocked = True
        missing_fields.append("Windows event logs not collected for this case")
    elif product == "zeek" and "zeek" not in available_sources:
        blocked = True
        missing_fields.append("Zeek network logs not available for this case")
    elif category == "network_connection" and "sysmon_network" not in available_sources:
        blocked = True
        missing_fields.append("Sysmon EID 3 network connection events not collected")

    return RuleCoverage(
        rule_id=rule_id,
        rule_title=rule["title"],
        rule_type="sigma",
        required_logsource=required_logsource,
        required_fields=required_fields[:10],
        mapped_mitre_techniques=mitre_techniques,
        severity=rule.get("level", "medium"),
        triggered_in_case=triggered,
        blocked_by_missing_data=blocked,
        missing_fields=missing_fields,
    )


def _get_available_sources(db: Session, case_id: int) -> set:
    """Determine which log source types are present for a case."""
    sources: set = set()

    if db.query(NormalizedEvent.id).filter(NormalizedEvent.case_id == case_id).first():
        sources.add("windows_logs")

    net_types = db.query(NetworkAnalysisResult.log_type).filter(
        NetworkAnalysisResult.case_id == case_id
    ).all()
    for (lt,) in net_types:
        if lt:
            lt_lower = lt.lower()
            sources.add(lt_lower)
            if lt_lower in ("conn", "dns", "http") or "zeek" in lt_lower:
                sources.add("zeek")
            if "suricata" in lt_lower:
                sources.add("suricata")

    if db.query(PcapAnalysisResult.id).filter(PcapAnalysisResult.case_id == case_id).first():
        sources.add("pcap")

    if db.query(MalwareTriageResult.id).filter(MalwareTriageResult.case_id == case_id).first():
        sources.add("yara")

    if db.query(NormalizedEvent.id).filter(
        NormalizedEvent.case_id == case_id,
        NormalizedEvent.event_id == "3",
    ).first():
        sources.add("sysmon_network")

    return sources


def _sources_to_labels(sources: set) -> List[str]:
    labels: List[str] = []
    if "windows_logs" in sources:
        labels.append("Windows Event Logs")
    if "zeek" in sources or any(s in sources for s in ("conn", "dns", "http")):
        labels.append("Zeek Network Logs")
    if "suricata" in sources:
        labels.append("Suricata IDS Alerts")
    if "pcap" in sources:
        labels.append("PCAP Network Capture")
    if "yara" in sources:
        labels.append("YARA Static Analysis")
    if "sysmon_network" in sources:
        labels.append("Sysmon Network Events (EID 3)")
    return sorted(labels)


def _is_gap_present(
    key: str,
    event_ids: set,
    has_dns: bool,
    has_http: bool,
) -> bool:
    for gap_def in _TELEMETRY_GAPS:
        if gap_def["key"] != key:
            continue
        req_ids = gap_def["required_event_ids"]
        if req_ids:
            return not req_ids.intersection(event_ids)
        # Special cases without event ID checks
        if key == "dns_logs":
            return not has_dns
        if key == "proxy_http_logs":
            return not has_http
        if key == "edr_process_tree":
            return True  # always a gap until EDR integration is added
    return False


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/coverage/rules", response_model=RuleCoverageListResponse)
def list_coverage_rules(
    rule_type: Optional[str] = Query(None, description="Filter by rule type (sigma)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    logsource: Optional[str] = Query(None, description="Filter by logsource substring"),
    tactic: Optional[str] = Query(None, description="Filter by MITRE technique substring"),
):
    """List all Sigma rules with coverage metadata (no case context)."""
    sigma_rules = get_cached_rules()

    rules: List[RuleCoverage] = []
    for rule in sigma_rules:
        cov = _sigma_to_rule_coverage(rule, set(), set())

        if rule_type and rule_type.lower() != "sigma":
            continue
        if severity and cov.severity.lower() != severity.lower():
            continue
        if logsource and logsource.lower() not in cov.required_logsource.lower():
            continue
        if tactic:
            tac_lower = tactic.lower()
            if not any(tac_lower in t.lower() for t in cov.mapped_mitre_techniques):
                continue

        rules.append(cov)

    return RuleCoverageListResponse(rules=rules, total_count=len(rules))


@router.get("/cases/{case_id}/coverage", response_model=CaseCoverageResponse)
def get_case_coverage(case_id: int, db: Session = Depends(get_db)):
    """Analyse detection coverage for a specific case."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    triggered_rows = db.query(DetectionFinding.rule_id).filter(
        DetectionFinding.case_id == case_id
    ).distinct().all()
    triggered_ids = {r for (r,) in triggered_rows}

    available_sources = _get_available_sources(db, case_id)
    sigma_rules = get_cached_rules()

    rules_triggered: List[RuleCoverage] = []
    rules_not_triggered: List[RuleCoverage] = []
    rules_blocked: List[RuleCoverage] = []

    for rule in sigma_rules:
        cov = _sigma_to_rule_coverage(rule, triggered_ids, available_sources)
        if cov.triggered_in_case:
            rules_triggered.append(cov)
        elif cov.blocked_by_missing_data:
            rules_blocked.append(cov)
        else:
            rules_not_triggered.append(cov)

    available_labels = _sources_to_labels(available_sources)
    all_expected = {
        "Windows Event Logs",
        "Zeek Network Logs",
        "Suricata IDS Alerts",
        "PCAP Network Capture",
        "YARA Static Analysis",
    }
    missing_labels = sorted(all_expected - set(available_labels))

    covered_techniques: set = set()
    for r in rules_triggered:
        covered_techniques.update(r.mapped_mitre_techniques)

    all_techniques: set = set()
    for rule in sigma_rules:
        for tag in rule.get("tags", []):
            if tag.lower().startswith("attack.t"):
                all_techniques.add(tag.replace("attack.", "").upper())

    total_count = len(all_techniques) if all_techniques else 1
    covered_count = len(covered_techniques)
    coverage_percent = round(covered_count / total_count * 100, 1)

    return CaseCoverageResponse(
        case_id=case_id,
        rules_triggered=rules_triggered,
        rules_not_triggered=rules_not_triggered,
        rules_blocked=rules_blocked,
        available_log_sources=available_labels,
        missing_log_sources=missing_labels,
        mitre_covered_techniques=covered_count,
        mitre_total_techniques=total_count,
        coverage_percent=coverage_percent,
    )


@router.get("/cases/{case_id}/telemetry-gaps", response_model=TelemetryGapListResponse)
def get_telemetry_gaps(case_id: int, db: Session = Depends(get_db)):
    """Identify telemetry gaps for a specific case based on collected evidence."""
    if not db.query(Case).filter(Case.id == case_id).first():
        raise HTTPException(status_code=404, detail="Case not found")

    available_sources = _get_available_sources(db, case_id)

    event_ids: set = set()
    for (eid,) in db.query(NormalizedEvent.event_id).filter(
        NormalizedEvent.case_id == case_id
    ).all():
        if eid:
            event_ids.add(str(eid))

    has_dns = any(
        "dns" in (lt or "").lower()
        for (lt,) in db.query(NetworkAnalysisResult.log_type).filter(
            NetworkAnalysisResult.case_id == case_id
        ).all()
    ) or bool(
        db.query(PcapAnalysisResult.id).filter(
            PcapAnalysisResult.case_id == case_id,
            PcapAnalysisResult.dns_queries.isnot(None),
        ).first()
    )

    has_http = any(
        "http" in (lt or "").lower()
        for (lt,) in db.query(NetworkAnalysisResult.log_type).filter(
            NetworkAnalysisResult.case_id == case_id
        ).all()
    ) or bool(
        db.query(PcapAnalysisResult.id).filter(
            PcapAnalysisResult.case_id == case_id,
            PcapAnalysisResult.http_requests.isnot(None),
        ).first()
    )

    gaps: List[TelemetryGap] = []
    for gap_def in _TELEMETRY_GAPS:
        key = gap_def["key"]
        absent = _is_gap_present(key, event_ids, has_dns, has_http)
        if absent:
            gaps.append(TelemetryGap(
                missing_log_source=gap_def["missing_log_source"],
                why_it_matters=gap_def["why_it_matters"],
                affected_detection_rules=gap_def["affected_detection_rules"],
                related_mitre_techniques=gap_def["related_mitre_techniques"],
                recommendation=gap_def["recommendation"],
            ))

    return TelemetryGapListResponse(
        case_id=case_id,
        gaps=gaps,
        available_log_sources=_sources_to_labels(available_sources),
        gap_count=len(gaps),
    )
