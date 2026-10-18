"""
Detection rule drafting assistant.

Generates Sigma YAML, Splunk SPL, and Elastic KQL/ES|QL rule templates
from a natural-language description and optional event context.

All output is draft-quality and marked experimental.
Rules must be reviewed and tested against real log data before production deployment.
"""

import re
import uuid
from datetime import date
from typing import Optional

QUALITY_DISCLAIMER = (
    "This is a draft rule generated from a text description. "
    "It has not been tested against real log data. "
    "Review the detection logic, test against known-good and known-bad samples, "
    "tune field values and thresholds for your environment, "
    "and validate coverage before deploying to production."
)

_VALIDATION_WARNINGS_BASE = [
    "Rule not tested — validate against your own log samples before production use.",
    "Detection values are placeholders — replace with values observed in your environment.",
    "Coverage depends on your log collection configuration (audit policy, Sysmon config, ECS mapping).",
]

EVENT_TYPE_LABELS = {
    "process_creation": "Process Creation (Sysmon EID 1 / Windows 4688)",
    "network_connection": "Network Connection (Sysmon EID 3)",
    "dns_query": "DNS Query (Sysmon EID 22)",
    "file_creation": "File Creation (Sysmon EID 11)",
    "registry_modification": "Registry Modification (Sysmon EID 12/13/14)",
    "user_logon": "User Logon Success (Windows 4624)",
    "failed_logon": "Failed Logon / Brute Force (Windows 4625)",
    "service_installation": "Service Installation (Windows 7045)",
    "generic": "Generic (specify log source manually)",
}

_ET_TITLE = {
    "process_creation": "Suspicious Process Creation",
    "network_connection": "Suspicious Network Connection",
    "dns_query": "Suspicious DNS Query",
    "file_creation": "Suspicious File Creation",
    "registry_modification": "Suspicious Registry Modification",
    "user_logon": "Suspicious User Logon",
    "failed_logon": "Potential Brute Force Attack",
    "service_installation": "Suspicious Service Installation",
    "generic": "Suspicious Activity",
}

# Keywords for auto-detecting event type from description
_ET_KEYWORDS = {
    "process_creation": [
        "process", "execution", "execute", "spawn", "launch", "cmd",
        "powershell", "command", "invoke", "wscript", "cscript", "mshta",
        "regsvr32", "rundll32", "msiexec", "certutil", "bitsadmin",
    ],
    "network_connection": [
        "network", "connect", "outbound", "c2", "beacon", "callback",
        "remote", "socket", "tcp", "udp", "port", "destination",
    ],
    "dns_query": [
        "dns", "domain", "resolve", "nxdomain", "dga", "tunnel",
        "lookup", "subdomain",
    ],
    "file_creation": [
        "file", "drop", "write", "download", "temp", "appdata",
        "artifact", "payload",
    ],
    "registry_modification": [
        "registry", "reg", "hkey", "hklm", "hkcu", "persistence",
        "autorun", "run key",
    ],
    "user_logon": [
        "successful login", "successful logon", "auth success", "4624",
    ],
    "failed_logon": [
        "failed login", "failed logon", "brute", "spray", "password fail",
        "invalid password", "4625",
    ],
    "service_installation": [
        "service", "install service", "new service", "7045", "sc.exe",
    ],
}

_TEMPLATES = {
    "process_creation": {
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_field": "CommandLine|contains",
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059"],
        "falsepositives": [
            "Legitimate administrative scripts",
            "Software installers",
            "IT automation and management tooling",
        ],
        "log_source_notes": [
            "Requires Sysmon Event ID 1 (ProcessCreate) or Windows Security Event ID 4688 with command line logging enabled.",
            "Enable 'Audit Process Creation' under Advanced Audit Policy → Detailed Tracking.",
            "For Windows 4688: enable 'Include command line in process creation events' via Group Policy.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "spl_filter": "EventCode=1",
        "spl_field": "CommandLine",
        "kql_field": "process.command_line",
        "kql_keep": "@timestamp, host.name, user.name, process.name, process.command_line",
    },
    "network_connection": {
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection_field": "DestinationIp|contains",
        "level": "medium",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "falsepositives": [
            "Legitimate software communicating to the same destination",
            "Network monitoring and management tools",
            "Vulnerability scanners operated by your security team",
        ],
        "log_source_notes": [
            "Requires Sysmon Event ID 3 (NetworkConnect). Enable network connection logging in your Sysmon configuration.",
            "Alternatively, use Zeek conn.log or Suricata eve.json for network-based detection.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "spl_filter": "EventCode=3",
        "spl_field": "DestinationIp",
        "kql_field": "destination.ip",
        "kql_keep": "@timestamp, host.name, source.ip, destination.ip, destination.port",
    },
    "dns_query": {
        "logsource": {"category": "dns"},
        "detection_field": "QueryName|contains",
        "level": "medium",
        "tags": ["attack.command_and_control", "attack.t1071.004"],
        "falsepositives": [
            "Legitimate domains with similar naming patterns",
            "CDN and content delivery networks",
            "Vendor domains that may appear high-entropy",
        ],
        "log_source_notes": [
            "Requires Sysmon Event ID 22 (DnsQuery), Windows DNS Server analytic logs, or passive DNS via Zeek dns.log.",
            "Enable DnsQuery events in your Sysmon configuration.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "spl_filter": "EventCode=22",
        "spl_field": "QueryName",
        "kql_field": "dns.question.name",
        "kql_keep": "@timestamp, host.name, user.name, dns.question.name",
    },
    "file_creation": {
        "logsource": {"category": "file_event", "product": "windows"},
        "detection_field": "TargetFilename|contains",
        "level": "medium",
        "tags": ["attack.defense_evasion", "attack.t1027"],
        "falsepositives": [
            "Legitimate software writing to temporary directories",
            "Antivirus quarantine operations",
            "Software update processes",
        ],
        "log_source_notes": [
            "Requires Sysmon Event ID 11 (FileCreate). Configure Sysmon to monitor relevant directories.",
            "Exclude browser caches and Windows Temp directories to reduce noise.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "spl_filter": "EventCode=11",
        "spl_field": "TargetFilename",
        "kql_field": "file.path",
        "kql_keep": "@timestamp, host.name, user.name, file.path",
    },
    "registry_modification": {
        "logsource": {"category": "registry_set", "product": "windows"},
        "detection_field": "TargetObject|contains",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1547"],
        "falsepositives": [
            "Legitimate software installers modifying run keys",
            "Group Policy application",
            "Administrative tools and endpoint agents",
        ],
        "log_source_notes": [
            "Requires Sysmon Event IDs 12, 13, or 14 (Registry events). Configure Sysmon to monitor the relevant registry paths.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "spl_filter": "EventCode IN (12,13,14)",
        "spl_field": "TargetObject",
        "kql_field": "registry.path",
        "kql_keep": "@timestamp, host.name, user.name, registry.path, registry.value",
    },
    "user_logon": {
        "logsource": {"product": "windows", "service": "security"},
        "detection_field": None,
        "level": "informational",
        "tags": ["attack.lateral_movement", "attack.t1021"],
        "falsepositives": [
            "Expected remote logins from IT administrators",
            "Scheduled tasks using network logon type",
            "Service account authentications",
        ],
        "log_source_notes": [
            "Requires Windows Security Event ID 4624. Enable 'Audit Logon' (Success) in Advanced Audit Policy → Account Logon.",
            "Filter known administrative hosts and service accounts to reduce volume.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Security",
        "spl_filter": "EventCode=4624",
        "spl_field": "LogonType",
        "kql_field": "event.code",
        "kql_keep": "@timestamp, host.name, user.name, source.ip, winlog.event_data.LogonType",
    },
    "failed_logon": {
        "logsource": {"product": "windows", "service": "security"},
        "detection_field": None,
        "level": "medium",
        "tags": ["attack.credential_access", "attack.t1110"],
        "falsepositives": [
            "Misconfigured service accounts with expired passwords",
            "Legitimate users forgetting their password",
            "Automated testing frameworks",
        ],
        "log_source_notes": [
            "Requires Windows Security Event ID 4625. Enable 'Audit Logon' (Failure) in Advanced Audit Policy.",
            "The count threshold (>10 failures) must be tuned for your environment's baseline authentication volume.",
        ],
        "spl_sourcetype": "XmlWinEventLog:Security",
        "spl_filter": "EventCode=4625",
        "spl_field": "SubjectUserName",
        "kql_field": "event.code",
        "kql_keep": "@timestamp, host.name, user.name, source.ip",
    },
    "service_installation": {
        "logsource": {"product": "windows", "service": "system"},
        "detection_field": None,
        "level": "high",
        "tags": ["attack.persistence", "attack.t1543.003"],
        "falsepositives": [
            "Legitimate software installing Windows services",
            "AV/EDR product driver and service installation",
            "Approved IT automation installing agents",
        ],
        "log_source_notes": [
            "Requires Windows System Event ID 7045 (A new service was installed). This event is logged by default.",
            "Filter known-good service names (e.g., your AV/EDR product names) to reduce noise.",
        ],
        "spl_sourcetype": "XmlWinEventLog:System",
        "spl_filter": "EventCode=7045",
        "spl_field": "ServiceName",
        "kql_field": "event.code",
        "kql_keep": "@timestamp, host.name, winlog.event_data.ServiceName, winlog.event_data.ServiceFileName",
    },
    "generic": {
        "logsource": {"product": "windows"},
        "detection_field": "Message|contains",
        "level": "medium",
        "tags": [],
        "falsepositives": [
            "Legitimate administrative activity",
            "Software installers and update mechanisms",
        ],
        "log_source_notes": [
            "Specify the correct Sigma log source (category, product, service) for your detection scenario.",
            "Review which audit policies or sensor configuration is required.",
        ],
        "spl_sourcetype": "WinEventLog",
        "spl_filter": "",
        "spl_field": "Message",
        "kql_field": "message",
        "kql_keep": "@timestamp, host.name, user.name, message",
    },
}


# ─── event type detection ─────────────────────────────────────────────────────

def _detect_event_type(description: str, hint: Optional[str]) -> str:
    if hint and hint in _TEMPLATES:
        return hint
    desc_lower = description.lower()
    scores = {et: 0 for et in _ET_KEYWORDS}
    for et, kws in _ET_KEYWORDS.items():
        for kw in kws:
            if kw in desc_lower:
                scores[et] += 1
    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "generic"


# ─── keyword extraction ───────────────────────────────────────────────────────

def _extract_keyword(description: str, event_type: str = "generic") -> str:
    # Prefer quoted strings (double or single)
    quoted = re.findall(r'"([^"]{1,80})"', description)
    if quoted:
        return quoted[0]
    backtick = re.findall(r'`([^`]{1,80})`', description)
    if backtick:
        return backtick[0]

    # PowerShell / .NET cmdlet-style names (Verb-Noun)
    cmdlets = re.findall(r'\b([A-Z][a-zA-Z]+-[A-Za-z]+)\b', description)
    if cmdlets:
        return cmdlets[0]

    # IP addresses (useful for network_connection)
    if event_type == "network_connection":
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', description)
        if ips:
            return ips[0]
        ports = re.findall(r'\bport\s+(\d{2,5})\b', description, re.IGNORECASE)
        if ports:
            return ports[0]

    # Executable names
    exes = re.findall(r'\b([\w-]+\.exe)\b', description, re.IGNORECASE)
    if exes:
        return exes[0]

    # Domain names (useful for dns_query)
    if event_type == "dns_query":
        domains = re.findall(r'\b((?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|xyz|ru|cn|info|biz))\b', description)
        if domains:
            return domains[0]

    # Generic: longest meaningful word (> 5 chars, not a stop word)
    stop = {
        "detect", "detection", "looking", "behavior", "activity", "event",
        "suspicious", "malicious", "unusual", "create", "monitor", "alert",
        "generate", "produce", "should", "would", "could", "using", "when",
        "where", "which", "download", "downloading", "process", "system",
    }
    words = [
        w.strip(".,;:()[]") for w in description.split()
        if len(w) > 5 and w.lower().strip(".,;:()[]") not in stop
    ]
    return words[0] if words else "REPLACE_WITH_ACTUAL_VALUE"


# ─── YAML building ────────────────────────────────────────────────────────────

def _detection_block(event_type: str, keyword: str) -> str:
    if event_type == "user_logon":
        return (
            "  selection:\n"
            "    EventID: 4624\n"
            "    LogonType: 3\n"
            "  condition: selection"
        )
    if event_type == "failed_logon":
        return (
            "  selection:\n"
            "    EventID: 4625\n"
            "  condition: selection | count(SubjectUserName) > 10"
        )
    if event_type == "service_installation":
        return (
            "  selection:\n"
            "    EventID: 7045\n"
            "  condition: selection"
        )
    field = _TEMPLATES[event_type]["detection_field"]
    kw_safe = keyword.replace("'", "\\'")
    return (
        f"  selection:\n"
        f"    {field}: '{kw_safe}'\n"
        f"  condition: selection"
    )


def build_sigma_yaml(title: str, description: str, event_type: str, keyword: str) -> str:
    rule_id = str(uuid.uuid4())
    today = date.today().isoformat()
    tmpl = _TEMPLATES[event_type]

    # Indent description for YAML literal block scalar
    desc_indented = "\n".join("  " + line for line in description.split("\n"))

    tags_section = ""
    if tmpl.get("tags"):
        tags_lines = "\n".join(f"  - {t}" for t in tmpl["tags"])
        tags_section = f"tags:\n{tags_lines}\n"

    ls_lines = "\n".join(f"  {k}: {v}" for k, v in tmpl["logsource"].items())
    fp_lines = "\n".join(f"  - {fp}" for fp in tmpl["falsepositives"])
    title_safe = title.replace('"', "'")

    return (
        f'title: "{title_safe}"\n'
        f"id: {rule_id}\n"
        f"status: experimental\n"
        f"description: |\n"
        f"{desc_indented}\n"
        f"\n"
        f"  NOTE: Draft rule generated by SOC Copilot Workbench.\n"
        f"  Review and test against real log data before production deployment.\n"
        f"author: SOC Copilot Workbench (Draft)\n"
        f"date: {today}\n"
        f"modified: {today}\n"
        f"{tags_section}"
        f"logsource:\n"
        f"{ls_lines}\n"
        f"detection:\n"
        f"{_detection_block(event_type, keyword)}\n"
        f"falsepositives:\n"
        f"{fp_lines}\n"
        f"level: {tmpl['level']}\n"
    )


# ─── SPL building ─────────────────────────────────────────────────────────────

def build_spl(event_type: str, keyword: str) -> str:
    tmpl = _TEMPLATES[event_type]
    src = tmpl["spl_sourcetype"]
    flt = tmpl["spl_filter"]
    field = tmpl["spl_field"]

    if event_type == "user_logon":
        return (
            f'index=* sourcetype="{src}" {flt} LogonType=3\n'
            "| table _time, host, SubjectUserName, TargetUserName, IpAddress, LogonType\n"
            "| sort -_time"
        )
    if event_type == "failed_logon":
        return (
            f'index=* sourcetype="{src}" {flt}\n'
            "| stats count by SubjectUserName\n"
            "| where count > 10\n"
            "| sort -count"
        )
    if event_type == "service_installation":
        return (
            f'index=* sourcetype="{src}" {flt}\n'
            "| table _time, host, ServiceName, ServiceType, ServiceFileName\n"
            "| sort -_time"
        )
    filter_part = f" {flt}" if flt else ""
    keep = tmpl["kql_keep"].replace("@timestamp", "_time").replace("host.name", "host").replace("user.name", "user")
    return (
        f'index=* sourcetype="{src}"{filter_part}\n'
        f'| search {field}="*{keyword}*"\n'
        f"| table _time, host, user, {field}\n"
        "| sort -_time"
    )


# ─── KQL / ES|QL building ─────────────────────────────────────────────────────

def build_kql(event_type: str, keyword: str) -> str:
    if event_type == "user_logon":
        return 'event.code : "4624" and winlog.event_data.LogonType : "3"'
    if event_type == "failed_logon":
        return 'event.code : "4625"'
    if event_type == "service_installation":
        return 'event.code : "7045"'
    field = _TEMPLATES[event_type]["kql_field"]
    return f'{field} : "*{keyword}*"'


def build_esql(event_type: str, keyword: str) -> str:
    tmpl = _TEMPLATES[event_type]
    keep = tmpl["kql_keep"]

    if event_type == "user_logon":
        return (
            "FROM logs-*\n"
            '| WHERE event.code == "4624" AND winlog.event_data.LogonType == "3"\n'
            f"| KEEP {keep}\n"
            "| SORT @timestamp DESC\n"
            "| LIMIT 100"
        )
    if event_type == "failed_logon":
        return (
            "FROM logs-*\n"
            '| WHERE event.code == "4625"\n'
            "| STATS failure_count = COUNT() BY user.name\n"
            "| WHERE failure_count > 10\n"
            "| SORT failure_count DESC"
        )
    if event_type == "service_installation":
        return (
            "FROM logs-*\n"
            '| WHERE event.code == "7045"\n'
            f"| KEEP {keep}\n"
            "| SORT @timestamp DESC\n"
            "| LIMIT 100"
        )
    field = tmpl["kql_field"]
    return (
        "FROM logs-*\n"
        f'| WHERE {field} LIKE "*{keyword}*"\n'
        f"| KEEP {keep}\n"
        "| SORT @timestamp DESC\n"
        "| LIMIT 100"
    )


# ─── validation warnings ──────────────────────────────────────────────────────

def _extra_warnings(event_type: str, keyword: str) -> list:
    warnings = []
    if "REPLACE_WITH" in keyword:
        warnings.append(
            "No specific detection value was extracted from your description — "
            "replace 'REPLACE_WITH_ACTUAL_VALUE' in all queries with a real indicator."
        )
    if event_type == "generic":
        warnings.append(
            "Event type could not be auto-detected — manually set the correct Sigma "
            "logsource (category, product, service) before using this rule."
        )
    if event_type == "failed_logon":
        warnings.append(
            "Threshold-based rule — calibrate the failure count threshold (>10) "
            "against your environment's normal authentication baseline."
        )
    return warnings


# ─── public entry point ───────────────────────────────────────────────────────

def generate_rule_draft(
    description: str,
    event_type: Optional[str] = None,
    example_fields: Optional[dict] = None,
) -> dict:
    """
    Generate Sigma YAML, SPL, KQL, and ES|QL rule drafts from a description.

    Returns a dict with all rule text, false positives, log source notes,
    validation warnings, and a quality disclaimer.
    """
    detected_type = _detect_event_type(description, event_type)
    keyword = _extract_keyword(description, detected_type)

    # If example_fields provided, override keyword with a real observed value
    if example_fields:
        for fname in ("CommandLine", "TargetFilename", "QueryName",
                      "DestinationIp", "TargetObject", "Message"):
            val = str(example_fields.get(fname, "")).strip()[:100]
            if val:
                keyword = val
                break

    title = (
        f"{_ET_TITLE.get(detected_type, 'Suspicious Activity')} — "
        f"{description[:45].rstrip()}{'…' if len(description) > 45 else ''}"
    )
    tmpl = _TEMPLATES[detected_type]

    return {
        "event_type_detected": detected_type,
        "event_type_label": EVENT_TYPE_LABELS.get(detected_type, detected_type),
        "keyword_extracted": keyword,
        "sigma_yaml": build_sigma_yaml(title, description, detected_type, keyword),
        "spl_query": build_spl(detected_type, keyword),
        "kql_query": build_kql(detected_type, keyword),
        "esql_query": build_esql(detected_type, keyword),
        "false_positives": tmpl["falsepositives"],
        "log_source_notes": tmpl["log_source_notes"],
        "validation_warnings": _VALIDATION_WARNINGS_BASE + _extra_warnings(detected_type, keyword),
        "quality_disclaimer": QUALITY_DISCLAIMER,
    }
