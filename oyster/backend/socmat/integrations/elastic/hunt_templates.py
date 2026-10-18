"""
ECS-based KQL / ES|QL Hunt Template library.

Seven templates covering the most common threat hunting scenarios in Elastic.
Each template includes both a KQL query (for Kibana Discover) and an ES|QL
query (for Kibana ES|QL / Elasticsearch 8.11+).
"""

from typing import Any, Dict, List

HUNT_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "encoded_powershell",
        "title": "Encoded PowerShell Execution",
        "description": "Detect PowerShell invoked with an encoded command argument.",
        "kql_query": (
            'process.name: "powershell.exe" AND\n'
            "process.command_line: (*-enc* OR *-EncodedCommand* OR *-ec* OR *-encodedcommand*)"
        ),
        "esql_query": (
            "FROM logs-*,winlogbeat-*\n"
            '| WHERE process.name == "powershell.exe"\n'
            "  AND (\n"
            '    process.command_line LIKE "*-enc*" OR\n'
            '    process.command_line LIKE "*-EncodedCommand*" OR\n'
            '    process.command_line LIKE "*-ec *"\n'
            "  )\n"
            "| KEEP @timestamp, host.name, user.name, process.name, process.command_line\n"
            "| SORT @timestamp DESC"
        ),
        "index_pattern": "logs-*,winlogbeat-*,filebeat-*",
        "detects": (
            "PowerShell processes invoked with a Base64-encoded command payload, "
            "used by threat actors to obfuscate malicious scripts and bypass command-line "
            "detection."
        ),
        "required_ecs_fields": [
            "@timestamp", "host.name", "user.name",
            "process.name", "process.command_line",
        ],
        "false_positives": [
            "Legitimate automation scripts that use encoded commands for safe transport",
            "Configuration management tools (SCCM, DSC, Ansible WinRM modules)",
        ],
        "recommended_pivots": [
            "Decode the Base64 payload and review its intent",
            "Check for Sysmon EventID 3 (network) from the same process",
            "Review parent process — look for Office, browser, or document viewer parents",
            "Correlate with email gateway logs for phishing delivery at the same time",
        ],
    },
    {
        "id": "suspicious_child_process",
        "title": "Suspicious Child Process from Office or Browser",
        "description": (
            "Detect shell or script interpreters spawned by productivity apps "
            "— a classic phishing/macro execution pattern."
        ),
        "kql_query": (
            'process.parent.name: ("winword.exe" OR "excel.exe" OR "powerpnt.exe" OR\n'
            '                       "outlook.exe" OR "acrord32.exe" OR "chrome.exe" OR "msedge.exe") AND\n'
            'process.name: ("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR\n'
            '               "cscript.exe" OR "mshta.exe" OR "rundll32.exe")'
        ),
        "esql_query": (
            "FROM logs-*,winlogbeat-*\n"
            '| WHERE process.parent.name IN\n'
            '    ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","chrome.exe","msedge.exe")\n'
            '  AND process.name IN\n'
            '    ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")\n'
            "| KEEP @timestamp, host.name, user.name, process.parent.name, process.name, process.command_line\n"
            "| SORT @timestamp DESC"
        ),
        "index_pattern": "logs-*,winlogbeat-*",
        "detects": (
            "Shell or scripting engine processes spawned by Office applications or browsers, "
            "commonly seen in macro-based phishing attacks and drive-by download scenarios."
        ),
        "required_ecs_fields": [
            "@timestamp", "host.name", "user.name",
            "process.name", "process.parent.name", "process.command_line",
        ],
        "false_positives": [
            "Legitimate Office add-ins that invoke helper processes",
            "Browser extension updaters that spawn command-line tools",
        ],
        "recommended_pivots": [
            "Review the full process tree for subsequent execution chains",
            "Correlate with email delivery logs for the same user and time window",
            "Check for file drops in TEMP or AppData directories (Sysmon EventID 11)",
            "Look for network connections initiated by the child process",
        ],
    },
    {
        "id": "new_service_creation",
        "title": "New Windows Service Created",
        "description": (
            "Detect Windows service creation events — a common persistence "
            "and privilege escalation technique."
        ),
        "kql_query": (
            'event.code: "4697" AND\n'
            'event.provider: "Microsoft-Windows-Security-Auditing"'
        ),
        "esql_query": (
            "FROM logs-*,winlogbeat-*\n"
            '| WHERE event.code == "4697"\n'
            '  AND event.provider == "Microsoft-Windows-Security-Auditing"\n'
            "| KEEP @timestamp, host.name, user.name, event.action, process.name\n"
            "| SORT @timestamp DESC"
        ),
        "index_pattern": "logs-*,winlogbeat-*",
        "detects": (
            "New service installations (Windows EventCode 4697) that may indicate "
            "persistence via a malicious service binary or privilege escalation via "
            "a writable service path."
        ),
        "required_ecs_fields": [
            "@timestamp", "host.name", "user.name", "event.code", "event.action",
        ],
        "false_positives": [
            "Software installation and update processes",
            "EDR, AV, or monitoring agent deployments",
        ],
        "recommended_pivots": [
            "Review the service binary path — is it in a temp or user-writable directory?",
            "Hash the binary and check threat intelligence feeds",
            "Identify the installing account and review its recent activity",
            "Correlate with process creation events for the service executable",
        ],
    },
    {
        "id": "rare_outbound_destination",
        "title": "Rare Outbound Network Destination",
        "description": (
            "Surface processes making outbound connections to external IP addresses "
            "— potential C2 communication or data exfiltration."
        ),
        "kql_query": (
            'event.category: "network" AND network.direction: "egress" AND\n'
            'NOT destination.ip: ("10.*" OR "192.168.*" OR "172.16.*" OR\n'
            '                     "172.17.*" OR "172.18.*" OR "172.19.*" OR\n'
            '                     "172.2*" OR "172.3*" OR "127.*" OR "::1")'
        ),
        "esql_query": (
            "FROM logs-*,filebeat-*\n"
            '| WHERE event.category == "network" AND network.direction == "egress"\n'
            '  AND NOT CIDR_MATCH(destination.ip, "10.0.0.0/8", "192.168.0.0/16",\n'
            '                     "172.16.0.0/12", "127.0.0.0/8")\n'
            "| STATS count = COUNT(), dest_ips = VALUES(destination.ip)\n"
            "        BY host.name, user.name, process.name\n"
            "| SORT count DESC"
        ),
        "index_pattern": "logs-*,filebeat-*,packetbeat-*",
        "detects": (
            "Processes establishing outbound connections to external IP addresses, "
            "potentially indicating C2 communication, data exfiltration, or beaconing."
        ),
        "required_ecs_fields": [
            "@timestamp", "host.name", "user.name", "process.name",
            "destination.ip", "source.ip", "network.direction",
        ],
        "false_positives": [
            "Browsers and update agents making legitimate internet requests",
            "Cloud sync clients (OneDrive, Dropbox, Google Drive)",
        ],
        "recommended_pivots": [
            "Resolve destination IPs against threat intelligence feeds",
            "Look for beaconing: periodic connections at regular intervals",
            "Review the process binary hash and parent process",
            "Check DNS queries from the same host around the connection time",
        ],
    },
    {
        "id": "dns_tunneling",
        "title": "DNS Tunneling Candidates",
        "description": (
            "Identify unusually long or high-frequency DNS queries that may "
            "indicate DNS tunneling for C2 or data exfiltration."
        ),
        "kql_query": (
            "dns.question.name: * AND\n"
            'NOT dns.question.name: ("*.microsoft.com" OR "*.windows.com" OR\n'
            '                        "*.google.com" OR "*.amazonaws.com")'
        ),
        "esql_query": (
            "FROM logs-*,filebeat-*,packetbeat-*\n"
            "| WHERE dns.question.name IS NOT NULL\n"
            "| EVAL name_len = LENGTH(dns.question.name)\n"
            "| WHERE name_len > 40\n"
            "| STATS count = COUNT(), avg_len = AVG(name_len)\n"
            "        BY dns.question.name, source.ip\n"
            "| WHERE count > 5\n"
            "| SORT count DESC"
        ),
        "index_pattern": "logs-*,filebeat-*,packetbeat-*",
        "detects": (
            "Abnormally long DNS hostnames or high query frequency from a single host, "
            "patterns commonly associated with DNS tunneling tools such as dnscat2 or iodine."
        ),
        "required_ecs_fields": [
            "@timestamp", "source.ip", "dns.question.name", "host.name",
        ],
        "false_positives": [
            "CDN edge nodes with long CNAME chains",
            "Certificate validation queries with long subject-alternative-name fields",
        ],
        "recommended_pivots": [
            "Check the registered domain (rDNS) against threat intelligence",
            "Look for repetitive subdomain patterns that encode data (hex or base32)",
            "Correlate with endpoint logs for the process making the DNS request",
            "Review outbound traffic volume — exfil typically has high byte counts",
        ],
    },
    {
        "id": "auth_failure_then_success",
        "title": "Authentication Failures Followed by Success",
        "description": (
            "Identify accounts with multiple failed logins that were eventually "
            "authenticated — a credential compromise indicator."
        ),
        "kql_query": (
            'event.code: ("4625" OR "4624") AND\n'
            'event.provider: "Microsoft-Windows-Security-Auditing"'
        ),
        "esql_query": (
            "FROM logs-*,winlogbeat-*\n"
            '| WHERE event.code IN ("4625", "4624")\n'
            '| EVAL outcome = CASE(event.code == "4624", "success", "failure")\n'
            '| STATS failures = COUNT_IF(outcome == "failure"),\n'
            '        successes = COUNT_IF(outcome == "success")\n'
            "        BY user.name, source.ip\n"
            "| WHERE failures > 3 AND successes > 0\n"
            "| SORT failures DESC"
        ),
        "index_pattern": "logs-*,winlogbeat-*",
        "detects": (
            "User accounts that experienced multiple authentication failures followed by "
            "a successful login, indicating a likely brute-force or password-spray compromise."
        ),
        "required_ecs_fields": [
            "@timestamp", "user.name", "source.ip", "event.code", "host.name",
        ],
        "false_positives": [
            "Users mistyping their password before a successful login",
            "Automated scripts that cycle through cached credentials after a password change",
        ],
        "recommended_pivots": [
            "Review post-logon process and network activity for lateral movement",
            "Check the source IP against known VPN exit nodes and corporate ranges",
            "Correlate with endpoint logs for the session after the successful login",
            "Look for privilege escalation attempts shortly after the logon",
        ],
    },
    {
        "id": "suspicious_script_interpreter",
        "title": "Suspicious Script Interpreter Usage",
        "description": (
            "Detect LOLBins and script interpreters commonly abused for payload "
            "delivery, defense evasion, and code execution."
        ),
        "kql_query": (
            'process.name: ("wscript.exe" OR "cscript.exe" OR "mshta.exe" OR\n'
            '               "regsvr32.exe" OR "certutil.exe" OR "msiexec.exe" OR\n'
            '               "installutil.exe" OR "regasm.exe" OR "regsvcs.exe")'
        ),
        "esql_query": (
            "FROM logs-*,winlogbeat-*\n"
            '| WHERE process.name IN\n'
            '    ("wscript.exe","cscript.exe","mshta.exe","regsvr32.exe",\n'
            '     "certutil.exe","msiexec.exe","installutil.exe","regasm.exe")\n'
            "| STATS count = COUNT()\n"
            "        BY host.name, user.name, process.name, process.command_line\n"
            "| SORT count DESC"
        ),
        "index_pattern": "logs-*,winlogbeat-*",
        "detects": (
            "Living-off-the-land binaries (LOLBins) and Windows script interpreters commonly "
            "abused to execute malicious payloads while evading detection based on process name."
        ),
        "required_ecs_fields": [
            "@timestamp", "host.name", "user.name", "process.name",
            "process.command_line", "process.parent.name",
        ],
        "false_positives": [
            "msiexec.exe during legitimate software installation flows",
            "certutil.exe used by PKI infrastructure for certificate management",
            "regsvr32.exe during COM component registration by installed applications",
        ],
        "recommended_pivots": [
            "Review the full command line for external URLs or suspicious file paths",
            "Identify the parent process — look for Office, browser, or email clients",
            "Check for network connections from the process (Sysmon EventID 3)",
            "Correlate with web proxy or email logs for the same user and host",
        ],
    },
]

# Keyword → template id mapping for the hunt assistant
INTENT_KEYWORDS: Dict[str, List[str]] = {
    "encoded_powershell": [
        "powershell", "encoded", "base64", "-enc", "obfuscat", "lolbin ps",
    ],
    "suspicious_child_process": [
        "child process", "spawn", "lineage", "parent", "word", "office",
        "macro", "document", "phishing",
    ],
    "new_service_creation": [
        "service", "persist", "4697", "new service", "install service",
    ],
    "rare_outbound_destination": [
        "outbound", "rare", "external", "destination", "exfil", "c2", "beacon",
        "network", "egress",
    ],
    "dns_tunneling": [
        "dns", "tunnel", "dnscat", "iodine", "dns exfil", "covert channel",
    ],
    "auth_failure_then_success": [
        "fail", "brute", "spray", "4625", "credential", "auth fail",
        "login fail", "compromise",
    ],
    "suspicious_script_interpreter": [
        "script", "interpreter", "wscript", "cscript", "mshta", "lolbin",
        "regsvr32", "certutil", "rundll32", "msiexec",
    ],
}
