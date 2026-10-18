"""
SPL Query Template library.

Seven templates covering the most common SOC investigation scenarios.
Each template is a plain dict matching the SPLQueryTemplate Pydantic schema.
"""

from typing import Any, Dict, List

QUERY_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "failed_logins",
        "title": "Failed Logins",
        "description": "Detect repeated authentication failures for a single account.",
        "spl_query": (
            "index=* sourcetype=WinEventLog:Security EventCode=4625\n"
            "| stats count by user, src_ip, dest_ip\n"
            "| where count > 5\n"
            "| sort -count"
        ),
        "index_sourcetype": "index=* sourcetype=WinEventLog:Security",
        "detects": (
            "Multiple failed authentication attempts that may indicate a "
            "brute-force or password-spray attack."
        ),
        "expected_fields": ["user", "src_ip", "dest_ip", "EventCode", "_time"],
        "false_positives": [
            "Locked-out accounts retrying cached credentials after a password change",
            "Service accounts with expired credentials",
        ],
        "investigation_steps": [
            "Determine whether failures originate from one IP (brute-force) "
            "or many IPs (spray).",
            "Check whether any targeted account subsequently authenticated "
            "successfully (EventCode 4624).",
            "Cross-reference src_ip against known VPN ranges and internal networks.",
            "Review the account's activity after any successful logon.",
        ],
    },
    {
        "id": "success_after_failures",
        "title": "Successful Login After Failed Logins",
        "description": (
            "Identify a successful authentication preceded by multiple failures "
            "— classic credential-compromise indicator."
        ),
        "spl_query": (
            "index=* sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)\n"
            "| eval outcome=if(EventCode=\"4624\",\"success\",\"failure\")\n"
            "| stats count(eval(outcome=\"failure\")) as failures,\n"
            "        count(eval(outcome=\"success\")) as successes\n"
            "        by user, src_ip\n"
            "| where failures > 3 AND successes > 0\n"
            "| sort -failures"
        ),
        "index_sourcetype": "index=* sourcetype=WinEventLog:Security",
        "detects": (
            "Accounts that experienced authentication failures followed by a "
            "successful login, indicating a possible credential compromise."
        ),
        "expected_fields": ["user", "src_ip", "EventCode", "_time"],
        "false_positives": [
            "User mistyping a password and then correcting it",
            "Automated scripts that rotate credentials",
        ],
        "investigation_steps": [
            "Identify the time gap between the last failure and the successful login.",
            "Check whether the successful-logon source IP matches the failure IP.",
            "Review post-logon activity for lateral movement, file access, or "
            "privilege escalation.",
            "Correlate with Sysmon process creation events for the authenticated session.",
        ],
    },
    {
        "id": "powershell_encoded",
        "title": "PowerShell Encoded Command",
        "description": (
            "Detect PowerShell processes using the -EncodedCommand flag "
            "— common in living-off-the-land attacks."
        ),
        "spl_query": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n"
            "| search process_name=*powershell*\n"
            "        (command_line=*-enc* OR command_line=*-EncodedCommand* OR command_line=*-ec*)\n"
            "| table _time, host, user, process_name, command_line\n"
            "| sort -_time"
        ),
        "index_sourcetype": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational"
        ),
        "detects": (
            "PowerShell processes invoked with a Base64-encoded command, used by "
            "threat actors to obfuscate payloads and bypass command-line inspection."
        ),
        "expected_fields": ["_time", "host", "user", "process_name", "command_line", "EventCode"],
        "false_positives": [
            "Legitimate automation scripts that use encoded commands for transport safety",
            "Configuration management tools (SCCM, Ansible, SaltStack)",
        ],
        "investigation_steps": [
            "Decode the Base64 payload and review its content.",
            "Identify the parent process that spawned PowerShell.",
            "Check for network connections initiated by the process (Sysmon EventCode 3).",
            "Look for follow-on file drops (EventCode 11) or registry modifications "
            "(EventCode 13).",
        ],
    },
    {
        "id": "new_service",
        "title": "New Service Installation",
        "description": (
            "Detect the creation of a new Windows service "
            "— a common persistence mechanism."
        ),
        "spl_query": (
            "index=* sourcetype=WinEventLog:Security EventCode=4697\n"
            "| table _time, host, user, ServiceName, ServiceFileName\n"
            "| sort -_time"
        ),
        "index_sourcetype": "index=* sourcetype=WinEventLog:Security",
        "detects": (
            "New Windows service installations (EventCode 4697) that may indicate "
            "persistence or privilege escalation via a malicious service binary."
        ),
        "expected_fields": ["_time", "host", "user", "ServiceName", "ServiceFileName", "EventCode"],
        "false_positives": [
            "Software installations and updates",
            "EDR, AV, or monitoring agent deployments",
        ],
        "investigation_steps": [
            "Check whether the service binary path is in a temp or user-writable directory.",
            "Hash the binary and look it up in threat intelligence.",
            "Review the installing account — was it a standard user or service account?",
            "Look for matching Sysmon process creation events for the service executable.",
        ],
    },
    {
        "id": "suspicious_process",
        "title": "Suspicious Process Execution",
        "description": "Detect LOLBins and commonly abused processes executing in the environment.",
        "spl_query": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n"
            "| search process_name IN "
            "(mshta.exe, regsvr32.exe, certutil.exe, wscript.exe, "
            "cscript.exe, rundll32.exe, msiexec.exe)\n"
            "| stats count by host, user, process_name, command_line\n"
            "| sort -count"
        ),
        "index_sourcetype": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational"
        ),
        "detects": (
            "Living-off-the-land binaries (LOLBins) commonly abused for payload delivery, "
            "defense evasion, or code execution."
        ),
        "expected_fields": ["_time", "host", "user", "process_name", "command_line"],
        "false_positives": [
            "msiexec.exe during legitimate software installation",
            "certutil.exe used by PKI infrastructure for certificate management",
        ],
        "investigation_steps": [
            "Review the full command line for external URL references or suspicious paths.",
            "Identify the parent process — look for Office, browser, or scripting engine parents.",
            "Check for network connections initiated by the process (Sysmon EventCode 3).",
            "Correlate with email or web proxy logs for the same user/host at the same time.",
        ],
    },
    {
        "id": "rare_parent_child",
        "title": "Rare Parent-Child Process Pairs",
        "description": "Surface unusual process lineage that deviates from expected relationships.",
        "spl_query": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n"
            "| stats count by ParentImage, Image\n"
            "| where count < 5\n"
            "| sort count"
        ),
        "index_sourcetype": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational"
        ),
        "detects": (
            "Unusual parent-child process relationships that occur rarely in the environment, "
            "such as Word → PowerShell, Explorer → cmd, or svchost → cmd."
        ),
        "expected_fields": ["_time", "host", "user", "Image", "ParentImage", "CommandLine"],
        "false_positives": [
            "Rare but legitimate administrative tooling",
            "First-run software installers that call unusual helpers once",
        ],
        "investigation_steps": [
            "Focus on pairs where a document reader, browser, or productivity app spawns a shell.",
            "Review full command lines for both parent and child.",
            "Check whether the occurrence coincides with a phishing email delivery time.",
            "Cross-reference the host with recent vulnerability exploitation attempts.",
        ],
    },
    {
        "id": "outbound_connections",
        "title": "Outbound Network Connections",
        "description": "Identify processes making outbound connections to external IP addresses.",
        "spl_query": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3\n"
            "| where NOT (dest_ip LIKE \"10.%\" OR dest_ip LIKE \"192.168.%\" "
            "OR dest_ip LIKE \"172.16.%\")\n"
            "| stats count, values(dest_ip) as dest_ips, values(DestinationPort) as ports\n"
            "        by host, user, process_name\n"
            "| sort -count"
        ),
        "index_sourcetype": (
            "index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational"
        ),
        "detects": (
            "Processes establishing outbound connections to external IPs, potentially "
            "indicating C2 communication, data exfiltration, or beaconing."
        ),
        "expected_fields": ["_time", "host", "user", "process_name", "dest_ip", "DestinationPort"],
        "false_positives": [
            "Browsers and update agents making legitimate internet requests",
            "Cloud sync clients (OneDrive, Dropbox, Google Drive)",
        ],
        "investigation_steps": [
            "Resolve destination IPs and check against threat intelligence feeds.",
            "Look for beaconing: periodic connections at regular intervals.",
            "Check the process binary hash and parent process.",
            "Review DNS queries from the host around the connection time.",
        ],
    },
]

# Keyword → template id mapping for the query assistant
INTENT_KEYWORDS: Dict[str, List[str]] = {
    "failed_logins": [
        "fail", "brute", "spray", "4625", "login fail", "auth fail",
    ],
    "success_after_failures": [
        "success after", "compromise", "4624 after", "after fail", "credential",
    ],
    "powershell_encoded": [
        "powershell", "encoded", "base64", "obfuscat", "-enc", "lolbin ps",
    ],
    "new_service": [
        "service", "persist", "4697", "install service",
    ],
    "suspicious_process": [
        "lolbin", "mshta", "regsvr32", "certutil", "rundll32", "wscript",
        "cscript", "suspicious process", "abuse",
    ],
    "rare_parent_child": [
        "parent", "child", "lineage", "spawn", "unusual process", "process pair",
    ],
    "outbound_connections": [
        "outbound", "network", "c2", "exfil", "beacon", "external", "connection",
    ],
}
