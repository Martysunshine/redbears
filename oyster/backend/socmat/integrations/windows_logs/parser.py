"""
Windows Event Log and Sysmon log parser.

Supports JSON (array or newline-delimited) and CSV exports.
Normalises each record into a common structure and runs
lightweight detection logic to flag suspicious patterns.
"""

import csv
import io
import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Windows / Sysmon event ID catalogue
# ---------------------------------------------------------------------------

EVENT_NAMES: Dict[str, str] = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4627": "Group Membership",
    "4648": "Logon with Explicit Credentials",
    "4672": "Special Privileges Assigned",
    "4688": "Process Creation",
    "4689": "Process Terminated",
    "4698": "Scheduled Task Created",
    "4699": "Scheduled Task Deleted",
    "4700": "Scheduled Task Enabled",
    "4702": "Scheduled Task Updated",
    "4720": "User Account Created",
    "4728": "Member Added to Security Group",
    "4732": "Member Added to Local Group",
    "4756": "Member Added to Universal Group",
    "7045": "Service Installed",
    "7036": "Service Changed State",
    # Sysmon
    "1":  "Sysmon: Process Creation",
    "3":  "Sysmon: Network Connection",
    "7":  "Sysmon: Image Loaded",
    "11": "Sysmon: File Created",
    "12": "Sysmon: Registry Object Created/Deleted",
    "13": "Sysmon: Registry Value Set",
    "22": "Sysmon: DNS Query",
    "23": "Sysmon: File Deleted",
}

# ---------------------------------------------------------------------------
# Field name aliases — maps a variety of export column names to canonical keys
# ---------------------------------------------------------------------------

FIELD_ALIASES: Dict[str, str] = {
    # Timestamp variants
    "timecreated": "timestamp",
    "time_created": "timestamp",
    "systemtime": "timestamp",
    "system_time": "timestamp",
    "eventtime": "timestamp",
    "event_time": "timestamp",
    "timestamp": "timestamp",
    "@timestamp": "timestamp",
    "_time": "timestamp",
    "date": "timestamp",
    # Event ID
    "eventid": "event_id",
    "event_id": "event_id",
    "eventcode": "event_id",
    "event_code": "event_id",
    "id": "event_id",
    # Host
    "computer": "host",
    "computername": "host",
    "computer_name": "host",
    "hostname": "host",
    "host": "host",
    "host.name": "host",
    # User / Account
    "accountname": "user",
    "account_name": "user",
    "targetusername": "user",
    "target_username": "user",
    "subjectusername": "user",
    "subject_username": "user",
    "username": "user",
    "user.name": "user",
    "user": "user",
    # Process
    "newprocessname": "process_name",
    "new_process_name": "process_name",
    "processname": "process_name",
    "process_name": "process_name",
    "image": "process_name",
    "process.name": "process_name",
    "parentprocessname": "parent_process_name",
    "parent_process_name": "parent_process_name",
    "parentimage": "parent_process_name",
    "parentprocessid": "parent_process_name",
    # Command line
    "commandline": "command_line",
    "command_line": "command_line",
    "processcreationinfo.commandline": "command_line",
    # Source IP
    "ipaddress": "source_ip",
    "ip_address": "source_ip",
    "source_ip": "source_ip",
    "src_ip": "source_ip",
    "source.ip": "source_ip",
    "ipaddressv4": "source_ip",
    # Destination IP
    "destination_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "destinationip": "destination_ip",
    "destinationhostname": "destination_ip",
    # Destination port
    "destination_port": "destination_port",
    "destinationport": "destination_port",
    "dest_port": "destination_port",
    # DNS
    "queryname": "dns_query",
    "query": "dns_query",
    # Channel / log source
    "channel": "channel",
    "logname": "channel",
}

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe",
    "cscript.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "msiexec.exe", "wmic.exe", "net.exe", "net1.exe", "psexec.exe",
    "at.exe", "schtasks.exe", "bitsadmin.exe", "curl.exe", "wget.exe",
}

ENCODED_CMD_RE = re.compile(r"(?i)(?:-e|-en|-enc|-enco|-encod(?:ed(?:command)?)?)\s+[A-Za-z0-9+/=]{20,}")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


# ---------------------------------------------------------------------------
# Normalise a single raw record
# ---------------------------------------------------------------------------

def _coerce_key(k: str) -> str:
    return FIELD_ALIASES.get(k.lower().strip(), k.lower().strip())


def normalise_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map a raw dict (from JSON or CSV) to canonical fields."""
    out: Dict[str, Any] = {}
    for k, v in raw.items():
        canon = _coerce_key(k)
        if canon not in out:
            out[canon] = str(v).strip() if v is not None else ""

    # Flatten nested "EventData" / "System" dicts common in Sysmon JSON exports
    for wrapper in ("eventdata", "system", "event_data", "userdata"):
        if wrapper in out:
            try:
                sub = json.loads(out[wrapper]) if isinstance(out[wrapper], str) else out[wrapper]
                if isinstance(sub, dict):
                    for k2, v2 in sub.items():
                        canon2 = _coerce_key(k2)
                        if canon2 not in out:
                            out[canon2] = str(v2).strip() if v2 is not None else ""
            except (json.JSONDecodeError, TypeError):
                pass

    return out


def _parse_timestamp(raw: Dict[str, Any]) -> Optional[datetime]:
    ts = raw.get("timestamp", "")
    if not ts:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ):
        try:
            return datetime.strptime(ts[:26], fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Detection logic — returns list of (description, severity) per record
# ---------------------------------------------------------------------------

def _detect(rec: Dict[str, Any], context: Dict[str, Any]) -> List[Tuple[str, str]]:
    findings: List[Tuple[str, str]] = []
    eid = rec.get("event_id", "")
    user = rec.get("user", "")
    host = rec.get("host", "")
    cmd = rec.get("command_line", "").lower()
    proc = rec.get("process_name", "").lower()
    parent = rec.get("parent_process_name", "").lower()
    src_ip = rec.get("source_ip", "")
    dest_ip = rec.get("destination_ip", "")

    proc_base = proc.split("\\")[-1] if proc else ""
    parent_base = parent.split("\\")[-1] if parent else ""

    # Track failed logons per (user, src_ip)
    if eid == "4625":
        key = f"{user}|{src_ip}"
        context.setdefault("failed_logons", defaultdict(int))
        context["failed_logons"][key] += 1
        if context["failed_logons"][key] == 5:
            findings.append((
                f"5+ failed logons for '{user}' from {src_ip or 'unknown IP'} — possible brute force",
                "high",
            ))

    # Successful logon after prior failures
    if eid == "4624":
        key = f"{user}|{src_ip}"
        if context.get("failed_logons", {}).get(key, 0) >= 3:
            findings.append((
                f"Successful logon for '{user}' after {context['failed_logons'][key]} failures — possible credential spray success",
                "high",
            ))

    # Special privileges assigned
    if eid == "4672":
        if user and not user.lower().endswith("$"):
            findings.append((
                f"Special privileges assigned to '{user}' on {host or 'unknown host'}",
                "medium",
            ))

    # Service installed
    if eid == "7045":
        svc = rec.get("servicename", rec.get("param1", ""))
        findings.append((
            f"New service installed: '{svc}' on {host or 'unknown host'} — review for persistence",
            "high",
        ))

    # Scheduled task created
    if eid in ("4698", "4700", "4702"):
        task = rec.get("taskname", rec.get("taskpath", ""))
        findings.append((
            f"Scheduled task created/modified: '{task}' by '{user}'",
            "medium",
        ))

    # Process creation — check for suspicious patterns
    if eid in ("4688", "1"):
        # Encoded PowerShell command
        if "powershell" in proc_base or "pwsh" in proc_base:
            if ENCODED_CMD_RE.search(cmd):
                findings.append((
                    f"PowerShell with encoded command executed by '{user}': {cmd[:120]}",
                    "high",
                ))
            elif "-nop" in cmd or "-noni" in cmd or "bypass" in cmd:
                findings.append((
                    f"PowerShell with execution-policy bypass flags: {cmd[:120]}",
                    "medium",
                ))

        # cmd.exe spawning powershell
        if "cmd" in parent_base and "powershell" in proc_base:
            findings.append((
                f"cmd.exe → powershell.exe process chain detected (user: '{user}')",
                "medium",
            ))

        # certutil with decode / urlcache — specific check takes priority over generic LOLBIN
        _certutil_specific_fired = False
        if "certutil" in proc_base and any(x in cmd for x in ("-decode", "-urlcache", "-split")):
            findings.append((
                f"certutil used for potential file download/decode: {cmd[:120]}",
                "high",
            ))
            _certutil_specific_fired = True

        # Suspicious LOLBIN execution (skip certutil if the specific rule already fired)
        for lolbin in ("mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "wscript.exe", "cscript.exe"):
            if lolbin in proc_base:
                if lolbin == "certutil.exe" and _certutil_specific_fired:
                    break
                findings.append((
                    f"Suspicious LOLBIN '{proc_base}' executed by '{user}': {cmd[:100] or 'no cmdline'}",
                    "medium",
                ))
                break

        # net/net1 commands for account/group reconnaissance
        if proc_base in ("net.exe", "net1.exe"):
            if any(x in cmd for x in ("user ", "group ", "localgroup ", "accounts")):
                findings.append((
                    f"Account/group reconnaissance via '{proc_base}': {cmd[:100]}",
                    "low",
                ))

    # Sysmon network connection by suspicious process
    if eid == "3":
        if proc_base in SUSPICIOUS_PROCESSES:
            findings.append((
                f"Outbound network connection by '{proc_base}' to {dest_ip or 'unknown'} — possible C2",
                "high",
            ))

    # Sysmon DNS query — long domain or suspicious TLD
    if eid == "22":
        domain = rec.get("dns_query", rec.get("queryname", ""))
        if len(domain) > 50:
            findings.append((
                f"Long DNS query (possible DGA/tunneling): {domain[:80]}",
                "medium",
            ))

    return findings


# ---------------------------------------------------------------------------
# Parse file bytes (JSON or CSV) and return normalised records + findings
# ---------------------------------------------------------------------------

def _load_json(content: bytes) -> List[Dict[str, Any]]:
    text = content.decode("utf-8", errors="replace").strip()
    if text.startswith("["):
        return json.loads(text)
    # Newline-delimited JSON
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _load_csv(content: bytes) -> List[Dict[str, Any]]:
    text = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def parse_windows_logs(
    content: bytes,
    filename: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse Windows/Sysmon log file content.

    Returns:
        normalised  – list of normalised event dicts
        all_findings – list of {event_id, severity, description, host, user} dicts
    """
    ext = filename.lower().rsplit(".", 1)[-1]

    if ext == "csv":
        raw_records = _load_csv(content)
    else:
        # Try JSON first, fall back to CSV
        try:
            raw_records = _load_json(content)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raw_records = _load_csv(content)

    normalised: List[Dict[str, Any]] = []
    all_findings: List[Dict[str, Any]] = []
    context: Dict[str, Any] = {}

    for raw in raw_records:
        if not isinstance(raw, dict):
            continue
        rec = normalise_record(raw)
        rec["timestamp_dt"] = _parse_timestamp(rec)
        rec["raw"] = json.dumps(raw, default=str)
        normalised.append(rec)

        hits = _detect(rec, context)
        for desc, sev in hits:
            all_findings.append({
                "event_id": rec.get("event_id", ""),
                "severity": sev,
                "description": desc,
                "host": rec.get("host"),
                "user": rec.get("user"),
            })

    return normalised, all_findings
