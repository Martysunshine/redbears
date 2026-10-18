// Blue-team Cook Book — curated, copyable reference content. Static (ships with
// the app, no backend). Everything here is defensive: detection skeletons,
// SIEM query templates, triage one-liners, ATT&CK detection ideas, and
// incident checklists. Every snippet is copy-to-clipboard in the Cook Book panel.

export interface Snippet {
  label: string;
  code: string;
  note?: string;
}
export interface ShortcutGroup {
  id: string;
  title: string;
  snippets: Snippet[];
}

export const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    id: "sigma",
    title: "Sigma detection rules",
    snippets: [
      {
        label: "Sigma rule skeleton",
        code: `title: <short descriptive title>
id: <uuid>
status: experimental
description: <what this detects and why>
references:
  - https://attack.mitre.org/techniques/Txxxx/
author: <you>
date: 2026/01/01
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - 'FromBase64String'
  condition: selection
falsepositives:
  - Legitimate admin automation
level: high
tags:
  - attack.execution
  - attack.t1059.001`,
      },
      {
        label: "Encoded PowerShell",
        code: `detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
      - 'FromBase64String'
  condition: selection`,
        note: "ATT&CK T1059.001 — needs process_creation logging (Sysmon EID 1 / Security 4688).",
      },
      {
        label: "Office spawning a shell",
        code: `detection:
  parent:
    ParentImage|endswith:
      - '\\\\winword.exe'
      - '\\\\excel.exe'
      - '\\\\powerpnt.exe'
  child:
    Image|endswith:
      - '\\\\cmd.exe'
      - '\\\\powershell.exe'
      - '\\\\wscript.exe'
  condition: parent and child`,
        note: "Classic macro-execution pattern (T1566.001 / T1204.002).",
      },
    ],
  },
  {
    id: "yara",
    title: "YARA rules",
    snippets: [
      {
        label: "YARA rule skeleton",
        code: `rule Suspicious_Sample
{
    meta:
        author = "you"
        description = "what this matches"
        reference = "https://..."
        date = "2026-01-01"
    strings:
        $s1 = "cmd.exe /c" ascii wide nocase
        $s2 = { 4D 5A }              // MZ header
        $re = /http:\\/\\/[a-z0-9.-]+\\/[a-z0-9]{8}/ nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}`,
      },
      {
        label: "Base64 PE / shellcode marker",
        code: `strings:
    $b64_mz = "TVqQAA"      // base64 of "MZ\\x90\\x00"
    $b64_pe = "This program cannot be run in DOS mode"
condition:
    any of them`,
      },
    ],
  },
  {
    id: "splunk",
    title: "Splunk SPL",
    snippets: [
      {
        label: "Failed logons by source (brute force)",
        code: `index=wineventlog EventCode=4625
| stats count by src_ip, TargetUserName
| where count > 10
| sort - count`,
      },
      {
        label: "Successful logon after failures",
        code: `index=wineventlog (EventCode=4625 OR EventCode=4624)
| transaction TargetUserName maxspan=5m
| search EventCode=4625 EventCode=4624
| table _time TargetUserName src_ip`,
      },
      {
        label: "Rare parent/child process pairs",
        code: `index=sysmon EventCode=1
| stats count by ParentImage, Image
| sort count
| head 25`,
      },
      {
        label: "Long DNS names (tunneling)",
        code: `index=dns
| eval qlen=len(query)
| where qlen > 50
| stats count by src_ip, query
| sort - qlen`,
      },
    ],
  },
  {
    id: "elastic",
    title: "Elastic KQL / ES|QL",
    snippets: [
      {
        label: "KQL — encoded PowerShell",
        code: `process.name:"powershell.exe" and process.command_line:(*-enc* or *FromBase64String*)`,
      },
      {
        label: "ES|QL — top talkers",
        code: `FROM logs-network-*
| STATS bytes = SUM(network.bytes) BY source.ip, destination.ip
| SORT bytes DESC
| LIMIT 20`,
      },
      {
        label: "KQL — new service install",
        code: `event.code:"7045" and winlog.channel:"System"`,
        note: "Windows System EID 7045 — service installation (T1543.003).",
      },
    ],
  },
  {
    id: "windows",
    title: "Windows / Sysmon triage",
    snippets: [
      {
        label: "Key Security event IDs",
        code: `4624  successful logon        4625  failed logon
4634  logoff                  4648  explicit-cred logon
4672  admin logon             4688  process creation
4720  user created            4728  added to group
7045  service installed       1102  audit log cleared`,
      },
      {
        label: "Key Sysmon event IDs",
        code: `1  process creation     3  network connection
7  image loaded         8  CreateRemoteThread
11 file created         13 registry set
22 DNS query            10 process access (LSASS)`,
      },
      {
        label: "wevtutil — export a channel",
        code: `wevtutil epl Security C:\\triage\\security.evtx
wevtutil epl Microsoft-Windows-Sysmon/Operational C:\\triage\\sysmon.evtx`,
        note: "Then upload the .evtx as evidence in SOC Copilot → Analyze.",
      },
    ],
  },
  {
    id: "hunt",
    title: "PowerShell / Linux hunting",
    snippets: [
      {
        label: "PowerShell — recent processes",
        code: `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 200 |
  Select-Object TimeCreated, @{n='NewProcess';e={$_.Properties[5].Value}},
    @{n='CommandLine';e={$_.Properties[8].Value}}`,
      },
      {
        label: "PowerShell — listening ports + owners",
        code: `Get-NetTCPConnection -State Listen |
  Select LocalAddress,LocalPort,OwningProcess,
    @{n='Proc';e={(Get-Process -Id $_.OwningProcess).Name}}`,
      },
      {
        label: "Linux — persistence quick look",
        code: `crontab -l; ls -la /etc/cron.*; systemctl list-unit-files --state=enabled
cat /etc/passwd | awk -F: '$3>=1000'; last -20`,
      },
      {
        label: "Linux — suspicious network + procs",
        code: `ss -tulpn; ps -eo pid,ppid,user,cmd --sort=start_time | tail -30`,
      },
    ],
  },
];

// ── ATT&CK quick reference ──────────────────────────────────────────────────

export interface AttackCard {
  id: string;
  name: string;
  tactic: string;
  detection: string;
  logSource: string;
}

export const ATTACK_CARDS: AttackCard[] = [
  { id: "T1059.001", name: "PowerShell", tactic: "Execution", detection: "Encoded commands, download cradles, EncodedCommand; parent is Office/wscript.", logSource: "Sysmon 1 · Security 4688 · PS ScriptBlock 4104" },
  { id: "T1003.001", name: "LSASS Memory dumping", tactic: "Credential Access", detection: "Process access to lsass.exe by non-system tools; comsvcs.dll MiniDump.", logSource: "Sysmon 10 · Security 4656/4663" },
  { id: "T1547.001", name: "Registry Run Keys", tactic: "Persistence", detection: "Writes to Run/RunOnce keys by unusual processes.", logSource: "Sysmon 13 · Security 4657" },
  { id: "T1543.003", name: "Windows Service", tactic: "Persistence", detection: "New service install, esp. with cmd/powershell ImagePath.", logSource: "System 7045 · Security 4697" },
  { id: "T1021.001", name: "RDP lateral movement", tactic: "Lateral Movement", detection: "LogonType 10 from internal hosts; unexpected source workstations.", logSource: "Security 4624 (Type 10) · TerminalServices" },
  { id: "T1071.004", name: "DNS C2 / tunneling", tactic: "Command & Control", detection: "Long/high-entropy subdomains, high query volume to one domain.", logSource: "Zeek dns.log · Sysmon 22 · DNS analytics" },
  { id: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access", detection: "Office spawning shells; child processes from mail clients.", logSource: "Sysmon 1 (parent/child) · email gateway" },
  { id: "T1048", name: "Exfil over alternative protocol", tactic: "Exfiltration", detection: "Large outbound over DNS/ICMP/uncommon ports; beacon-then-spike.", logSource: "Zeek conn.log · NetFlow · firewall" },
];

// ── Triage checklists ───────────────────────────────────────────────────────

export interface Checklist {
  id: string;
  name: string;
  when: string;
  steps: string[];
}

export const CHECKLISTS: Checklist[] = [
  {
    id: "phishing",
    name: "Phishing / suspicious email",
    when: "Reported email, malicious attachment, or credential-harvest link.",
    steps: [
      "Preserve the original email (headers + attachments) as evidence.",
      "Extract IOCs: sender, reply-to, URLs, attachment hashes.",
      "Detonate/inspect attachments in a lab — never on a prod host.",
      "Check whether any recipient clicked / entered credentials (proxy, auth logs).",
      "Search the mailflow for the same sender/subject across the org.",
      "If creds entered: force password reset + revoke sessions/tokens.",
      "Block sender domain/URLs; add IOCs to the block list.",
      "Disposition + document; escalate confirmed compromise to IR.",
    ],
  },
  {
    id: "malware",
    name: "Malware / suspicious file",
    when: "EDR/YARA hit, dropped binary, or user-reported infection.",
    steps: [
      "Isolate the host from the network (contain first).",
      "Collect the sample + hashes (MD5/SHA1/SHA256); run YARA triage.",
      "Pull process tree, autoruns, scheduled tasks, services on the host.",
      "Identify persistence and any lateral movement from this host.",
      "Extract C2 IOCs (IPs/domains/URLs) and block them.",
      "Scope: how many hosts share the same IOCs?",
      "Remediate (reimage if integrity uncertain); rotate exposed creds.",
      "Disposition + write the incident report.",
    ],
  },
  {
    id: "bruteforce",
    name: "Brute force / account compromise",
    when: "Spike in failed logons, or a success following many failures.",
    steps: [
      "Quantify failed logons (4625) by source IP and target account.",
      "Confirm any successful logon (4624) from the same source/account.",
      "Classify the source IP: internal, VPN, or unexpected external.",
      "Review post-auth activity on the host (process creation, network).",
      "Check for lateral movement (Type 3/10 logons onward).",
      "Assess the account's privilege and data access.",
      "Contain: disable/reset the account, revoke sessions.",
      "Disposition; escalate confirmed compromise.",
    ],
  },
  {
    id: "c2",
    name: "Command-and-control traffic",
    when: "Beaconing, suspicious DNS, or IDS C2 alert.",
    steps: [
      "Identify the internal host and the external destination(s).",
      "Characterize the pattern: interval/jitter, bytes, protocol.",
      "Correlate with process on the host (which binary opened the socket).",
      "Extract and enrich the C2 IOCs; check threat intel.",
      "Contain the host; block the destination at the firewall/proxy.",
      "Hunt the same IOCs across the fleet.",
      "Remediate the initial access + persistence.",
      "Disposition + report.",
    ],
  },
  {
    id: "exfil",
    name: "Data exfiltration",
    when: "Large/anomalous outbound transfer or DLP alert.",
    steps: [
      "Identify source host/user, destination, volume, and channel.",
      "Determine what data classification was involved.",
      "Check for staging (archives, unusual temp files) on the host.",
      "Review auth + access logs for how the data was reached.",
      "Contain: block the channel, isolate the host if active.",
      "Notify data-owner / legal per policy if sensitive data left.",
      "Scope other hosts/accounts touching the same data.",
      "Disposition + report with the impact assessment.",
    ],
  },
];
