# MITRE ATT&CK — Technique to Detection to Mitigation

*Original condensed summaries. Source: MITRE ATT&CK® — https://attack.mitre.org/ © The MITRE Corporation (used per the ATT&CK Terms of Use). STIX 2.1: https://github.com/mitre-attack/attack-stix-data. Confirm current technique details and sub-techniques at the source.*

ATT&CK models adversary behavior as **tactics** (the why) and **techniques** (the how), each with an ID (e.g. T1059). The value for an operator is the chain: a technique has **prerequisites**, generates **telemetry**, is caught by specific **detections**, and is reduced by named **mitigations**. Use this to turn every offensive step into defensive coverage (purple teaming).

The ATT&CK STIX 2.1 dataset expresses these as objects and **relationships** — `attack-pattern` (technique) linked by `mitigates` (course-of-action → technique) and `detects` (data-component → technique). Oyster can walk those relationships: Technique → Mitigations, Technique → Data sources/Detections.

---

## T1059 — Command and Scripting Interpreter (Execution)

- **Prerequisites**: Code execution on a host; an available interpreter (PowerShell, bash, cmd, Python, JScript).
- **Telemetry**: Process creation with command-line arguments (Windows 4688 / Sysmon 1), PowerShell script-block logging (4104), parent-child lineage (e.g. `winword.exe → powershell.exe`).
- **Detection**: Encoded/obfuscated command lines, interpreters spawned by Office/browser processes, `-enc`/`-nop`/`IEX` patterns, unusual parent processes.
- **Mitigation**: M1042 disable/remove unneeded interpreters; M1038 execution prevention (AppLocker/WDAC); constrained language mode; M1026 privileged account management.
- **Source**: https://attack.mitre.org/techniques/T1059/

## T1558.003 — Kerberoasting (Credential Access)

- **Prerequisites**: Any authenticated domain account; service accounts with SPNs and weak passwords.
- **Telemetry**: Kerberos service-ticket requests (Windows 4769) with RC4 encryption type and abnormal volume from one principal.
- **Detection**: Spikes of 4769 for many SPNs from a single account; RC4 (0x17) ticket requests where AES is expected; honeypot SPN accounts.
- **Mitigation**: M1027 strong (25+ char) managed service-account passwords / gMSA; enforce AES; least-privilege SPNs.
- **Source**: https://attack.mitre.org/techniques/T1558/003/

## T1003 — OS Credential Dumping (Credential Access)

- **Prerequisites**: Local admin/SYSTEM (LSASS) or Domain Controller replication rights (DCSync).
- **Telemetry**: Handle opens to `lsass.exe`, Sysmon 10; directory-replication requests (4662 with the DS-Replication-Get-Changes GUID) from non-DC hosts.
- **Detection**: Non-DC hosts performing replication (DCSync); LSASS access by non-system tools; credential-tool signatures.
- **Mitigation**: M1043 Credential Guard / LSASS PPL; M1026 tiered admin; restrict replication rights to DCs.
- **Source**: https://attack.mitre.org/techniques/T1003/

## T1071 — Application Layer Protocol / C2 (Command and Control)

- **Prerequisites**: An implant with outbound network access.
- **Telemetry**: Proxy/DNS/Netflow logs; TLS JA3 fingerprints; beacon periodicity and jitter.
- **Detection**: Regular-interval beacons, rare destinations, long-lived low-volume connections, DNS with high entropy or excessive TXT queries.
- **Mitigation**: M1031 network intrusion prevention; egress filtering and DNS inspection; block known-bad infrastructure.
- **Source**: https://attack.mitre.org/techniques/T1071/

## T1547 — Boot or Logon Autostart Execution (Persistence)

- **Prerequisites**: Write access to an autostart location (Run keys, services, scheduled tasks, startup folder).
- **Telemetry**: Registry-modification events (Sysmon 13), new service installs (7045), scheduled-task creation (4698).
- **Detection**: New/modified autostart entries pointing at user-writable or unusual paths; unsigned binaries in autostart.
- **Mitigation**: M1028 harden config; M1024 restrict registry permissions; application control.
- **Source**: https://attack.mitre.org/techniques/T1547/

## Using ATT&CK in an engagement

When you execute or find a technique, record its ATT&CK ID. That single ID lets the report state (a) what the adversary behavior was, (b) which telemetry should have caught it, (c) a concrete detection to add, and (d) the mitigation to recommend. This is what makes a finding *defensible* rather than just an exploit — and it drives Sigma/KQL detection generation.
