# Incident Response Lifecycle & Digital Forensics

## NIST SP 800-61 lifecycle
1. **Preparation** — tooling, logging, playbooks, forensic readiness.
2. **Detection & Analysis** — validate the alert, scope it, build an initial timeline.
3. **Containment, Eradication & Recovery** — isolate, remove attacker footholds, restore.
4. **Post-Incident Activity** — lessons learned, control improvements, reporting.

Repeated tasks: preserve evidence, establish the initial point of compromise, determine affected accounts/systems, identify persistence and lateral movement, contain, recover, produce a complete timeline, and recommend controls that prevent recurrence.

## Evidence handling
- **Never modify original evidence.** Work from forensic copies; hash (SHA-256) before/after to prove integrity.
- **Chain of custody**: who collected what, when, from where, and every transfer.
- **Order of volatility** (collect most-volatile first): CPU/registers/cache → RAM → network state/connections → running processes → disk → logs/archives → physical media.

## Toolkit
- Acquisition: **FTK Imager**, **Magnet Acquire**, `dd` (disk); memory capture tools.
- Memory analysis: **Volatility** (processes, injected code, network artifacts).
- Endpoint collection/hunting: **Velociraptor**, **KAPE**, **osquery**.
- Disk/artifact analysis: **Autopsy**, Magnet AXIOM, EnCase, X-Ways.
- Timeline: **Plaso/log2timeline** → **Timesketch**.
- Network: **Wireshark**, **Zeek**, **NetworkMiner**.
- Indicators: **YARA**, **Sigma**, VirusTotal.
- Case management: TheHive, ServiceNow, Jira.

## SOC/triage reality
Analysts spend most time on triage, enrichment, scoping, documentation, and handovers — not dramatic exploitation. Distinguish forensic *guidance* from direct execution; in this tool, IR content is advisory.

## References
- NIST SP 800-61r2 — https://csrc.nist.gov/pubs/sp/800/61/r2/final
- Volatility Foundation — https://www.volatilityfoundation.org/
- Velociraptor — https://docs.velociraptor.app/
