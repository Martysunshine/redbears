# Detection Engineering & Purple Teaming

Purple teaming connects offense and defense. For each approved technique: define the behavior → execute in a controlled environment → check endpoint/network telemetry → confirm whether an alert fired → improve the detection → repeat → record coverage.

## Detection formats
- **Sigma** — portable, YAML detection logic that compiles to many SIEM backends (KQL, SPL, Elastic). Good for sharing detections across tools.
- **YARA** — pattern matching for files and memory (malware families, artifacts).
- **KQL** — Microsoft Sentinel / Defender XDR query language.
- **SPL** — Splunk Search Processing Language.
- **Suricata/Snort** rules — network IDS signatures.

A generated rule must ship with its **assumptions, required data sources, false-positive considerations, and test status** — a detection you haven't tested against real telemetry is a hypothesis.

## Example Sigma skeleton
```yaml
title: Suspicious PowerShell Encoded Command
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: medium
falsepositives: [Legitimate admin automation]
```

## ATT&CK-driven coverage
Map detections to **MITRE ATT&CK** tactics/techniques to measure coverage and find blind spots. Drive tests with **Atomic Red Team** (small, ATT&CK-mapped tests) and **MITRE Caldera** (automated adversary emulation). Track results over time (e.g., Vectr).

## The engineering behind defense
Mature blue teams design log pipelines, decide required telemetry, normalize events, build+tune detections, maintain allowlists, simulate attacks against new rules, and measure detection/response time. Languages: KQL, SPL, EQL/Lucene, Sigma, YARA, plus SQL/Python for analysis.

## References
- SigmaHQ — https://github.com/SigmaHQ/sigma
- MITRE ATT&CK — https://attack.mitre.org/
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- MITRE Caldera — https://caldera.mitre.org/
