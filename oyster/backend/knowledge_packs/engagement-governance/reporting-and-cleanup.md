# Evidence, Reporting, Cleanup & Retesting

Weak reporting can make excellent technical work nearly worthless. The client needs two outputs: an **executive report** (business exposure, risk narrative) and a **technical report** (developers/defenders can act on it).

## Evidence per finding
Every material finding should record:
- Affected asset + time discovered + testing account/source system.
- Exact observation, **reproduction steps**, and request/response or screenshot evidence.
- **Business impact**, severity, and confidence.
- CVE / CWE / CVSS (and EPSS / CISA KEV where relevant).
- MITRE ATT&CK technique mapping when appropriate.
- Remediation + a **safe validation/retest procedure**.
- Cleanup status and retest outcome.

## Severity is not just CVSS
Combine technical severity, exploitability (EPSS), exposure, asset importance, existing controls, available attack path, data sensitivity, regulatory impact, and business consequence. A *medium* on a critical identity system can outrank a *critical* on an isolated test box.

## Attack-path narrative (red team)
A pentest says "these 14 vulns exist." A red-team engagement tells a story: how an attacker moves from initial access to a critical business system, and what the defenders did or did not detect. Structure with MITRE ATT&CK tactics/techniques.

## Cleanup obligations
Remove test accounts, payloads, uploaded web shells, scheduled tasks, C2 infrastructure, and any config changes. Keep an engagement activity log so cleanup can be verified item-by-item. Record evidence-retention and deletion dates.

## Retesting
Fixes must be validated. Track: finding → remediation deadline (SLA) → ticket → fix → retest result → recurrence detection. A finding that reopens after remediation is a signal about process, not just a bug.

## Report tooling
PlexTrac, Dradis, Faraday, Ghostwriter, or structured Markdown. Executive summary first; technical detail and evidence appendix after.

## References
- PTES Reporting — http://www.pentest-standard.org/index.php/Reporting
- FIRST CVSS — https://www.first.org/cvss/
- CISA Known Exploited Vulnerabilities (KEV) — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
