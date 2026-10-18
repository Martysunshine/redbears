# Vulnerability Management & Prioritization

Finding vulnerabilities is the beginning. The operation is turning thousands of findings into the few that matter.

## The pipeline
Ingest scanner output → **normalize** (common schema) → **deduplicate** (same asset+vuln from multiple scanners) → suppress **false positives** → assign **asset ownership** → correlate findings into **attack paths** → prioritize → open tickets with **remediation SLAs** → accept/transfer risk with tracked exceptions → **verify fixes (retest)** → detect recurrence → report aging + SLA violations.

## Prioritization signals (don't use CVSS alone)
- **CVSS** — technical severity (base/temporal/environmental). A starting point, not a verdict.
- **EPSS** — probability the CVE will be exploited in the wild (next 30 days). Great for ranking.
- **CISA KEV** — vulnerabilities *known to be actively exploited*; treat as top priority.
- **Business context** — asset importance, exposure (internet-facing?), data sensitivity, existing controls, available attack path, regulatory impact.

A *medium* on a critical, internet-facing identity system can outrank a *critical* on an isolated lab box. Correlate: two mediums that chain into domain compromise are a single high-impact path.

## Platforms
Tenable, Qualys, Rapid7 InsightVM, Wiz, DefectDojo (open source aggregation/dedup), ServiceNow Vulnerability Response, Jira for tickets.

## Metrics leaders care about
Critical attack paths eliminated, % of important assets covered, mean time to detect/contain, vulnerability age, findings reopened after remediation, retest success rate, orphaned-asset count. "12,483 vulnerabilities found" is less useful than "these three attack paths reach production customer data."

## References
- FIRST EPSS — https://www.first.org/epss/
- FIRST CVSS — https://www.first.org/cvss/
- CISA KEV catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
