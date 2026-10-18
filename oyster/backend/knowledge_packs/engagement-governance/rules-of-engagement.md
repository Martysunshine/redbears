# Authorization & Rules of Engagement (RoE)

Authorized security testing is gated by paperwork before any packet is sent. NIST SP 800-115 treats **planning, execution, and post-execution (analysis + mitigation)** as equal parts of security testing — exploitation is a small slice.

## Required before testing
- **Signed Statement of Work (SOW)** and a **written authorization ("get-out-of-jail" letter)** naming the authorizing party who owns the assets.
- **Exact scope**: in-scope IPs, CIDR ranges, domains/subdomains, applications, cloud accounts, and named subsidiaries. Everything else is out of scope by default.
- **Testing windows** (allowed hours/days) and **change-freeze** blackout periods.
- **Prohibited techniques** (e.g., DoS/stress, destructive exploits, social engineering, physical) unless explicitly authorized in writing.
- **Emergency contacts** and a **stop-testing procedure** reachable 24/7.
- **Third-party restrictions**: cloud providers (AWS/Azure/GCP) and SaaS often require their own authorization or have testing policies; shared hosting may host other tenants.
- **Data-handling rules**: what may be accessed, how PII/PHI is treated, encryption at rest/in transit, and **evidence retention + deletion dates**.

## Scope enforcement principles
- Scope is a **hard gate enforced in code**, not a suggestion in a prompt. Normalize domains, URLs, IPs, CIDRs, and ports before comparison.
- **Attribution matters**: finding an exposed host is easy; proving it belongs to the client (WHOIS, ASN, certificate SANs, DNS ownership, cloud account IDs) is the hard part. Never test an asset you cannot attribute to the authorized owner.
- Follow redirects **only if the destination stays in scope**. Defend against DNS rebinding and alternate IP encodings (decimal/octal/IPv6-mapped) used to bypass allowlists.
- Never expand scope because an uploaded file, webpage, or tool output *mentions* another system. Mentions are not authorization.

## Engagement lifecycle (professional)
Authorization → scope/asset definition → RoE → threat intel & scenario design → recon → attack-surface mapping → vuln discovery → manual validation → controlled exploitation → privilege/access-path analysis → detection testing → business-impact validation → cleanup → technical + executive reporting → remediation → **retesting** → detection-coverage improvement.

## Read-only vs active
Separate **passive research** (OSINT, cert transparency, public DNS) from **active testing** (scanning, exploitation). Passive is generally low-risk; active requires scope + approval. Provide a **dry-run** mode wherever meaningful.

## References
- NIST SP 800-115 — https://csrc.nist.gov/pubs/sp/800/115/final
- PTES (Pre-engagement Interactions) — http://www.pentest-standard.org/
- CISA Red Team Assessments evaluate people + process + technology — https://www.cisa.gov/
