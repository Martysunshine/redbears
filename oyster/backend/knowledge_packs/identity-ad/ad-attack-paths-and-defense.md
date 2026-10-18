# Active Directory & Entra ID: Attack Paths and Defense

A large share of corporate red teaming is **identity work** — mapping who can reach privileged roles, not "hacking the firewall."

## Fundamentals
- **Objects**: users, groups, computers, OUs, GPOs; domains/forests joined by **trusts**.
- **Auth**: Kerberos (TGT/TGS tickets, KDC) and legacy NTLM. Service accounts run as SPNs.
- **Hybrid**: Entra ID (Azure AD) synced via Entra Connect; Conditional Access + MFA are the modern control plane.

## Common misconfig / attack-path concepts (for analysis & detection)
- **Kerberoasting** — request service tickets for SPN accounts and crack offline; weak service-account passwords are the root cause. Detect: TGS requests (Event 4769) with RC4 for many SPNs. Fix: long random gMSA passwords, AES-only.
- **AS-REP roasting** — accounts with "no pre-auth" allow offline cracking. Fix: require pre-auth.
- **Delegation abuse** — unconstrained/constrained/resource-based delegation lets a host impersonate users. Audit delegation settings.
- **ADCS (certificate services)** misconfigurations (ESC1-ESC8) can yield domain privilege. Review template enrollment permissions.
- **DCSync** — replicating directory changes to pull password hashes; restricted to accounts with replication rights. Detect: 4662 with replication GUIDs from non-DCs.
- **Privileged group sprawl / nested membership** — the real risk is *paths* to Domain Admins.

## Tooling
- **BloodHound + SharpHound** graph attack paths ("shortest path to Domain Admins"); **PingCastle** / **Purple Knight** score AD/Entra hygiene.
- **Impacket**, **NetExec (nxc)**, **Rubeus** are used in authorized testing to demonstrate/validate paths.
- Defensive: **Microsoft Defender for Identity**, native Windows/PowerShell auditing, Entra sign-in/audit logs.

## Defensive priorities
Tiered admin model, LAPS for local admin passwords, gMSA for services, Conditional Access + phishing-resistant MFA, remove delegation/legacy protocols, monitor Kerberos anomalies and privileged group changes. Describe legitimate use, prerequisites, the evidence produced, its interpretation, detection, and remediation for every technique.

## References
- MITRE ATT&CK — https://attack.mitre.org/
- BloodHound docs — https://bloodhound.readthedocs.io/
- Microsoft AD security best practices — https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory
