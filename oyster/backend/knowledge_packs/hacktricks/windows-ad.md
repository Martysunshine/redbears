# Windows & Active Directory — Methodology Summary

*Original condensed methodology. Techniques popularized by HackTricks — https://book.hacktricks.wiki/ (verify against source). Read-only knowledge: active use requires an authorized, in-scope target and approval.*

## Windows local privilege escalation

Enumerate first (WinPEAS, `whoami /priv`, `systeminfo`):

- **Token privileges** — `SeImpersonatePrivilege` / `SeAssignPrimaryToken` enable "potato"-style local escalation on service accounts.
- **Unquoted service paths** and **weak service permissions** — a service you can reconfigure or whose binary path you can hijack.
- **AlwaysInstallElevated** — MSI packages install as SYSTEM if both registry keys are set.
- **Writable autoruns / scheduled tasks** run by a higher-privilege account.
- **Credentials** — in the registry, `cmdkey`, DPAPI blobs, unattended install files, and the SAM/LSASS in memory.

## Active Directory attack path

AD compromise is about chaining small misconfigurations into a path to Domain Admin. Standard flow:

1. **Recon (no creds)** — identify the domain, DCs, and users; look for anonymous LDAP/SMB and legacy protocols.
2. **Initial creds** — password spraying (respect lockout), LLMNR/NBT-NS poisoning to capture NetNTLM hashes, or a foothold host.
3. **Enumerate with BloodHound** — collect and analyze the graph to find the shortest path from your principal to high-value targets. This is the single most useful AD step.
4. **Credential access**:
   - **Kerberoasting** — request service tickets for accounts with SPNs and crack offline (weak service-account passwords).
   - **AS-REP roasting** — accounts with pre-auth disabled yield crackable material.
   - **LSASS / DCSync** — dump secrets from memory or replicate them with sufficient rights.
5. **Lateral movement** — pass-the-hash / pass-the-ticket, WMI/WinRM/PsExec-style execution.
6. **Privilege escalation via ACLs / delegation** — abusable object ACLs, unconstrained/constrained/resource-based delegation, GPO edit rights, ADCS misconfigurations (ESC1-ESC8).
7. **Domain dominance** — golden/silver tickets, DCSync — post-DA persistence (only if explicitly authorized).

## Discipline & detection

Each of these steps is noisy in a specific way — Kerberoasting shows up as anomalous TGS requests, DCSync as replication from a non-DC, LLMNR poisoning on the wire. Record the **telemetry each technique generates** so the engagement produces detections (Sigma/KQL) and remediation, not just a path to DA. Never operate outside the written scope; a trust relationship discovered in AD is not authorization to pivot into another domain.
