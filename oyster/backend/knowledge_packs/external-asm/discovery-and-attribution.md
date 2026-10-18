# External Attack Surface: Discovery & Attribution

Goal: enumerate everything the organization exposes to the internet, then **prove ownership** before testing.

## What to discover
Domains & subdomains, DNS records, public IP ranges & ASNs, TLS certificates (SANs), internet-facing apps and APIs, VPN/remote-access portals, cloud assets, exposed storage (S3/Blob/GCS), forgotten dev/staging environments, shadow IT, acquired-company infrastructure, and leaked credentials/secrets.

## Passive first (low-risk, no packets to target)
- **Certificate transparency** (crt.sh), **DNS history** (SecurityTrails, DNSDumpster), search engines, GitHub code/secret search, Wayback/`gau` for historical URLs.
- Subdomain enumeration: **Subfinder**, **Amass** (passive mode), Assetfinder, theHarvester; org/infrastructure graphing with SpiderFoot / Maltego; internet scan data via **Shodan** / **Censys**.

## Active resolution & probing
- Resolve candidates, then probe liveness with **httpx** (status, title, tech), crawl with **Katana**, port-scan discovered hosts with **Naabu**/Nmap, and run **Nuclei** for known exposures.
- Secret scanning of exposed repos/artifacts with **TruffleHog** / **Gitleaks** (treat hits as *indicators*, verify, and redact values).

## Attribution (the hard part)
An exposed server is easy to find; proving it belongs to the client is harder. Cross-check WHOIS/registrant, ASN ownership, certificate SAN patterns, DNS delegation, cloud account IDs, and the authorized scope list. **Do not test an asset you cannot attribute to the authorized owner** — attribution errors mean testing someone else's systems.

## Deduplication & monitoring
The same host appears via many names/IPs. Deduplicate by canonical host + IP + service fingerprint. ASM is continuous: new subdomains and cloud assets appear constantly, so re-run discovery on a schedule and diff.

## References
- OWASP Amass — https://github.com/owasp-amass/amass
- ProjectDiscovery (subfinder, httpx, naabu, katana, nuclei) — https://projectdiscovery.io/
- crt.sh certificate transparency — https://crt.sh/
