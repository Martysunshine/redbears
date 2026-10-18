# Threat Intelligence → Detection

Good intel is not "here are 5,000 malicious IPs." It is "this actor is relevant to us, uses these behaviors, targets these assets, and is detectable through these telemetry sources."

## Layers
- **Indicators (IOCs)**: hashes, IPs, domains, URLs — cheap for attackers to change.
- **TTPs (tactics, techniques, procedures)**: behavior — expensive to change, the durable detection target.
- **Actors / campaigns / malware families** and their **infrastructure relationships**.

## Pyramid of Pain
From easiest→hardest for the attacker to change: hash values → IP addresses → domain names → network/host artifacts → tools → **TTPs**. Detections built on TTPs cause the most "pain" and age best. Map behavior to **MITRE ATT&CK** and translate into detection logic (Sigma/KQL/SPL).

## Confidence & relevance
Assign confidence to each piece of intel; decide sector/asset relevance before acting. Analytic tradecraft: analyze malware/infrastructure, build indicator relationships, and feed detection engineering + threat-informed red-team scenarios.

## Sharing standards & platforms
- **STIX** (structured representation) + **TAXII** (transport) for machine-readable sharing.
- Platforms: **MISP**, **OpenCTI**, VirusTotal, Mandiant/Recorded Future/CrowdStrike Intelligence, AlienVault OTX; authoritative CERT/government advisories (CISA, national CERTs).

## Output that matters
Threat-informed testing: pick actors relevant to the org, emulate their ATT&CK techniques (MITRE adversary-emulation plans), and verify detection coverage.

## References
- MITRE ATT&CK — https://attack.mitre.org/
- MITRE adversary-emulation plans — https://attack.mitre.org/resources/adversary-emulation-plans/
- OASIS STIX/TAXII — https://oasis-open.github.io/cti-documentation/
