# Local development checkpoint (2026-10-18) — not a release

Scope: Oyster import + Huihui model option + Nemotron evidence reranking + Red Bears panel.

**Not implemented:** Tavily research · generative Nemotron orchestration · Juice Shop isolation · detection validation · sandboxed attack simulation · deployment hardening (see SECURITY.md).

## Pre-push checks run
* Remote `Martysunshine/redbears` reported `"private": false` by the GitHub API → **push blocked until made private**.
* detect-secrets over all 15,495 files proposed for commit: no live credentials found (details in the hand-off message): hits were test fixtures, AWS/Kubernetes/OWASP documentation samples (`example.com` issuers, `AKIA…EXAMPLE`), model/file checksums.
* Personal admin e-mail addresses removed from `oyster/backend/.env.example`; `.env*` ignored (only `.env.example` tracked).
* Source repo history (515 commits, excluding packs) pattern-scanned for key/token/private-key formats: matches only in files not imported here, test fixtures, a honeypot decoy `.env`, and a commented example JWT_SECRET placeholder. **Confirm with the owner that no value in those was ever real**; rotate if so.

## Third-party knowledge packs — sharing rights to confirm before going public
108 MB, ~14.8k files, 54 upstream `*-src` snapshots + 17 hand-written packs. Per-pack licence/attribution is in each `pack.json`, but **no upstream LICENSE/NOTICE texts are shipped** (only 2 packs include one). Licences present: CC-BY-SA-4.0 (14, share-alike), MIT (8), Apache-2.0 (8), GPL-3.0 (GTFOBins, LOLBAS, WADComs), GPL-2.0 (Suricata guide), DRL-1.1 (Sigma), CC-BY-4.0 (5), IETF/NIST/public-domain (9), MITRE ATT&CK Terms of Use (3 snapshots), community-spec-1.0 (2).
Unclear → needs a decision from the owners: copyleft obligations of GPL/CC-BY-SA material in a public repo; MITRE terms for redistributed snapshots; 12 small packs with **no licence field** (claimed Oyster-authored — ownership unconfirmed); `hacktricks` pack's own note says upstream licence "historically CC BY-NC" (it claims original summaries only). A `THIRD_PARTY_NOTICES` file with licence texts is still to be written.
