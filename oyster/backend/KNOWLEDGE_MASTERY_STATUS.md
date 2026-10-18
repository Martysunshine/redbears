# Cybersecurity Knowledge Mastery — Implementation Status

Persistent, honest checklist. A row is **DONE** only if real retrievable content
and/or tests support it. Last updated: 2026-08-18 (Phase 13: graph-integrity
hardening, Microsoft Entra + Red Hat CSAF + Debian/Alpine/OSS-Fuzz OSV + 6 AWS
sources, deterministic version-check and patch-prioritization answers,
persistent-data-directory fix, restoration of 41 previously-unloaded packs).

Legend: ✅ done+verified · 🟡 partial · ⚙️ implemented but env-limited ·
⛔ blocked by licence · ⬜ not started

## Phase status

| Phase | Scope | Status | Evidence |
|-------|-------|--------|----------|
| 1 | Reusable **connector framework**: provenance, licensing gate, atomic install, injection defense, update history/rollback | ✅ | `services/knowledge/connectors/*`; 24 tests in `tests/test_knowledge_connectors.py` |
| 2 | **OWASP WSTG** real ingestion + verified retrieval | ✅ | Live import: 175 docs / **1974 chunks**, commit `c11a9509`; hybrid retrieval + citations + offline lexical + update-check demonstrated |
| 3 | **MITRE ATT&CK** structured (STIX) ingestion + technique/mitigation/detection relations | ✅ | `StixConnector` (json_stix) live-imported **all three ATT&CK domains**: Enterprise **697 techniques / 3547 chunks**, Mobile **124 / 356**, ICS **97 / 461** @ `a6c36643`; each doc carries tactics + platforms + mitigations (Mxxxx) + detection data-components + group/software use; citations → attack.mitre.org; 5 offline STIX tests |
| 4 | Kali docs, HackTricks, GTFOBins, PayloadsAllTheThings | ✅ / ⛔ | **GTFOBins live-imported: 482 binaries / 625 chunks** @ `acd52462` (GPL-3.0). HackTricks ⛔ (CC-BY-NC-4.0 → manual_confirm); Kali ⛔ (licence unclear); PayloadsAllTheThings ⛔ (high-risk/unclear) — all three still blocked before any fetch. |
| 5 | OWASP API / ASVS / MASVS-MASTG + cloud/container/mobile | ✅ | **All three live-imported**: API Security 200 docs/1039 chunks @ `e85ddfa5`; ASVS 200/2518 @ `fe049861`; MASTG **1069 docs/5811 chunks** @ `0e88142b` (cap raised to 2000 — full corpus now indexed). |
| 6 | LOLBAS, WADComs, Sigma, YARA, Atomic Red Team, detection maps | ✅ | **All live-imported**: LOLBAS 267/857 @ `a2784c79`; **Sigma 4241 rules/11884 chunks** @ `5e969bc5` (DRL 1.1); **YARA (ReversingLabs) 310/5041** @ `e0a0be54` (MIT); **Atomic Red Team 363/6001** @ `1ba1dd8d` (MIT); **WADComs 106/210** @ `31283f15` (GPL-3.0) |
| 7 | Malware/RE, DFIR, TI, OT/ICS, IoT, AI/LLM security packs | 🟡 | Covered by hand-curated packs (incident-response-dfir, threat-intel, ai-llm-security); no dedicated connectors yet |
| 8 | Dataset governance + eval harness | ✅ | `datasets.json` v2.0 governance + **evaluation harness** (`services/evaluation/`): local retrieval-grounding suite, deterministic scoring (pack-hit/source-hit/MRR/citation), SQLite run history, dataset-governance gate (**training always forbidden in code**, registry datasets eval-gated + never stored). Live: 10/10 cases, MRR 0.845, citation-rate 1.0. 8 tests |
| 9 | Cross-source knowledge graph, advanced rerank, contradiction handling | ✅ | `services/knowledge/graph/` joins ATT&CK ⟷ Atomic ⟷ Sigma on technique id → **918 techniques, 2197 edges, 5 packs**; purple-team coverage (275 detection+emulation) + inconsistencies (dangling refs, detection-without-emulation gaps). Deterministic, no LLM. 5 tests |

## Connector library (declared source allow-list)

| Connector | Licence | Disposition | Live-imported |
|-----------|---------|-------------|---------------|
| owasp-wstg-src | CC-BY-SA-4.0 | store_local ✅ | ✅ 140 docs / 1831 chunks @ c11a9509 |
| owasp-api-security-src | CC-BY-SA-4.0 | store_local ✅ | ✅ 46 docs / 251 chunks @ e85ddfa5 (EN only) |
| owasp-asvs-src | CC-BY-SA-4.0 | store_local ✅ | ✅ 49 docs / 671 chunks @ fe049861 (EN only) |
| owasp-mastg-src | CC-BY-SA-4.0 | store_local ✅ | ✅ 852 docs / 4881 chunks @ 0e88142b (globs widened to real content dirs) |
| gtfobins-src | GPL-3.0 | store_local ✅ | ✅ 478 binaries / 610 chunks @ acd52462 |
| lolbas-src | GPL-3.0 | store_local ✅ | ✅ 242 LOLBins / 813 chunks @ a2784c79 |
| mitre-attack-src | mitre-attack-terms | store_local ✅ | ✅ 697 techniques / 3547 chunks (Enterprise) @ a6c36643 |
| mitre-attack-mobile-src | mitre-attack-terms | store_local ✅ | ✅ 124 techniques / 356 chunks (Mobile) @ a6c36643 |
| mitre-attack-ics-src | mitre-attack-terms | store_local ✅ | ✅ 97 techniques / 461 chunks (ICS) @ a6c36643 |
| sigma-src | DRL-1.1 | store_local ✅ | ✅ 3752 rules / 10785 chunks @ 4faa9d9d (rules dirs only) |
| yara-reversinglabs-src | MIT | store_local ✅ | ✅ 310 rule files / 5041 chunks @ e0a0be54 |
| atomic-red-team-src | MIT | store_local ✅ | ✅ 356 technique tests / 5981 chunks @ 1ba1dd8d |
| wadcoms-src | GPL-3.0 | store_local ✅ | ✅ 100 commands / 192 chunks @ 31283f15 |
| hacktricks-src | CC-BY-NC-4.0 | manual_confirm ⛔ | blocked (NonCommercial) |
| kali-docs-src | unclear | manual_confirm ⛔ | blocked (licence unclear) |
| payloadsallthethings-src | unclear/high-risk | manual_confirm ⛔ | blocked |

**13 connectors live-imported → 35,420 knowledge chunks total** (WSTG, API,
ASVS, MASTG, GTFOBins, LOLBAS, Sigma, YARA, Atomic Red Team, WADComs via git;
ATT&CK Enterprise/Mobile/ICS via STIX). Counts are **post-cleanup**: a matcher
bug let a generic `file_type` (`.yml`/`.md`) bypass declared `include_globs` via
an `endswith()` fallback, pulling non-content files (Sigma `regression_data/`,
`.github/` workflows; OWASP non-English translations) into packs. Fixed so
declared globs are the authoritative allow-list (fallback only when a profile
declares *no* globs); every git pack re-imported → all packs now match their
globs exactly (verified `outside_globs=0`). The 3 blocked connectors are never
fetched — the licence gate is enforced before acquisition.

## Domain coverage matrix (30 domains)

Backed = curated pack and/or live-imported connector content exists.

| # | Domain | Backing | Note |
|---|--------|---------|------|
| 1 | Network recon/enumeration | 🟡 pack (network-pentest) | |
| 2 | Web application security | ✅ WSTG live + web-appsec pack | strongest |
| 3 | API security | ✅ OWASP API Security live + pack | |
| 4 | AuthN/session | ✅ WSTG live | |
| 5 | AuthZ/access control | ✅ WSTG live | |
| 6 | Active Directory/Windows | 🟡 pack (identity-ad) | |
| 7 | Linux privesc | ✅ GTFOBins live (482 binaries) + pack | |
| 8 | Windows privesc | ✅ LOLBAS live (267 LOLBins) | |
| 9 | Cloud (AWS/Azure/GCP) | 🟡 pack (cloud-security) | |
| 10 | Containers/K8s | ⬜ | not yet |
| 11 | Mobile Android/iOS | ✅ OWASP MASTG live (1069 docs) + Mobile ATT&CK (124 techniques) | |
| 12 | Wireless | ⬜ | not yet |
| 13 | Identity/OAuth/OIDC/SAML | 🟡 pack (identity-ad) | |
| 14 | DevSecOps/supply-chain | 🟡 pack (vuln-management) | |
| 15 | SAST/dependency analysis | 🟡 pack | |
| 16 | Malware triage/RE | ✅ YARA (ReversingLabs 310 rule files) + registry/classifier | |
| 17 | DFIR | ✅ Sigma rules-dfir + incident-response-dfir pack | |
| 18 | Threat hunting | ✅ Sigma rules-threat-hunting live + pack | |
| 19 | Detection engineering | ✅ Sigma 3752 rules + YARA 310 live + pack + KG coverage gaps | |
| 20 | Threat intel/IOC | 🟡 pack (threat-intel) | |
| 21 | ATT&CK mapping | ✅ STIX live — Enterprise 697 + Mobile 124 + ICS 97 techniques + relations | |
| 22 | Vuln research/exploit valid. | 🟡 pack (vuln-management) | |
| 23 | Crypto weaknesses | ⬜ | not yet |
| 24 | Social-engineering (authorized) | ⬜ | not yet |
| 25 | OT/ICS | ✅ ICS ATT&CK live (97 techniques + relations) | technique KB; no ICS-specific pack yet |
| 26 | IoT/embedded | ⬜ | not yet |
| 27 | AI/LLM/agent/RAG security | 🟡 pack (ai-llm-security) | |
| 28 | Prompt-injection/tool-abuse defense | ✅ connector injection scanner + classifier | |
| 29 | Security architecture/threat modelling | 🟡 pack (engagement-governance) + ASVS connector | |
| 30 | Remediation/retest/reporting | 🟡 WSTG reporting + packs | |

## Weak / incomplete (honest)

- Containers/K8s, wireless, crypto, IoT, social-eng have no dedicated backing
  beyond general packs. OT/ICS now has ICS ATT&CK technique coverage but no
  ICS-specific defensive/methodology pack.
- ATT&CK STIX: **all three domains live** (Enterprise + Mobile + ICS). Only the
  current version of each bundle is imported (update-check compares upstream
  commit for refresh).
- Eval harness suites are locally-authored retrieval-grounding cases (10). No
  external eval dataset is downloaded/ingested (governance keeps them eval-only,
  gated, un-provisioned). Broader suites can be added as JSON under
  `services/evaluation/suites/`.
- Knowledge graph joins only ATT&CK-bearing sources (ATT&CK/Atomic/Sigma) on
  technique id; YARA and the OWASP prose packs are not yet node-linked (no shared
  technique id in their chunks).

## Phase 10 — new official sources + relationship graph + deterministic routing

| Scope | Status | Evidence |
|-------|--------|----------|
| 5 new connectors: MITRE D3FEND (official CSV mapping export, new API-type connector), OWASP Top 10, OWASP Cheat Sheet Series, Kubernetes security docs, Docker security docs | ✅ | Live-imported: D3FEND 156/808, OWASP Top10 18/211 (English-only, `2021/docs/en/**`), CheatSheets 120/3586, K8s 38/984, Docker 19/247. **+5836 chunks.** |
| Graph extended beyond ATT&CK-id joins: ATT&CK↔D3FEND (`countered_by`), CVE↔CWE (`classified_as`), CWE↔CAPEC (`exploits`), CVE↔KEV (`listed_in`), platform↔pack (`has_guidance`) | ✅ | `services/knowledge/graph/builder.py` `_vuln_relationships()` / `_platform_relationships()`; sourced from real `vulnerability_cwe_links`/`capec_cwe_links` tables (populated by KEV/CWE/CAPEC/EPSS sync, not fabricated). Live: 156 countermeasure nodes, 969 CWE, 615 CAPEC, 1665 CVE, 19 platform nodes, 11,062 edges total. |
| Deterministic pre-LLM router (`services/knowledge/security_router.py`) + grounded 7-part answer formatter (`security_answer.py`) | ✅ | Exact CVE/CWE/CAPEC/ATT&CK/D3FEND id → real DB lookup, never semantic search; topic keywords → scoped retrieval (detection/mitigation/incident_response/cloud/vulnerability_filter); `POST /knowledge/intelligence/ask`, `GET /knowledge/intelligence/classify`. |
| New eval suite `security-intelligence-v1` (137 cases; identifier samples drawn live from the installed DB, not hand-typed) | ✅ | `POST /evaluation/security/run`. Live: **137/137 pass** — route_accuracy 1.0, exact_lookup_accuracy 1.0, non_fabrication_rate 1.0 (fake CVE/CWE/CAPEC/ATT&CK/D3FEND ids), citation_resolution_rate 1.0, injection_safety_rate 1.0, latency p95 structured 30ms (<500ms gate), p95 general ~350ms. |

## Continuation checkpoint

**Phases 6, 8, 9, 10 complete.** 18 connectors live-imported (13 prior + 5 new
this session), all under authoritative globs. Vulnerability sync pipeline
hydrated for real: KEV 1665, CWE 969 (exact baseline match), CAPEC 615 (exact
baseline match), EPSS-derived vulnerability_records 360,399 (baseline 360,426 —
normal daily drift, not a discrepancy). **41,418 total knowledge chunks**
(35,582 pre-existing + 5,836 new). Cross-source knowledge graph extended with
CVE/CWE/CAPEC/D3FEND/platform relationships (11,062 edges, up from 2,197).
Deterministic security-question router + grounded answer format built and
API-exposed. New eval suite passing 137/137 with all required non-fabrication/
citation/injection-safety gates at 100%. 322 backend tests pass (up from 128 +
Phase-10 additions).

**Deliberately not attempted this pass** (documented, not silently skipped):
CISA Cybersecurity Advisories (no clear rights/licence statement found on the
RSS feed, `cisagov/CSAF` repo, or cisa.gov site notices — `cisagov/CSAF` also
republishes third-party vendor CSAFs, making a blanket public-domain assumption
unsafe); CISA Secure by Design (no structured feed, mostly narrative/PDF); NIST
CSF 2.0 (no official structured JSON/CSV export located; no dedicated
`usnistgov` GitHub repo); NIST SP 800-61/800-207/800-218 (NIST SP 800-53 *is*
available as a real, CC0-licensed, structured OSCAL catalog at
`usnistgov/oscal-content` — verified but not ingested this pass, would need a
dedicated OSCAL JSON-catalog parser rather than the markdown-chunk connector
pattern); AWS/Azure/GCP official guidance (Azure docs repo confirmed CC-BY-4.0
but is a huge general monorepo needing careful glob scoping; AWS/GCP official
docs repos not confidently identified); Red Hat/Ubuntu/Debian security
advisories (confirmed live JSON APIs, licensing not verified, and CVE-shaped
data doesn't fit the markdown-chunk connector model — closer to the
vulnerabilities-subsystem pattern); ENISA threat-landscape (JS-rendered site,
no structured download found). Full CVE corpus (NVD REST API pagination,
~360K records) was not re-backfilled from scratch — EPSS's single bulk CSV
already gives near-complete CVE-id coverage; CVSS/description backfill for the
non-KEV majority still needs the slower NVD windowed sync.

The verified STIX connector lives at `connectors/stix_connector.py`, the new
D3FEND connector at `connectors/d3fend_connector.py`; graph at
`services/knowledge/graph/{store,builder,query}.py`; eval at
`services/evaluation/{store,datasets_gate,harness,security_harness}.py` +
`suites/*.json`; routing/answering at
`services/knowledge/{security_router,security_answer}.py`.

## Phase 11 — NIST OSCAL controls, CISA CSAF advisories, 19 new sources, sparse clone

**Correction to Phase 10's "not attempted" note:** NIST CSF 2.0 and SP 800-218
(SSDF) **do** have official structured OSCAL exports — they live in
`usnistgov/oscal-content` alongside the already-known SP 800-53 catalog; Phase
10 simply hadn't found them yet. All three (plus the SP 800-53 Privacy control
baseline) are now ingested for real.

| Scope | Status | Evidence |
|-------|--------|----------|
| NIST OSCAL structured controls — new `services/knowledge/controls/` subsystem (`oscal.py` pure parser, `store.py` schema, `sync.py`), separate from the pack/Chroma pipeline (matches the CWE/CAPEC precedent: exact-ID lookup needs a real SQL table, not semantic search) | ✅ | Live-synced from `usnistgov/oscal-content` (public domain, US Gov work): CSF 2.0 catalog (225 records), SP 800-53 rev5 full catalog (1216 records, 3512 real `related`-control links), SSDF v1.1 (65 records, 528 links incl. real cross-framework tags to CSF/EO 14028/BSIMM/etc.), SP 800-53 Privacy baseline (112 records, 792 links). **1618 records, 4832 links total.** Idempotent re-sync verified (0 written / all unchanged on 2nd run). |
| NIST narrative SPs with no OSCAL export — new `PDF` connector type, section-split on the doc's own numbered headings | ✅ | SP 800-207 Zero Trust (79/214), SP 800-61r3 Incident Response (11/138), SP 800-161r1 Supply Chain Risk Mgmt (102/1414) — all `nvlpubs.nist.gov`, public domain. |
| IETF RFCs — new `RFC` connector type, plain-text `www.rfc-editor.org`, IETF Trust Legal Provisions licence | ✅ | RFC 9700 (OAuth 2.0 Security BCP), 8446 (TLS 1.3), 7208 (SPF), 6376 (DKIM), 7489 (DMARC), 8252 (OAuth Native Apps) — 6 sources, 1279 chunks. |
| CISA CSAF vendor advisories — new `vulnerabilities/sources/cisa_csaf.py`, enriches (never duplicates) existing `vulnerability_records` CVE rows | ✅ | Real ROLIE feeds via `cisagov/CSAF` (TLP:WHITE, public domain). Bounded to the 250 most-recently-published across IT+OT/ICS feeds (~3950 available total — honestly not exhaustive). 249 advisories, 1838 CVE-level findings, **1702 distinct CVEs enriched** with real CVSS/CWE/remediation/fixed-version/vendor-reference data. |
| 14 new git-based connectors (OWASP CI/CD Top 10, OWASP K8s Top 10, SLSA spec, SPDX spec, OpenSSF Scorecard docs, OpenSSF Best Practices docs, Sigstore/cosign docs, Microsoft Sentinel detections, osquery docs, OCSF docs/schema) | ✅ | All licence-verified before install (CC-BY-SA-4.0 / Apache-2.0 / MIT / Community Specification License 1.0 — the last added to `licensing.py`'s policy table this session, a real permissive-with-attribution licence, not previously recognized). 9631 new chunks across these 19 new git+PDF+RFC connectors combined. |
| 4 new sources correctly **blocked** by the licence gate, not silently skipped | ⛔ | OWASP SAMM / CycloneDX / Dependency-Check (no machine-verifiable LICENSE file found in the time available → `manual_confirm`), Velociraptor docs (real CC-BY-NC-SA-4.0 → NonCommercial → `manual_confirm`). |
| Git-connector sparse/partial-clone fast path (`git_connector.py`) | ✅ | Azure/Azure-Sentinel's naive full shallow clone exceeded the 240s timeout (576MB+ for a repo where only ~500 YAML files under `Detections/` were wanted). Added an opportunistic `--filter=blob:none --sparse` clone derived from `include_globs`' directory prefix, falling back to the exact original full-clone path on any failure. Same repo: 240s timeout → **~30s, 9MB**. Verified no regression on all 20+ existing connectors (31/31 offline connector tests still pass). |
| Knowledge graph extended with real NIST control relationships (`_control_relationships()`) | ✅ | `related_control` edges sourced only from `control_links` rows where BOTH endpoints have a real synced record (never a dangling/fabricated edge — same rule as the ATT&CK side). Live: 749 control nodes, 3913 `related_control` edges. Graph total: 5146 nodes / 14,984 edges (up from 2,197 edges before Phase 10, 11,062 after Phase 10). |
| Router/answer extended for NIST control identifiers + a new `compliance` topic route | ✅ | `security_router.py`: `_NIST_CONTROL_RE` bounded to the 20 real SP 800-53 families + real CSF functions + real SSDF groups (never a bare 2-letter false-positive); `resolve_exact()`/`security_answer._answer_control()` field-driven, zero LLM dependency. `ROUTE_COMPLIANCE` checked **before** `ROUTE_CLOUD` (a `container`+`cosign` question is a supply-chain question, not a K8s/Docker-hardening one). |
| Eval suite grown 137 → **307 cases**, still 100% on every required gate | ✅ | Added: live-sampled real NIST control ids across all 4 frameworks (+ SP 800-53 enhancements), fake-control non-fabrication cases (real family prefix + nonexistent number — not an unrecognizable-format string, a genuine "plausible but absent" test), CISA-CSAF-enriched CVE lookups, compliance/cloud/detection/mitigation/IR/general topic coverage for every new source. **route_accuracy 1.0, exact_lookup_accuracy 1.0, non_fabrication_rate 1.0, citation_resolution_rate 1.0, injection_safety_rate 1.0**, p95 structured latency 31ms (<500ms gate). 4 real router-priority bugs found and fixed this way (compliance-vs-cloud ordering, missing `ocsf`/`csf`/`vendor advisor`/`ransomware incident` keywords) — not hidden, fixed. |
| 347 backend tests pass (up from 322) | ✅ | +25 new: `test_nist_controls.py` (oscal parser, controls store, router/answer/graph integration), `test_pdf_rfc_cisa_sources.py` (heading detection, CSAF normalization) — all offline, synthetic fixtures, no network. |
| SQL/Chroma consistency verified | ✅ | `oyster_knowledge` (50,155) + `oyster_vulnerabilities` (3,250) = 53,405 = exact `knowledge_chunks` SQL row count. Zero drift. |
| Oyster runtime data footprint | ✅ | 735MB total (`data/` dir: 463MB Chroma + 272MB SQLite), well under the 5GB budget; 765GB/926GB free (82.6%), well above the 15% floor. Temp download workdir (`data/knowledge_src/`) verified empty after every install — nothing left behind. |

**Deliberately not attempted this pass** (honest, not silently skipped): full
CISA cybersecurity-advisory/ICS-advisory coverage beyond the 250-advisory
bounded CSAF sample (~3700 more available); CISA Secure by Design, Cross-Sector
CPGs, StopRansomware hub (narrative/PDF, not yet parsed); AWS/Azure/GCP/MSRC
official docs (no confirmed permissively-licensed structured export located —
these are generally proprietary documentation, not open-licensed, so ingesting
them would need an explicit per-vendor licence review this pass didn't reach);
Red Hat/Ubuntu/Debian/PostgreSQL/Python/Node.js security-advisory feeds
(real feeds likely exist for several of these but weren't independently
licence-verified this pass); Elastic detection-rules (Elastic License 2.0,
correctly excluded — restrictive, not a blanket permissive licence); Splunk
Security Content, WebAuthn/FIDO2 (W3C spec, not yet ingested), DNSSEC RFCs
beyond the 6 already added, Microsoft security baselines. All of the above
are real, plausible next sources — none were ruled out for licensing reasons
discovered and rejected; they simply weren't reached in the time available.

## Phase 12 — full CISA CSAF/NVD corpus, GHSA/OSV structured intelligence, 6 detection/cloud sources

**Correction to this file's own record:** this file was never updated for Phase
12's work — the commit that did the work (`910a844`, branch
`oyster/knowledge-mastery-v4`) understated its own backend-test delta in its
commit message (claimed 347→456; the real, fresh-checkout-verified count was
347→420). That commit is already pushed and is not being rewritten; this
entry — and the corrected 420 baseline used throughout Phase 13 below — is the
honest record going forward.

| Scope | Status | Evidence |
|-------|--------|----------|
| CISA CSAF — bounded 250/~3950 sample → full production synchronizer | ✅ | Resume/checkpoint (`cisa_csaf_seen`), bounded concurrency, retry/backoff, quality-preserving merge. Full corpus: **3,958 advisories, 100% coverage, 14,513+ findings**. |
| NVD — KEV-only enrichment → full historical backfill | ✅ | CVSS v4 support, multi-source CVSS provenance (`cve_cvss_scores`), `embed=False` backfill path (storage discipline). **378,599/378,675 CVEs (99.98%) with real NVD data.** |
| GHSA (new) | ✅ | Sparse-clone of `github/advisory-database`'s `advisories/github-reviewed` tree, OSV-schema parser shared with OSV.dev. 34,437 advisories, 910 withdrawn. |
| OSV.dev (new) | ✅ | 8 ecosystems (npm/PyPI/Maven/Go/crates.io/NuGet/RubyGems/Packagist/GitHub Actions), GHSA-alias dedup. 248,961 records. |
| 6 secondary defensive sources | ✅ | Splunk Security Content, Falco rules+docs, Zeek docs, Suricata user guide, Azure security docs — all licence-verified, all `store_local`. |
| Router/answer extended for GHSA/OSV/package queries, source-disagreement, fixed-version aggregation | ✅ | New `ROUTE_PACKAGE`; `_QUERY_OSV_RE`/`_QUERY_GHSA_RE` identifier regexes; `resolve_exact()`/`security_answer.py` GHSA/OSV branches. |
| `busy_timeout=30000` added to all `conn()` factories | ✅ | Fixed a real concurrent-write `database is locked` crash discovered running 3 background sync jobs at once. |
| 420 backend tests pass (up from 347) | ✅ | Verified via fresh checkout of `910a844` in a separate worktree — this is the number that corrects the commit message's inaccurate "456". |
| Eval suite grown 307 → 460 cases, 100% on every gate | ✅ | 3 real router bugs found+fixed this way (npm scoped-package regex, OSV identifier false-positive/negative, IR-vs-detection keyword priority). |

## Phase 13 — Cycle V5: graph hardening, Microsoft/Linux/cloud sources, deterministic version+priority answers

**A structural finding, not a Phase 12 regression:** Phase 12's own worktree
was removed after that cycle finished (per this project's git-safety rules —
runtime databases are never committed). Because the sync jobs had been pointed
at that worktree's *local* `data/` directory rather than the persistent
checkout's, every byte of Phase 12's actual ingested data (the 378k NVD CVEs,
34k GHSA, 249k OSV, the whole knowledge graph) was deleted along with it — only
the *code* that produces that data survived, correctly, in git. Separately,
this cycle's audit also found that **41 of 67 materialized knowledge-pack
directories** (including `mitre-d3fend-src`, `mitre-attack-src`'s NIST-control
counterpart controls system, every RFC/NIST-SP/OWASP/OpenSSF/SLSA/SPDX/
Sigstore/OCSF/osquery pack, and 16 pre-Phase-12 hand-curated packs) had never
been loaded into *this* persistent checkout's `knowledge_chunks` table at all
— a pre-existing gap, not something this cycle broke. Both are now fixed: all
sync/install jobs in this cycle write to the persistent checkout's `data/`
directory (`OYSTER_DATA_DIR` pointed there explicitly), and all 60
non-licence-blocked packs (44 connector-managed + 16 hand-curated) are
reinstalled and verified present.

| Scope | Status | Evidence |
|-------|--------|----------|
| Persistent data directory fix | ✅ | All ingestion this cycle targets `oyster/backend/data/` in the main checkout (gitignored, outside any worktree) instead of a worktree-local copy — the exact mistake that erased Phase 12's data is now structurally avoided for future cycles. |
| Graph: generated+indexed `source`/`ecosystem`/`package` columns on `kg_nodes`; `edge_type`/`(src,edge_type)`/`(dst,edge_type)` indexes on `kg_edges` | ✅ | `services/knowledge/graph/store.py`. Safe in-place migration (pre-V5 tables without the new columns are dropped and rebuilt — the graph is a fully-derived artefact). |
| Graph: dangling edges are now structurally impossible to persist | ✅ | `builder.build()` filters every edge against the same build's own node set immediately before the atomic `replace_graph()` swap; anything that wouldn't have both endpoints is dropped and recorded as a `dangling_edge_dropped` inconsistency (never silently). `store.dangling_edges()` is the independent, read-only, post-hoc proof. Real-data run found and correctly dropped exactly 100 `cve→cwe` edges pointing at 12 now-deprecated CWE category ids (CWE-16/19/189/254/255/264/265/275/310/388/399/840) that NVD's historical classifications still reference but the current CWE catalog no longer contains — the underlying SQL classification is untouched, only the non-existent graph edge is skipped. |
| Graph: Splunk Security Content / Falco rules now feed real ATT&CK `detected_by` edges | ✅ | Both packs embed source-supplied `mitre_attack_id`/`T####` tags directly in their YAML; a bare-token extraction (safe only because these are curated detection-rule packs, never general prose) joins them the same way Sigma already was. |
| Graph: final rebuild + benchmarks | ✅ | **396,113 nodes** (capec 615, catalog 1, control 749, countermeasure 156, cve 36,990, cwe 969, ghsa 34,452, osv 321,714, pack 47, platform 22, technique 949) / **102,678 edges**. `nodes ≫ edges` is by design, not a defect (see the module's own docstring): a `cve`/`ghsa`/`osv` node is only created when it carries at least one real relationship — most of the 322k OSV records and a large share of NVD's 378k CVEs never received a CVE-CWE classification or a cross-reference from an installed advisory, so the majority of nodes legitimately have zero or one edge. Benchmarked (200 random samples each): exact node lookup p95 0.37ms; one-hop traversal p95 0.27ms; CVE→CWE→CAPEC 2-hop p95 2.18ms; package→advisory→CVE (structured SQL path — `osv_store.search_*_by_package`, batched into 4 queries instead of the prior N+1 pattern of up to 4×(matches) queries, a real ~35x speedup found while benchmarking: 232ms → 6.6ms on the single busiest real package) p95 9.76ms; ATT&CK technique→detection p95 2.54ms. All comfortably under the 500ms gate; `store.dangling_edges()` returns empty. |
| Git connector: sparse-checkout timeout bug fixed | ✅ | `sparse-checkout set` (which also updates the working tree — real blob-fetching work for a large monorepo) was hardcoded to 60s regardless of `KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT`; now shares that same configurable budget. This is what let `entra-identity-docs-src` (a ~3.2GB upstream repo) succeed in 302s where it previously timed out. |
| Microsoft Entra identity security docs (new) | ✅ | `MicrosoftDocs/entra-docs`, MIT. 7 narrowly-scoped sparse dirs (identity-platform, id-protection, id-governance, workload-id, identity, global-secure-access, standards). 600 docs / 9,945 chunks. |
| MSRC Security Update Guide | ⛔ | API is reachable without a key, but its redistribution/storage terms could not be verified via automated fetch (portal terms pages are JS-rendered) — blocked per the licence-unverifiable policy rather than guessed at. |
| Red Hat CSAF vendor advisories (new) | ✅ | Same CSAF 2.0 standard as CISA; `provider-metadata.json` explicitly declares `mirror_on_CSAF_aggregators: true`; every advisory's own `legal_disclaimer` states CC BY 4.0. RHSA-only (RHBA/RHEA bug-fix/enhancement advisories excluded — no CVE content). **27,027 attempted, 26,664 successful (363 exceeded the 2MB per-advisory size cap, isolated failures), 99,189 findings, 22,667 unique CVEs enriched.** |
| Ubuntu OSV ecosystem | ⛔ | Export is ~654MB compressed, over the connector's 400MB per-source safety cap and risky for the 5GB storage ceiling — not ingested. Debian's export (which shares much of Ubuntu's package heritage) was ingested instead. |
| Debian / Alpine / OSS-Fuzz OSV ecosystems (new) | ✅ | 64,050 / 4,489 / 4,213 records. |
| GCP official security docs | ⛔ | No official git-clonable/licence-clear docs-source repo found (unlike Microsoft/AWS, Google does not mirror cloud.google.com's source) — blocked rather than scraped. |
| AWS Well-Architected Security Pillar | ⛔ | No dedicated official docs-source repo found under `awsdocs` (the closest matches are workshop/lab repos, not the framework prose itself). |
| 6 AWS official service-guide docs (new) | ✅ | IAM (MIT), Organizations/GuardDuty/Security Hub/KMS/CloudTrail (CC BY-SA-4.0, confirmed via each repo's raw `LICENSE` file after GitHub's API license-detector misreported several as `NOASSERTION`). All are content-frozen "archived"-default-branch repos; each profile's `default_ref` points at the actual last-maintained `main`/`master` branch instead. 1,126 docs / 16,148 chunks total. |
| Kubernetes/Docker security docs, NIST controls (1,618 records/4,832 links), D3FEND, and 16 hand-curated packs | ✅ (restored) | Declared and licence-approved since before this cycle but absent from the persistent checkout (see the structural finding above) — reinstalled, not new content. |
| `services/knowledge/vulnerabilities/version_check.py` (new) | ✅ | Deterministic dotted-numeric version comparison against installed GHSA/OSV affected ranges. Never guesses: an unparseable version or range → `indeterminate`; no installed advisory → `not_found` (never "safe"). New `ROUTE_VERSION_CHECK`. |
| `services/knowledge/vulnerabilities/prioritization.py` (new) | ✅ | Deterministic, explainable KEV/EPSS/CVSS/fix-availability/advisory-recency/optional-asset-context scoring. Missing data is excluded from the weighted average and named in `missing_factors` — never defaulted to 0. Explicitly labeled "not a universal risk score." New `ROUTE_PRIORITIZATION`. |
| OS-distro fix cross-reference on CVE answers | ✅ | `retrieval.get_cve()` now surfaces Debian/Alpine package-level fix info via each OSV record's own CVE alias — `_answer_cve()` includes it in `defensive_actions`. |
| Frontend: `version_check`/`prioritization` routes | ✅ | `api.ts` types, `SecurityIntelligencePanel.tsx` route metadata + minimal dedicated rendering (verdict badge, ranked list) — typecheck/lint/build all clean. |
| AuthGate | ✅ (verified, unchanged) | Frontend requires explicit `NEXT_PUBLIC_OYSTER_DISABLE_AUTH=true`; backend fails closed (`raise RuntimeError`) if `OYSTER_ENVIRONMENT=production` and auth is still disabled. |
| NVD full-corpus enrichment | 🟡 | 378,020 total `vulnerability_records`; only 25,884 (6.8%) carry a real NVD description and 6,599 (1.7%) a real CVSS score as of this cycle's end — **not** the ~100% this file's Phase 12 entry reports. Root cause is external and reproducible: NVD's API served small ad-hoc requests normally throughout this session (confirmed via direct `curl`, sub-second) but a specific ~3.5-month `lastModified` window (2026-05-01 through today, 361k+ results — a mass-metadata-refresh event, the same phenomenon Phase 12 also hit) intermittently stalled for 15 minutes to 3+ hours per page-sequence before failing with a 503, even after splitting it into 2-day sub-windows with per-window retry. Three fetch strategies were tried (single backfill call, year-level chunking, 12-day chunking, 2-day chunking) before this was accepted as a session-bounded external outage rather than a code defect, and NVD sync was stopped to protect the rest of this cycle's delivery. The `sync_nvd_backfill(start, end)` entrypoint is unchanged and resumable — re-running it for `2026-05-01..today` when NVD's service stabilizes will pick up the remaining CVEs (they're idempotently upserted, not duplicated). |
| Backend tests | ✅ | 467 pass (up from the corrected 420 Phase-12 baseline; +47 new: prioritization, version_check, Red Hat CSAF, distro-fix cross-reference, graph-integrity/dangling-edge, version+prioritization router/answer wiring). |
| Eval suite grown 460 → 685 cases | ✅ | route_accuracy 1.0, exact_lookup_accuracy 1.0, non_fabrication_rate 1.0, citation_resolution_rate 1.0, injection_safety_rate 1.0, latency_p95_structured_ms 4.54 (<500ms gate). 685/685 passed. |
| SQL/Chroma reconciliation | ✅ | `knowledge_chunks` SQL = 106,936 = `oyster_knowledge` (97,062) + `oyster_vulnerabilities` (9,874) Chroma total. Exact match. |
| Storage | ✅ | 2.1GB runtime data (`memory.db` 1.2GB + `vector_db` 947MB), well under the 5GB budget; 763GB/926GB free (82%), well above the 15% floor. Connector workdir (`data/knowledge_src/`) verified empty — one 1.6GB leftover partial clone from an interrupted install attempt was found and removed during this cycle's own verification pass. |

**Deliberately not attempted this pass** (honest, not silently skipped):
Ubuntu OSV ecosystem (storage-cap risk, see above); GCP official docs and AWS
Well-Architected Security Pillar (no licence-clear structured source found);
MSRC Security Update Guide (terms unverifiable via automated fetch); a direct
CWE↔NIST-control graph edge type (the "which controls apply to this CVE"
question is still answerable — CVE→CWE and control exact-lookup both work
independently — but isn't yet one graph-native hop); GitHub Actions/Kubernetes/
Docker vendor-specific advisory feeds beyond what GHSA's reviewed corpus and
the existing `kubernetes-security-docs-src`/`docker-security-docs-src` packs
already cover (verified already-covered rather than re-ingested).
