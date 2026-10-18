# Oyster Knowledge Base — 100k Verification Evidence

_Generated from `data/reports/knowledge_audit_latest.json` and `retrieval_eval_retrieval-100k-v1_latest.json`. Audit run: 2026-09-07T18:22:37.546245+00:00; retrieval eval: 2026-09-07T18:25:47.336545+00:00._


## Headline

- **Eligible unique searchable chunks: 106,045** (threshold 100,000 — **PASS**)
- Attribution coverage: **100.0%** · Index availability (eligible): **100.0%**
- Retrieval top-5 pass rate: **93.22%** (110/118 cases) · MRR 0.7726 · citation rate 100%
- Embedding model: `all-MiniLM-L6-v2` (384-dim) · Chroma cosine · SQLite provenance

## Totals (physical store)

| Metric | Value |
|---|---:|
| Total provenance rows | 106,936 |
| Total Chroma embeddings | 106,936 |
| Distinct content hashes | 106,598 |
| Exact-duplicate rows (excluded from count) | 338 |
| Near-duplicate groups (normalised-text proxy) | 19 |
| Empty/trivial rows <40 chars (excluded) | 680 |
| Missing attribution | 0 |
| Missing embedding (not indexed) | 0 |
| Orphan embeddings (Chroma without row) | 0 |
| FTS lexical rows | 106,936 |
| **Eligible unique searchable chunks** | **106,045** |
| Source count | 70 |
| pack@versions | 71 |

## Structured records NOT counted as knowledge chunks

These are reachable by exact-id lookup but are not embedded chunks, so counting them would be inflation:

- `vulnerability_records`: 378,020
- `cwe_records`: 969
- `capec_records`: 615

## Per-source table

Eligible = meaningful (>=40 chars) + attributed + hashed + deduped + indexed. Indexed = rows present in the routed Chroma collection.

| Source (pack_id) | Ingested rows | Unique chunks | Eligible chunks | Indexed |
|---|---:|---:|---:|---:|
| splunk-security-content-src | 14,574 | 14,372 | 14,441 | 14,574 |
| sigma-src | 10,814 | 10,759 | 10,665 | 10,814 |
| entra-identity-docs-src | 9,945 | 9,941 | 9,913 | 9,945 |
| vulnerability-cve | 8,290 | 8,290 | 8,290 | 8,290 |
| atomic-red-team-src | 5,981 | 5,977 | 5,954 | 5,981 |
| aws-iam-docs-src | 5,710 | 5,706 | 5,685 | 5,710 |
| yara-reversinglabs-src | 5,041 | 5,031 | 5,019 | 5,041 |
| owasp-mastg-src | 4,881 | 4,881 | 4,832 | 4,881 |
| owasp-cheatsheets-src | 3,585 | 3,585 | 3,580 | 3,585 |
| mitre-attack-src | 3,562 | 3,559 | 3,517 | 3,562 |
| openssf-best-practices-src | 3,199 | 3,199 | 3,195 | 3,199 |
| aws-security-hub-docs-src | 3,097 | 3,094 | 3,080 | 3,097 |
| aws-kms-docs-src | 2,932 | 2,932 | 2,922 | 2,932 |
| azure-security-docs-src | 2,154 | 2,154 | 2,148 | 2,154 |
| suricata-userguide-src | 2,055 | 2,055 | 2,044 | 2,055 |
| aws-cloudtrail-docs-src | 2,018 | 2,018 | 2,014 | 2,018 |
| owasp-wstg-src | 1,854 | 1,854 | 1,843 | 1,854 |
| aws-organizations-docs-src | 1,612 | 1,612 | 1,605 | 1,612 |
| azure-sentinel-detections-src | 1,283 | 1,283 | 1,276 | 1,283 |
| falco-docs-src | 1,217 | 1,217 | 1,207 | 1,217 |
| kubernetes-security-docs-src | 984 | 984 | 982 | 984 |
| mitre-cwe | 969 | 969 | 969 | 969 |
| lolbas-src | 817 | 817 | 807 | 817 |
| mitre-d3fend-src | 808 | 769 | 798 | 808 |
| aws-guardduty-docs-src | 779 | 779 | 774 | 779 |
| owasp-asvs-src | 671 | 671 | 668 | 671 |
| mitre-capec | 615 | 615 | 615 | 615 |
| gtfobins-src | 610 | 608 | 599 | 610 |
| nist-sp800-161-src | 553 | 553 | 550 | 553 |
| slsa-spec-src | 533 | 533 | 532 | 533 |
| osquery-docs-src | 521 | 521 | 521 | 521 |
| zeek-docs-src | 493 | 493 | 492 | 493 |
| rfc8446-tls13-src | 482 | 482 | 477 | 482 |
| mitre-attack-ics-src | 461 | 460 | 455 | 461 |
| mitre-attack-mobile-src | 356 | 356 | 351 | 356 |
| falco-rules-src | 322 | 322 | 322 | 322 |
| ocsf-docs-src | 276 | 276 | 275 | 276 |
| owasp-api-security-src | 251 | 250 | 246 | 251 |
| docker-security-docs-src | 247 | 247 | 247 | 247 |
| rfc6376-dkim-src | 228 | 228 | 221 | 228 |
| openssf-scorecard-docs-src | 222 | 222 | 222 | 222 |
| owasp-top10-src | 211 | 210 | 209 | 211 |
| wadcoms-src | 192 | 192 | 180 | 192 |
| sigstore-cosign-docs-src | 184 | 182 | 180 | 184 |
| spdx-spec-src | 183 | 183 | 182 | 183 |
| nist-sp800-207-src | 181 | 181 | 180 | 181 |
| rfc7489-dmarc-src | 175 | 175 | 173 | 175 |
| rfc9700-oauth-security-src | 169 | 169 | 165 | 169 |
| rfc7208-spf-src | 150 | 150 | 148 | 150 |
| nist-sp800-61-src | 138 | 138 | 138 | 138 |
| owasp-cicd-top10-src | 108 | 108 | 107 | 108 |
| owasp-k8s-top10-src | 77 | 77 | 77 | 77 |
| rfc8252-oauth-native-src | 75 | 75 | 74 | 75 |
| engagement-governance | 9 | 9 | 9 | 9 |
| kali-linux | 9 | 9 | 9 | 9 |
| owasp-wstg | 9 | 9 | 9 | 9 |
| gtfobins | 8 | 8 | 7 | 8 |
| hacktricks | 8 | 8 | 8 | 8 |
| web-appsec | 8 | 8 | 8 | 8 |
| mitre-attack | 7 | 7 | 7 | 7 |
| ai-llm-security | 4 | 4 | 4 | 4 |
| api-security | 4 | 4 | 4 | 4 |
| identity-ad | 4 | 4 | 4 | 4 |
| cloud-security | 3 | 3 | 3 | 3 |
| detection-engineering | 3 | 3 | 3 | 3 |
| external-asm | 3 | 3 | 3 | 3 |
| incident-response-dfir | 3 | 3 | 3 | 3 |
| network-pentest | 3 | 3 | 3 | 3 |
| threat-intel | 3 | 3 | 3 | 3 |
| vuln-management | 3 | 3 | 3 | 3 |

## Failed / incomplete ingestion jobs

- Failed or incomplete import jobs: **11** — all NVD CVE historical-backfill runs that hit NVD API `HTTP 503/429` rate limiting, plus a few stale `running` records from a process stopped on 2026-08-18. These are the retryable *source-temporarily-unavailable* class; they do not affect the eligible count (the CVE pack holds 8,290 embedded chunks and 378,020 structured records already).
- Latest chunk ingested: 2026-08-18T01:20:50.928533+00:00
- Latest import job: 2026-08-18T14:57:56.608556+00:00

## Retrieval evaluation failures (honest)

8 of 118 cases did not retrieve an expected source within top-5 (pass rate 93.22% >= 90% required). These are genuine broad-query / substring-strictness misses, left un-tuned:

- `cheatsheet-password-storage`: pack_hit=True source_hit=False top_packs=['owasp-top10-src', 'owasp-cheatsheets-src', 'owasp-asvs-src', 'owasp-top10-src', 'owasp-cheatsheets-src']
- `entra-mfa`: pack_hit=True source_hit=False top_packs=['azure-security-docs-src', 'entra-identity-docs-src', 'azure-security-docs-src', 'entra-identity-docs-src', 'azure-security-docs-src']
- `lolbas-rundll32`: pack_hit=False source_hit=True top_packs=['atomic-red-team-src', 'mitre-attack-src', 'mitre-capec', 'mitre-capec', 'mitre-capec']
- `generic-privesc-linux`: pack_hit=False source_hit=True top_packs=['splunk-security-content-src', 'splunk-security-content-src', 'splunk-security-content-src', 'hacktricks', 'mitre-cwe']
- `generic-detection-lateral`: pack_hit=True source_hit=False top_packs=['sigma-src', 'sigma-src', 'vulnerability-cve', 'vulnerability-cve', 'vulnerability-cve']
- `generic-cloud-logging`: pack_hit=False source_hit=False top_packs=['sigma-src', 'sigma-src', 'vulnerability-cve', 'aws-iam-docs-src', 'vulnerability-cve']
- `generic-container-runtime`: pack_hit=True source_hit=False top_packs=['owasp-cheatsheets-src', 'owasp-cheatsheets-src', 'kubernetes-security-docs-src', 'owasp-k8s-top10-src', 'kubernetes-security-docs-src']
- `generic-ransomware-response`: pack_hit=False source_hit=True top_packs=['azure-security-docs-src', 'azure-security-docs-src', 'azure-security-docs-src', 'vulnerability-cve', 'vulnerability-cve']

## Exact commands used

```bash
# from oyster/backend, venv active
python -m scripts.rebuild_fts               # repair lexical index (additive, idempotent)
python -m scripts.audit_knowledge           # authoritative audit -> terminal + JSON, exit 0 on PASS
python -m scripts.run_retrieval_eval --suite retrieval-100k-v1 --top-k 5   # >=90% gate
python -m pytest -q                         # full backend suite
```

Reports are written to `data/reports/` (gitignored): `knowledge_audit_latest.json`,
`retrieval_eval_retrieval-100k-v1_latest.json`.

## Test results

- Backend pytest: **533 passed** (523 pre-existing + 10 new knowledge-100k tests), 0 failed.
- New tests (`tests/test_knowledge_100k_audit.py`): eligibility (dedup/trivial/attribution/index/orphan),
  metrics parity, public-statement withholding below threshold, FTS additive+idempotent rebuild,
  retrieval scoring, suite >=100 cases, and a live-store check asserting the real store >= 100,000.
- Frontend: `tsc --noEmit` 0 errors, `next lint` 0 errors, `next build` OK.

## Storage & runtime

- `data/memory.db` ≈ 1.2 GB (SQLite provenance + structured vuln records + FTS).
- `data/vector_db` ≈ 942 MB (Chroma persistent, cosine, 384-dim MiniLM).
- Audit: a few seconds. FTS rebuild (set-based): ~2 s. Retrieval eval (118 cases, real embeddings): ~45 s.

## What must NOT be committed

`data/` (memory.db, vector_db, reports, uploads, artifacts), `knowledge_src/` connector work
dirs, `.env`, model weights, downloaded upstream archives — all covered by `.gitignore`. Only
source, tests, docs and the eval suite JSON are committed.

## Reproduce the count

```bash
python -m scripts.audit_knowledge --floor 40 --threshold 100000   # RESULT: PASS
```

Final commit / branch are recorded in git on `oyster/verified-100k-knowledge`.
