# Verification results (2026-10-18, 24 GB M5 Mac)

Everything below was observed on this machine; nothing is projected. Raw per-question JSON is kept outside git in `~/redbears-assets/results/`.

## Checks

| Check | Result |
|---|---|
| Existing backend suite (`pytest`, isolated data dir) | **947 passed, 1 skipped** (+9 new rerank tests); 6 failures in `test_mcp_deploy_config.py` were removed with the deploy bundle that file tests (deliberately not imported) |
| Frontend `tsc --noEmit` | clean |
| Frontend `vitest` | **75 passed** (72 existing + 3 new `RedBearsPanel` tests: reranked badge, explicit fallback, in-band error) |
| Frontend/backend start | dev server 200 on :3101, backend `/health` ok on :8101 (default `oyster-dolphin-v2`, `huihui-qwen3.8-27b` listed) |
| Existing Oyster responds | `/chat` stream (Oyster V2) and `/knowledge/ask/stream` OK |
| Huihui streamed answer | `/chat` and `/knowledge/ask/stream` OK (10 RAG answers below) |
| Nemotron real request, ordering used | local NIM-schema server; e.g. Kerberoasting: MITRE T1558.003 moved from retrieval rank 12 → 2, Splunk Kerberoasting detection rank 1 → 3 |
| Fallback: reranker process down | `fell_back — reranker unavailable (ConnectError)` in 5 ms; selection identical to the un-reranked path |
| Fallback: NVIDIA-hosted URL, no key | `fell_back — NVIDIA_API_KEY is not set …`, no request sent |
| Fallback: timeout | observed live once (reranker paged out under memory pressure, 8 s limit → `fell_back`); default limit since raised to 15 s |
| Not tested live | a real NIM or NVIDIA-hosted call with a key (no credentials; hosted 1b-v2 endpoint returns 410) — covered by unit tests only. No browser automation was available, so the panel was verified by component tests + API, not a screenshot |

## Same 5 cybersecurity questions, both models, reranking on (top-5 evidence, warm models)

| | Oyster Dolphin V2 (8B Q4_K_M) | Huihui 27B (UD-IQ3_XXS, ctx 4096) |
|---|---|---|
| Mean time to first token | 13.3 s (9.7–20.0) | 36.6 s (31.5–43.3) |
| Mean total | 24.5 s | 75.7 s |
| Answers with inline `[n]` citations | 3 / 5 | 4 / 5 |
| Output-check flag `missing_citation` | 2 (Log4Shell, T1055) | 1 (CWE-89: only one source was retrievable) |
| `[n]` pointing outside the delivered sources | 0 | 0 |

TTFT includes retrieval (0.3–6 s) + rerank (0.8–3.7 s) + prompt prefill; the 27B prefill dominates on this memory-constrained machine.

**Citation correctness (spot-checked, not exhaustive):** Log4Shell — both models answered CVE-2021-44228; source [1] is the local CVE-2021-44228 record, which contains the CVSS 10.0 / KEV / EPSS figures Huihui cites; all 5 delivered passages contain the id. `[n]` numbers always map to the delivered, reranked list (`n` is reassigned after reranking, `chunk_id`/URL travel with each item).

**Quality (my reading of 4 of 10 answers, not a benchmark):** Huihui's answers were more thoroughly grounded and structured (T1055: every claim cited, detection strategies drawn from the sources). Oyster V2's T1055 answer carried no citations and added tools (OSSEC, Snort, Anomali) not in the evidence. For ransomware IR, V2 gave a shorter generic list; Huihui used the retrieved Azure/Defender guidance. Huihui is ~3× slower. One run (V2, Kerberoasting) used the fallback order because of the cold-reranker timeout, so its sources differ from Huihui's for that question. n = 5 questions, one run each: indicative only.
