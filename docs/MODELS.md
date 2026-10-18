# Models and runtimes

## Answer models

| Key (UI) | Role | Ollama tag | Notes |
|---|---|---|---|
| `oyster-dolphin-v2` | **Default**, existing Oyster | `oyster-dolphin-v2-gguf-q4` (digest `d82c7860dff5`) | Llama 8.0B, Q4_K_M, 8192 ctx. Unchanged. |
| `oyster-dolphin-v1` | Rollback | `oyster-dolphin-v1-q4` (`b6e5d24c7da0`) | Unchanged. |
| `huihui-qwen3.8-27b` | **Upstream Huihui model, integrated into Oyster** (not an Oyster-transformed model) | `huihui-qwen3.8-27b-abliterated-ud-iq3xxs` | See below. |

### Huihui

* Upstream: <https://huggingface.co/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF>, **pinned revision `1c69098e9c32db6dc06fc48f1d6cc75ad07da89e`** (last modified 2026-10-10). Base `Qwen/Qwen3.8-27B`, abliterated by huihui-ai. Licence **Apache-2.0** (card + metadata). Not gated.
* Architecture (GGUF): `qwen35`, 27.3B params, 262,144 trained context, hybrid attention, vision tower in a separate `mmproj` file (not used here).
* **Selected file: `Huihui-Qwen3.8-27B-abliterated-UD-IQ3_XXS.gguf`**, 11,021,122,464 B (11.0 GB), quantisation IQ3_XXS (Unsloth "UD" mixed precision),
  sha256 `e86259c841888b06fd84750963a0263947c9aae3c3029b52cbb3faa34a554827` (matches the Hugging Face LFS hash; re-verified after download).
* Runtime: Ollama (app 0.40.0, `runner: llamacpp`) loaded `qwen35` natively; Ollama reports capabilities `completion, tools, thinking` and uses the template embedded in the GGUF (the Modelfile sets no TEMPLATE). Standard llama.cpp suffices — **no Ternary/PrismML variant is used**.
* Context: `num_ctx 4096` (`OYSTER_HUIHUI_NUM_CTX`). 11.24 GB resident on the GPU at that setting. Not increased: see measurements.

#### Why this quantisation (24 GB M5 Mac, measured)

File sizes from the HF listing (bigger label ≠ bigger file — mixed-precision "UD"/"_L" variants break the ordering):
UD-Q2_K_XL 10.0 GB · **UD-IQ3_XXS 11.0 GB** · UD-Q3_K_XL 13.3 GB · UD-IQ4_XS 14.4 GB · UD-DW-Q4_K_M 16.6 GB · Q4_K 16.8 GB · Q2_K_L 17.2 GB (larger than Q3_K 13.5 GB and Q4_K_S 15.6 GB).

| | UD-IQ4_XS (14.40 GB) | **UD-IQ3_XXS (11.02 GB)** |
|---|---|---|
| Resident (`ollama ps`, ctx 4096) | 14.08 GB | 11.24 GB |
| Single-turn decode | 8.0 tok/s | 10.2–10.8 tok/s |
| System "memory free" while loaded | 12 % | 38 % |
| Full RAG request with the reranker alongside | reranker was paged out and timed out (8 s); 133 s total | completes; see comparison |

The machine already ran the original Oyster stack, VS Code, Safari and the Codex extension, and was using ~9 GB of swap *before* Huihui loaded. With IQ4_XS the 27B model squeezed the other processes into swap; IQ3_XXS fits with headroom. IQ4_XS stays registered (`OYSTER_HUIHUI_OLLAMA_TAG=huihui-qwen3.8-27b-abliterated-ud-iq4xs`) for a machine with more free RAM. The IQ3_XXS choice costs some model quality that was **not** measured against IQ4_XS here.

#### Verified behaviour (real calls to Ollama / the backend)

* Streaming through Oyster `/chat` (raw text, `X-Oyster-Model: huihui-…-ud-iq3xxs`) and through `/knowledge/ask/stream` (NDJSON) — works.
* Stop behaviour: custom `stop` sequence honoured (`ONE TWO ` then stopped, `done_reason: stop`); a "reply exactly OK" prompt ends on the model's own end-of-turn with no runaway.
* **Tool calling**: with a `lookup_cve` tool declared, the model returned a well-formed `tool_calls` entry `lookup_cve({"cve_id": "CVE-2021-44228"})` via Ollama `/api/chat`. This verifies the *model + template* only. Oyster's own tool-execution engine is disabled in this configuration (`OYSTER_EXECUTION_ENGINE_ENABLED=false`) and was **not** wired to Huihui.
* Thinking is disabled per request (`think:false`) like the other thinking-capable models in Oyster.

## Nemotron reranker (role: evidence reranking — not a chat or reasoning model)

* Model: **`nvidia/llama-nemotron-rerank-1b-v2`**, HF revision `828765652b05bd439c9789d2a6d093db1caa1443`. Cross-encoder fine-tuned from Llama-3.2-1B (bidirectional attention, mean pooling, 1-logit head), ~1B params BF16, 8192-token limit, 26 languages. Licence: OpenMDW-1.1 (+ Llama 3.2 Community Licence). Not gated.
* **Hosted endpoint is gone**: `POST https://ai.api.nvidia.com/v1/retrieval/nvidia/llama-nemotron-rerank-1b-v2/reranking` returns HTTP 410 *"reached its end of life on 2026-08-25"* (checked 2026-10-18). The model card points to the NIM container / open weights instead.
* So it runs **locally** (`rerank_server/server.py`, transformers on Apple MPS, ~2.5 GB) and exposes the documented NIM schema `POST /v1/ranking` (`query.text`, `passages[].text`, `truncate` → `rankings[{index, logit}]`). Pointing `NEMOTRON_RERANK_URL` + `NVIDIA_API_KEY` at a real NIM needs no code change.
* Sanity check against the model card's own example: ours 20.75 / −0.43 / −23.13 vs card 20.6 / – / −23.1 (BF16 on MPS vs CUDA).
* No NVIDIA credentials exist on this machine (env, shell profiles, repos checked, values never printed). The hackathon brief gave no requirement for a Nemotron *generative* model, so none was added.
