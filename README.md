# Red Bears — Oyster with Huihui + Nemotron reranking

Oyster (local cybersecurity copilot: FastAPI + Next.js + Ollama + a 118k-chunk security knowledge base) imported from
`oyster-integration@b3bca2ba` (see [docs/PROVENANCE.md](docs/PROVENANCE.md)), plus:

1. **Huihui Qwen3.8-27B abliterated** (upstream model) as a separately named answer model next to the existing Oyster Dolphin V2/V1.
2. **Nemotron reranking**: `question → existing hybrid retrieval (16 candidates) → llama-nemotron-rerank-1b-v2 → top 5 → answer model, cited [n]`.
3. A **Red Bears** panel (sidebar) showing model choice, reranking status, streamed answer, and sources.

**Status: local development checkpoint, not a deployment-ready release** — see [docs/CHECKPOINT.md](docs/CHECKPOINT.md) and [docs/SECURITY.md](docs/SECURITY.md).

Details, checksums, measurements: [docs/MODELS.md](docs/MODELS.md), [docs/RESULTS.md](docs/RESULTS.md).

## Run the demo

Prereqs: macOS arm64, Ollama running, Python 3.11, Node 18+. Large assets live outside git in `~/redbears-assets` (`REDBEARS_ASSETS`).

```bash
cp .env.example .env            # placeholders only; defaults work for the local demo
scripts/setup.sh                # venv, npm ci, downloads+verifies Huihui (11 GB), registers it with Ollama
scripts/start.sh                # reranker :8110, backend :8101, frontend :3101
open http://127.0.0.1:3101      # sidebar → "Red Bears"
scripts/stop.sh                 # stops only these three services
```

The knowledge index (2.4 GB) is not in git: copy an existing Oyster snapshot to `$REDBEARS_ASSETS/data/knowledge_snapshot`
(`cp -cR <oyster>/oyster/backend/data/knowledge_snapshot ~/redbears-assets/data/` — an APFS clone, no extra disk) or rebuild from the packs
(`oyster/backend/KNOWLEDGE_BASE.md`). Ports differ from the original Oyster (3001/8001) so both can run side by side.

## What the UI shows

* Model: Oyster Dolphin V2 (default) / Huihui 27B / Oyster Dolphin V1 (rollback).
* Checkbox **Rerank evidence with Nemotron**. The badge is green only when Nemotron's order was used
  (`Nemotron reranked 16 → 5 · local · 1.9 s`); otherwise amber with the reason (reranker down, timeout, HTTP error, missing `NVIDIA_API_KEY`, disabled).
* Sources are numbered to match `[n]` in the answer; each shows its Nemotron logit and "retrieval rank a → b". `chunk_id`, pack, URL, licence stay attached through reranking.

## Environment (all server-side; see `.env.example`)

`NEMOTRON_RERANK_URL`, `NEMOTRON_RERANK_MODEL`, `NEMOTRON_RERANK_TIMEOUT_S`, `NEMOTRON_RERANK_CANDIDATES`, `NVIDIA_API_KEY` (only for auth-requiring NIM endpoints; never sent to the browser),
`OYSTER_HUIHUI_NUM_CTX`, `OYSTER_HUIHUI_OLLAMA_TAG`, `HUIHUI_VARIANT` (setup), `REDBEARS_ASSETS`.

## Tests

```bash
cd oyster/backend && OYSTER_DATA_DIR=/tmp/rb/data OYSTER_LOGS_DIR=/tmp/rb/logs ../../.venv/bin/python -m pytest -q   # or $REDBEARS_ASSETS/venv-backend/bin/python
cd oyster/frontend && npx tsc --noEmit && npx vitest run
python3 scripts/compare_models.py out.json 1                                   # same questions, both models (backend running)
```
