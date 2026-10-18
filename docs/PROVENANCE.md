# Provenance of the imported Oyster application

Imported 2026-10-18 from the existing Oyster repository; the original was not modified.

| | |
|---|---|
| Source repo | `~/oyster-integration` (git worktree) |
| Branch / commit | `oyster-1x-integration` @ `b3bca2ba` (2026-10-14, "Fix Log4Shell identifier error, trace citation support, …"), clean tree |
| What was copied | `git archive HEAD oyster` — tracked files only (backend, frontend, knowledge packs, tests) |
| Left out | `oyster/docs/`, `oyster/deploy/`, `oyster/backend/deploy/`, `oyster/CLAUDE.md` (internal handoffs / deployment runbooks), `shark/`, `voice-engine/`, `supabase/` |
| Not in git (see README → Assets) | knowledge index + memory DB (`~/redbears-assets/data`), Python venv, `node_modules`, model weights |

The knowledge index and venv were APFS-cloned (`cp -cR`), so they occupy no extra disk until written to.

## Model state found in the source repo (verified, not assumed)

* **Selected default**: `oyster-dolphin-v2` → Ollama `oyster-dolphin-v2-gguf-q4`, digest
  `sha256:d82c7860dff52af5ba63f2f4eda43b958ef3f309f0e2d79ca7b0782926166670`, Llama 8.0B, Q4_K_M, GGUF
  (`/api/ps` confirmed it loaded; running backend env `OYSTER_DEFAULT_MODEL=oyster-dolphin-v2`;
  frontend `DEFAULT_MODEL = "oyster-dolphin-v2"`). Weights: `~/.ollama/models/blobs/sha256-61422299…`
  (sha256 `61422299380cb628562411fff869d56b555e0f72257a7a37d7c0e585ca6143d3`, 4,920,745,984 B), matching the manifest in `~/oyster-heretic-work/martin-oyster-dolphin-v2/`.
* **Newest experimental artifact** is the same V2 weights as an MLX safetensors build
  (`oyster-dolphin-v2-q4`, digest `3ca7cf03af2a`, reports "2.4B" — a packed-shape counting artifact; ~1.85× slower). It is not selected.
* **Rollback**: `oyster-dolphin-v1-q4` (digest `b6e5d24c7da0`), `dolphin3`.
* **The brief's history was out of date**: V2 *was* promoted (commit `c2b8b3b3`, 2026-10-09) and V1 is now the rollback.
* Stack unchanged: FastAPI + Next.js 14 + Ollama + hybrid retrieval (Chroma `all-MiniLM-L6-v2` vectors + SQLite FTS, RRF, trust/freshness weighting). Index: 118,317 unique chunks, 77 sources.
