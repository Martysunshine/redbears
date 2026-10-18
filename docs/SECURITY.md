# Security posture and operating runbook

**Status: local development checkpoint — NOT a deployment-ready release.** `.env` being git-ignored is necessary, not sufficient. Open items are listed at the end.

## Secrets: what exists and where it lives

| Secret | Used by | Where it lives | Never |
|---|---|---|---|
| `NVIDIA_API_KEY` (only if using a hosted/NIM endpoint) | backend → `*.nvidia.com` only | host secret manager / protected env | in git, images, build args, frontend bundle, logs, model context |
| `NEMOTRON_RERANK_API_KEY` = `RERANK_SERVER_TOKEN` | backend ↔ private rerank endpoint | secret manager | same |
| `OYSTER_SUPABASE_JWT_SECRET` / Supabase URL | backend token verification | secret manager | same |
| `OYSTER_MCP_HTTP_TOKENS` | MCP gateway (≥24 random chars in prod) | secret manager | same |
| `data/.memory_key` | decrypts stored user memories | `$OYSTER_DATA_DIR`, outside git, backed up separately from the DB | beside the DB it decrypts |

Only `NEXT_PUBLIC_*` values reach the browser (API URL, Supabase *anon* URL/key — public by design). The NVIDIA key is read only by `services/rerank_service.py` and is sent only when the endpoint host ends in `nvidia.com` (unit-tested); local/third-party rerank endpoints use the separate `NEMOTRON_RERANK_API_KEY`.

## Environments
Keep **development / demo / production** as separate credential sets (separate NVIDIA keys, Supabase projects, JWT secrets, MCP tokens). Never reuse a dev key in demo/prod. Inject values at runtime from the provider's secret manager (e.g. Docker/Compose secrets, Fly/Render/Vercel/Hostinger env-secrets); do not use `ARG`/`ENV` for secrets in a Dockerfile, do not `COPY .env`, and do not put secrets in `NEXT_PUBLIC_*`. Use scoped keys (one key per environment, rerank-only if the provider supports scopes) and restrict who can read the secret manager (admin access ≠ developer access).

## Configure → rotate → revoke (authorised maintainers)
* **Configure**: create the key in the provider console → store it in the environment's secret manager → redeploy/restart → confirm in the UI that the reranking badge shows `ran` (no key value is displayed anywhere).
* **Rotate** (routine, and **mandatory after any suspected exposure — deleting a file from git is not rotation**): create the new key → update the secret → restart → verify → **revoke the old key** in the provider console → note the date. For `RERANK_SERVER_TOKEN`/`NEMOTRON_RERANK_API_KEY`, change both sides together. For the Supabase JWT secret, rotating invalidates all sessions. Rotating `data/.memory_key` requires re-encrypting stored memories first.
* **Revoke**: revoke in the provider console first, then remove from the secret manager. Remove a maintainer's access to the secret manager when they leave.
* If a secret was ever committed to any repo (including the source Oyster repo), treat it as compromised: rotate, then (optionally) purge history — purging does not un-leak it.

## Access control (verified 2026-10-18)
With `OYSTER_DISABLE_AUTH=false` and `OYSTER_PUBLIC_CHAT_ENABLED=false`, all 193 routes in the OpenAPI spec were requested without credentials: **191 returned 401**, `GET /health` 200, and the token-addressed `GET /shared/findings/{token}` 404 for an invalid token. With the default `PUBLIC_CHAT_ENABLED=true`, 4 more routes answer anonymously by design (`/me`, `/me/training-consent`, project artifact listing, and `/chat` with a 1-message/day/IP allowance on the *local* public model; uploads return 422 validation, i.e. reachable) — **disable public chat for any shared deployment**. A bad bearer token → 401. Foreign-origin CORS preflight received no `Access-Control-Allow-Origin`.
* Streaming (`/knowledge/ask/stream`), documents, knowledge, execution, MCP, agent, memory, training: admin-gated (401 unauthenticated).
* Production boot guards (`config.py`) refuse to start with: auth disabled, no admin emails, no Supabase URL, weak MCP tokens, non-HTTPS/`*` CORS origins, non-HTTPS non-loopback rerank URL.
* Limits: `/knowledge/ask*` 12 req/min per caller (`OYSTER_KNOWLEDGE_STREAM_RATE_PER_MIN`); remote rerank calls capped at 500/UTC-day/process (`NEMOTRON_RERANK_DAILY_CALL_LIMIT`, then visible fallback); chat has its own queue/quota. Limits are in-process (single worker). **No provider-side spend cap is configured — set one in the NVIDIA console.**
* Positive authorisation (valid admin vs. non-admin Supabase token) was **not** exercised live — no Supabase project here; only the existing unit tests cover it.

## Agent / sandbox isolation
* The Execution Engine, legacy MCP tools and agent loop are off (`OYSTER_EXECUTION_ENGINE_ENABLED=false`) and 401 without admin. Do not enable them on a shared host.
* Fixed here: legacy MCP command/network/project tools ran subprocesses with the **full backend environment** (a tool running `env` would have seen every secret). They now get an allowlisted env (`mcp_server/tools/_safe_env.py`, tested). The newer Execution Engine already used a minimal env.
* **Not implemented / not verified:** disposable container sandbox for attack simulation, egress/metadata/host-file denial enforced outside the model, target allowlist enforced at network level, Juice Shop isolation. Until those exist, do not run attack tools against anything. No Docker socket is mounted anywhere in this repo (searched). Retrieved text is already framed as untrusted data in the prompts; that is a mitigation, not isolation.

## Data and retention
Uploaded documents, memory DB, logs and reports live under `$OYSTER_DATA_DIR`/`$OYSTER_LOGS_DIR` (outside git, `chmod 700` them on shared hosts). **No retention schedule, backup encryption or access-controlled log shipping is implemented yet.** Audit logging stores question prefixes; the NVIDIA key is never logged (rerank errors log only the exception type).

## Open blockers before any deployment
1. Repo visibility (see checkpoint notes); licence/attribution for third-party knowledge packs (docs/CHECKPOINT.md).
2. Sandbox for attack simulation, egress control, Juice Shop isolation, detection validation — unimplemented.
3. Tavily research and generative-Nemotron orchestration — unimplemented.
4. Provider spend caps, HTTPS termination/reverse proxy, WAF, shared (multi-worker) rate limiting.
5. Retention/backup policy; verification of valid-token authorisation against a real Supabase project.
6. Production-mode frontend bundle scan (only the dev bundle was scanned; no secrets or secret names found).
