# Red Bears — Oyster security research and validation

Oyster is Red Orca's existing cybersecurity copilot. Red Bears is the hackathon project building on it: help security teams research threats, reproduce attacks in isolated environments, and check whether their defences detect them before an incident.

**Development checkpoint: 18 October 2026. This is not a deployment-ready release.** The local implementation now includes restored Chat navigation, a bounded Token Factory/Tavily research loop, an evidence ledger, persisted activity and an optional isolated lab handoff. Live cloud research remains unverified: the operator chose to continue without provider credentials. The implementation has not been published to the public remote; its published baseline and README-only branch do not include these additions. A separately runnable research package is prepared in `public_submission/`, pending publication review.

## Existing product and hackathon scope

Oyster already provides a Next.js frontend, FastAPI backend, Ollama-backed chat, conversation history, citations, security knowledge retrieval, Security Intel Q&A and saved findings. Oyster Dolphin V2 and the older Dolphin option belong to that existing model experience; their weights are not supplied by Git.

The published Red Bears baseline adds a Huihui 27B answer-model option, local Nemotron evidence reranking, an Ask panel and development scripts. The subsequent local work adds a three-section navigation (Security Intel, Red Bears, Findings), restores the existing ChatWindow inside Red Bears, and introduces research-to-lab investigations, detection comparisons and provider adapters.

## Status and evidence

“Reported live” below means the earlier development notes record a real local run; those runs were not repeated during this README-only update. “Mock-tested” means simulated responses, not successful live provider access. Source inspection confirms implementation shape, not operational success.

| Area | Current evidence and limits |
|---|---|
| Oyster Chat and navigation | A real local answer rendered in Chrome. Chat defaults open in Red Bears; history, New Chat, Search and conversation links are restored. Desktop/mobile rendering checked. A later real NDJSON request started but produced no tokens within the short check; Stop returned control. Another generation exceeded a 180-second browser wait while a different large model was active on shared Ollama; historical citation/retrieval behaviour is preserved, not newly certified for every answer. |
| Local Nemotron reranker | Implemented in the published baseline; reported live locally. It ranks evidence, not research plans. |
| Token Factory Nemotron reasoning, Tavily and Devin | Local adapters exist. Earlier notes report mocked checks, but dedicated backend adapter tests for these three were not located in the inspected test directory. No live-account success is established. |
| OpenCVE adapter and feed | Local implementation with mocked adapter/cache tests present. Missing-credential behaviour was reported checked over the local API; authenticated provider responses remain unverified. |
| Juice Shop lab | Fresh IDOR isolation/validation/retest passed: reproduced, baseline missed, improved detection after fresh-instance retest, 2 benign events with no false positive. SQLi remains implemented and historically reported live. This is demonstration evidence, not production detection accuracy. |
| “Research this CVE” | Local implementation with mocked tests; research-only API path reported exercised with providers unconfigured. No CVE currently maps to a lab scenario. |
| Findings and Devin handoff | Local investigation finding storage and preview/handoff endpoints exist. Missing-credential refusal reported checked. No live Devin session or end-to-end fix/PR workflow established. |
| Iterative deep research | Implemented with model-selected plan/search/read/finish tools, budgets, cancellation, exact-quote checks and a separate model support review. Deterministic tests pass; live Token Factory/Tavily generation and three real claim-support checks remain blocked by absent credentials. |

Fresh checks for this update: **92 frontend tests passed**, TypeScript clean, **24 standalone research tests passed** both locally and in a fresh independent installation, and **23 focused backend tests passed** (research authorization, lab boundaries/cancellation, missing telemetry, promotion gating, OpenCVE/cache, CVE handoff and store redaction). These do not replace live provider verification. Earlier full-backend totals in development notes are historical, not rerun here.

Chrome checks exercised a real local Chat response, saved-conversation deep links/history, the desktop/mobile Chat layout, missing-credential research feedback, and the standalone page with run recovery after reload. Authenticated production Supabase sessions and live hosted integrations were not exercised. Research tests use clearly identified provider fixtures; no fixture report is presented as a live investigation.

## Workflows in the local implementation

### Chat and Ask

Red Bears contains **Chat**, **Ask** and **Investigate** tabs. Chat reuses Oyster's existing streaming conversation UI, history, sources and model picker. Ask performs knowledge retrieval, optionally reranks candidates through Nemotron, then asks the answer model for a cited response. The reranking status should be checked rather than assuming every response used it; unavailable reranking can leave retrieval order unchanged.

### Security Intel

The existing Security Intel Q&A handles security identifiers and knowledge-backed questions, including CVE/CWE/CAPEC/ATT&CK/D3FEND material. The local addition is a manually refreshed **Latest intelligence** feed from OpenCVE, with vendor/product filters, deduplication, a disk cache and stale/error indicators. Scheduled refresh is implemented but disabled by default. Failed refreshes preserve the prior cache.

Feed timestamps describe OpenCVE catalog creation/update activity, not NVD publication dates. OpenCVE severity is deliberately not displayed because its live metrics shape has not been verified. Existing vulnerability-source data elsewhere in Oyster remains separate.

**Research this CVE** seeds an investigation from the identifier and summary. The exact-CVE compatibility map is empty, so this currently returns research-only, with no lab validation. Sharing a vulnerability class with a Juice Shop scenario does not establish that a CVE affects Juice Shop.

### Investigations and findings

The original **Direct lab checks** section retains this fixed sequence (distinct from the new deep-research panel):

1. **Research:** one Tavily search, retaining source URLs, snippets and retrieval timestamps.
2. **Investigate:** one Token Factory structured completion for a hypothesis, evidence, gaps and proposed next action. That proposal does not drive an iterative tool loop.
3. **Prepare lab:** provision an isolated instance for the selected implemented scenario.
4. **Validate:** run the scenario and evaluate its success criteria.
5. **Detect:** evaluate recorded telemetry against the scenario's predefined demonstration baseline.
6. **Improve and verify:** reset the instance, rerun the same scenario and evaluate its predefined improved rule. The model does not generate or deploy a new rule.

Missing provider configuration is recorded as skipped; provider failures as unavailable. Lab stages can still run when research is skipped. A stage marked `ok` means it executed: inspect its simulation/detection result to determine whether reproduction or detection succeeded. Failed lab preparation prevents validation stages from running.

Oyster's sidebar **Findings** holds saved chat findings. Investigation findings are a separate JSON-backed collection displayed within Investigate, with investigation references, sources, lab provenance and detection/retest results. They are not yet unified with the sidebar collection. Promotion now requires a reproduced simulation and reproduction retest; an operator must still review the evidence. Detection success is reported separately from reproduction.

The Devin preview shows an evidence package and destination repository. The handoff currently constructs a shorter textual summary from selected fields, rather than transmitting that entire package or all source references. It requires an explicitly allowed repository and operator action; there is no merge operation in the adapter. Persisted Devin session tracking still needs end-to-end verification: the generic record redactor also redacts keys containing `session`, including the stored session object.

### Deep research → optional validation

The new **Evidence-led investigation** panel takes a question, then runs Token Factory tool calling with Tavily retrieval. The model can plan, search, read selected sources, request follow-up evidence, or finish. Nothing forces a second search when evidence is sufficient. There is no local-inference fallback.

Each run persists actual events before/after tool calls, a source ledger (stable IDs, URLs, titles, timestamps, bounded extracted passages and available publication dates), and a report. Facts require an exact quote from an extracted page and a separate model entailment check; failed support checks become unresolved claims. Inference is labelled separately. This is review assistance, not a guarantee of truth; three live material claims still need manual checking once credentials are available.

Limits are 10 iterations, 5 searches, 4 extraction batches, 180 seconds, 1,800 output tokens per call and a conservative 120,000-token reservation budget. Research cancellation stops in-flight async calls. Reports may propose IDOR or SQLi, but never execute arbitrary targets or shell commands. An explicit operator action starts the supported isolated lab, emits stage results and cleans up owned instances. CVE-specific research cannot propose a generic lab scenario as CVE validation. Unsupported hosts remain research-only.

## Architecture and integrations

The browser calls FastAPI. Local retrieval and Ollama answer generation remain distinct from the investigation services. Integration adapters are statically registered backend modules, not a runtime plugin marketplace.

| Component | Actual role and data flow |
|---|---|
| Nemotron **reranking** | A local cross-encoder (`nvidia/llama-nemotron-rerank-1b-v2`) scores question/passage pairs and reorders retrieved evidence through `/v1/ranking`. It does not generate answers or coordinate research. |
| Nemotron **reasoning** | The new core sends the research conversation and bounded evidence to Token Factory's chat-completions endpoint with tool schemas. The original direct-lab adapter still makes a single structured-summary call. It needs an explicitly configured model ID available to the account; listing models is not proof that completions work. |
| Tavily | The new loop uses search and extraction, enforcing source exclusions for both and permitting extraction only for ledger URLs. The older direct-lab adapter uses search only and its separate extract method has no exclusion check. Walkthrough exclusions cannot remove prior model knowledge of Juice Shop. |
| Devin | Uses organization-scoped v3 session endpoints for an operator-requested investigation/fix proposal in an allowed repository. Sends the finding summary, not model weights or the raw lab telemetry. Real session creation, permissions and PR output remain unverified. |
| OpenCVE | Read-only v2 catalog adapter using bearer authentication, pagination and dedicated vendor/product routes. Sends query/filter parameters, not lab evidence. Supplies the local cached intelligence feed. |

Adapters are registered in `oyster/backend/services/integrations/registry.py`. Their common base supplies connection status and bounded connection checks; provider methods use HTTP client timeouts and provider-specific error handling. Configuration presence alone is not a connection: **Test connection** attempts a real request (model listing, minimal search, session listing or CVE listing). These checks may consume provider quota and do not certify every endpoint. Status can reflect a cached previous check.

Settings are read server-side from configuration. Account Settings → Integrations accepts allowlisted runtime overrides in process memory; they are lost on restart. Secret readback is masked, including a short prefix/suffix for longer values. Disconnect clears the runtime credential; restarting can restore an environment-provided value. Repository allowlists and search exclusions are deployment configuration, not panel overrides.

Errors are sanitized on handled paths, but redaction is best-effort and not a blanket guarantee for arbitrary text. The new research core restricts provider hosts; older integration adapters still have configurable base URLs without a strict provider-host egress boundary. Treat configuration as trusted operator input. Shared deployment needs protected secret injection and access controls.

## Juice Shop lab (local-only)

The lab uses the official OWASP Juice Shop source pinned to `v20.2.0`, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`. Provisioning checks the source revision and rejects a dirty checkout. Instances use disposable copies; a recorded patch binds the target to loopback.

Isolation uses macOS `sandbox-exec` with a self-test. Missing or failed isolation causes provisioning to refuse to run; there is no unsandboxed fallback or implemented Linux/container equivalent. The target, telemetry proxy and scoped scenario runner have separate roles. The runner sends requests through the collector; detection reads its JSONL events. Missing telemetry is inconclusive.

Implemented scenarios are **SQL injection login bypass** and **IDOR basket access** with synthetic users. XSS, authentication/session, path traversal and rate-limit scenarios remain unavailable placeholders. Baselines are deliberately weak demonstration rules. IDOR identity/ownership ground truth comes from test-harness markers and context, not trustworthy application audit logs; production detection would need application-supplied identity evidence.

Instances have reset/cleanup operations, a concurrency cap and TTL sweeps during lifecycle activity. Do not treat the TTL as an independently scheduled hard deadline. Use the Investigate cleanup control (or `DELETE /investigation/lab/instances/<instance-id>`) before shutdown. Graceful backend shutdown now cancels research and invokes lab cleanup. Provision/reset cancellation waits for its owned process before cleanup; forced process termination still cannot guarantee cleanup.

## Setup, start and stop

These scripts are for the local integrated demo. The published baseline lacks the new research and lab additions. For a core research demo without Oyster assets, use the independent commands in [public_submission/README.md](public_submission/README.md); its server runs at `http://127.0.0.1:8120`. Its exact publication files are listed in [docs/PUBLIC_SUBMISSION_MANIFEST.md](docs/PUBLIC_SUBMISSION_MANIFEST.md).

Prerequisites: Git, Python 3.11 with venv support, Node.js 22–26 (the pinned Juice Shop engine range) and npm, Ollama, and enough disk/RAM for the selected models. The lab additionally requires macOS, `sandbox-exec` and the macOS copy/tooling used by the provisioner. Check Juice Shop's pinned `package.json` engine requirements before installing it; a frontend-compatible Node version alone is insufficient. Initial setup needs network access and downloads substantial assets.

From the repository root, create `.env` only if it does not already exist, then edit it locally:

```bash
[ -f .env ] || cp .env.example .env
# Start the Ollama app, or run this in a separate terminal:
ollama serve
```

```bash
# From the repository root, with Ollama running:
scripts/setup.sh
scripts/start.sh
open http://127.0.0.1:3101
```

`setup.sh` installs Python/frontend dependencies, installs the local `public_submission` package, and downloads/registers Huihui. In the local investigation version it also calls `scripts/setup-lab.sh`; that script is absent from the published baseline. Lab setup failure is reported but does not abort the remaining stack setup. Setup does not install Oyster Dolphin weights or create a missing knowledge index.

Default service ports are frontend **3101**, backend **8101**, reranker **8110**, and existing Ollama **11434**. The local lab allocates loopback ports from **31100–31199**. All three development services now bind loopback explicitly. Auth is disabled by default in these development scripts, including the frontend flag: do not use them as a shared deployment configuration.

```bash
curl --fail http://127.0.0.1:8101/health
curl --fail http://127.0.0.1:8110/v1/health/ready
# After cleaning up any lab instances:
scripts/stop.sh
```

`start.sh` now launches detached process groups and fails if readiness is not reached. `stop.sh` checks recorded PID/start-time/process-group identity and only stops owned services, allowing graceful cleanup. Healthy pre-existing services are reused but are not adopted or stopped; this includes a reranker started before these scripts were updated. Ollama stays running. Logs normally live under `$REDBEARS_ASSETS/logs` (`backend.log`, `frontend.log`, `rerank.log`).

### External assets

Cloning Git does not provide model weights, a populated knowledge snapshot, runtime databases or lab telemetry.

| Asset | Provisioning |
|---|---|
| Knowledge snapshot | Supply an authorized existing snapshot under `$REDBEARS_ASSETS/data/knowledge_snapshot`, or follow `oyster/backend/KNOWLEDGE_BASE.md` to rebuild. Required contents include the vector index and memory database. Corpus size depends on the supplied snapshot. |
| Oyster Dolphin models | Obtain/register authorized models separately. The default answer model is `oyster-dolphin-v2`; a picker entry alone does not install it. |
| Huihui 27B | `scripts/install-huihui.sh` downloads a pinned GGUF, verifies its checksum and registers it in Ollama. Requires substantial disk and model memory; downloads remain outside Git. |
| Nemotron reranker | First startup downloads pinned weights, approximately 2.5 GB. Check readiness after the download/load. |
| Juice Shop | Local-only `scripts/setup-lab.sh` clones the pinned source and runs its dependency install/build. |

`REDBEARS_ASSETS` defaults to a `redbears-assets` directory under the current user's home. Some local services still use independent home-relative defaults: changing this variable alone does not relocate every cache, lab instance or telemetry directory. Set the applicable path overrides and inspect the remaining lab path assumptions before using a custom asset root.

### Configuration

Keep real credentials in local protected configuration, never in Git or browser-public variables. The root `.env` is sourced by the scripts as shell code. Use trusted values and shell-compatible quoting. The published `.env.example` covers the baseline; the additional integration/lab variables belong to the unpublished implementation.

All values below are placeholders: replace them before use, and leave unused provider credentials unset.

```dotenv
REDBEARS_ASSETS='<absolute-asset-directory>'
NEBIUS_API_KEY='<token-factory-api-key>'
NEMOTRON_REASONING_MODEL='<model-id-available-to-your-account>'
TAVILY_API_KEY='<tavily-api-key>'
DEVIN_API_KEY='<devin-api-key>'
DEVIN_ORG_ID='<organization-id>'
DEVIN_ALLOWED_REPOS='<explicitly-approved-repository>'
OPENCVE_API_TOKEN='<opencve-organization-token>'
```

| Configuration names | Purpose |
|---|---|
| `REDBEARS_FRONTEND_PORT`, `REDBEARS_BACKEND_PORT`, `REDBEARS_RERANK_PORT` | Development ports. |
| `OYSTER_DEFAULT_MODEL`, `OYSTER_HUIHUI_NUM_CTX`, `HUIHUI_VARIANT` | Answer-model choice/context and installer variant. |
| `NEMOTRON_RERANK_URL`, `NEMOTRON_RERANK_MODEL`, `NEMOTRON_RERANK_TIMEOUT_S`, `NEMOTRON_RERANK_CANDIDATES` | Evidence reranking endpoint and retrieval settings. |
| `NEMOTRON_RERANK_API_KEY`, `RERANK_SERVER_TOKEN`, `NVIDIA_API_KEY` | Separate local/private reranker token pair; NVIDIA credential only for the supported hosted NVIDIA path. |
| `RERANK_CACHE_DIR` | Reranker weight-cache override. |
| `NEBIUS_TOKEN_FACTORY_BASE_URL`, `NEBIUS_TIMEOUT_S` | Reasoning endpoint and timeout. |
| `TAVILY_BASE_URL`, `TAVILY_TIMEOUT_S`, `TAVILY_EXCLUDE_DOMAINS` | Research endpoint, timeout and search exclusions. |
| `DEVIN_BASE_URL`, `DEVIN_TIMEOUT_S` | Devin endpoint and timeout; allowed repositories default to empty. |
| `OPENCVE_BASE_URL`, `OPENCVE_TIMEOUT_S`, `OPENCVE_PAGE_SIZE`, `OPENCVE_CACHE_PATH`, `OPENCVE_RECENT_WINDOW_S` | Intelligence retrieval/cache settings. |
| `OPENCVE_SCHEDULED_REFRESH_ENABLED`, `OPENCVE_SCHEDULED_REFRESH_INTERVAL_S` | Optional periodic refresh, off by default. |
| `LAB_ENABLED`, `LAB_JUICE_SHOP_DIR`, `LAB_MAX_INSTANCES`, `LAB_INSTANCE_TTL_S` | Lab source and lifecycle settings; enabling does not bypass isolation checks. |
| `OYSTER_DATA_DIR`, `OYSTER_LOGS_DIR`, `OYSTER_VECTOR_DB_DIR`, `OYSTER_MEMORY_DB` | Runtime storage; `start.sh` derives these from the asset root. |
| `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_OYSTER_DISABLE_AUTH` | Browser-visible development settings. Other `NEXT_PUBLIC_*` settings are also public; never place secrets in them. |

## Remaining work and demo delivery

The Token Factory + Tavily loop is implemented but **not live-verified**. With credentials configured locally, first run the bounded catalog/tool-call/search/extraction probe and the optional cookbook smoke command documented in `public_submission/README.md`. Then run the starter question, review three material claims against their quoted sources, inspect the actual trace, approve one compatible lab proposal and verify its retest. No exact Token Factory model ID is claimed until a real generation/tool-call succeeds.

Implementation references: [Nebius deep-research cookbook](https://dev.nebius.com/cookbook/deep-research-agent-tavily), [Token Factory documentation index](https://docs.tokenfactory.nebius.com/llms.txt), and [function calling](https://docs.tokenfactory.nebius.com/ai-models-inference/function-calling). The optional cookbook wrapper preserves the project's configuration names; it remains unverified with its optional dependencies and an account. The core implements an explicit bounded tool loop, not the cookbook's entire framework.

Still open: live provider/model compatibility, three real claim-support checks, production authentication/browser sessions, unified findings, Devin preview/session persistence correctness, portable lab isolation and publication approval. The research manager is single-process; provider spend caps, shared rate limiting, HTTPS deployment and retention/backup policies remain deployment work. Local model latency depends on the shared Ollama workload.

The two-minute outline in [public_submission/README.md](public_submission/README.md#two-minute-demo) covers question → actual research decisions → source evidence → isolated validation → detection retest → report. The planned deadline is **18 October 2026, 18:30 Europe/Berlin**. No video has been recorded or submitted, and nothing has been publicly deployed.

The remote is public. Only a separately reviewed minimal package may be published; a directory inside the full repository does not hide its other files or history. The implementation commit stays local pending that decision, preserving teammate work and the existing remote history.
