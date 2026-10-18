# Red Bears — Oyster security research and validation

Oyster is Red Orca's existing cybersecurity copilot. Red Bears is the hackathon project building on it: help security teams research threats, reproduce attacks in isolated environments, and check whether their defences detect them before an incident.

**Development checkpoint: 18 October 2026. This is not a deployment-ready release.** This README describes both the published baseline and the team's inspected local work. This documentation-only branch adds no implementation: the simplified navigation, restored Chat tab, integration settings, investigation workflow, OpenCVE feed and Juice Shop lab remain unpublished local changes. Cloning this branch does not provide those additions or the external model/index assets.

## Existing product and hackathon scope

Oyster already provides a Next.js frontend, FastAPI backend, Ollama-backed chat, conversation history, citations, security knowledge retrieval, Security Intel Q&A and saved findings. Oyster Dolphin V2 and the older Dolphin option belong to that existing model experience; their weights are not supplied by Git.

The published Red Bears baseline adds a Huihui 27B answer-model option, local Nemotron evidence reranking, an Ask panel and development scripts. The subsequent local work adds a three-section navigation (Security Intel, Red Bears, Findings), restores the existing ChatWindow inside Red Bears, and introduces research-to-lab investigations, detection comparisons and provider adapters.

## Status and evidence

“Reported live” below means the earlier development notes record a real local run; those runs were not repeated during this README-only update. “Mock-tested” means simulated responses, not successful live provider access. Source inspection confirms implementation shape, not operational success.

| Area | Current evidence and limits |
|---|---|
| Oyster Chat, model selection, citations and Red Bears Ask | Reported live locally. Restored Chat placement is local-only; selecting a model requires its Ollama registration. |
| Local Nemotron reranker | Implemented in the published baseline; reported live locally. It ranks evidence, not research plans. |
| Token Factory Nemotron reasoning, Tavily and Devin | Local adapters exist. Earlier notes report mocked checks, but dedicated backend adapter tests for these three were not located in the inspected test directory. No live-account success is established. |
| OpenCVE adapter and feed | Local implementation with mocked adapter/cache tests present. Missing-credential behaviour was reported checked over the local API; authenticated provider responses remain unverified. |
| Juice Shop SQL injection and IDOR, telemetry and detection retest | Local implementation; earlier notes report real isolated runs for both scenarios, baseline misses and improved-rule detections, with no alerts on the included benign controls. This is limited demonstration evidence, not production detection accuracy. |
| “Research this CVE” | Local implementation with mocked tests; research-only API path reported exercised with providers unconfigured. No CVE currently maps to a lab scenario. |
| Findings and Devin handoff | Local investigation finding storage and preview/handoff endpoints exist. Missing-credential refusal reported checked. No live Devin session or end-to-end fix/PR workflow established. |
| Iterative deep research | Planned. Current orchestration is a fixed sequence with one search and one structured reasoning call, not a model-directed research loop. |

Earlier notes report backend `968 passed, 1 skipped`, frontend `90 passed`, and a clean TypeScript check. These are historical reports, not fresh certification of this branch. The Investigate UI was covered by component tests and API checks in those notes, not an actual browser walkthrough. This update reviewed code, scripts, test presence and the documentation diff; it did not run models, labs, paid integrations or the full test suite.

## Workflows in the local implementation

### Chat and Ask

Red Bears contains **Chat**, **Ask** and **Investigate** tabs. Chat reuses Oyster's existing streaming conversation UI, history, sources and model picker. Ask performs knowledge retrieval, optionally reranks candidates through Nemotron, then asks the answer model for a cited response. The reranking status should be checked rather than assuming every response used it; unavailable reranking can leave retrieval order unchanged.

### Security Intel

The existing Security Intel Q&A handles security identifiers and knowledge-backed questions, including CVE/CWE/CAPEC/ATT&CK/D3FEND material. The local addition is a manually refreshed **Latest intelligence** feed from OpenCVE, with vendor/product filters, deduplication, a disk cache and stale/error indicators. Scheduled refresh is implemented but disabled by default. Failed refreshes preserve the prior cache.

Feed timestamps describe OpenCVE catalog creation/update activity, not NVD publication dates. OpenCVE severity is deliberately not displayed because its live metrics shape has not been verified. Existing vulnerability-source data elsewhere in Oyster remains separate.

**Research this CVE** seeds an investigation from the identifier and summary. The exact-CVE compatibility map is empty, so this currently returns research-only, with no lab validation. Sharing a vulnerability class with a Juice Shop scenario does not establish that a CVE affects Juice Shop.

### Investigations and findings

The current sequence is:

1. **Research:** one Tavily search, retaining source URLs, snippets and retrieval timestamps.
2. **Investigate:** one Token Factory structured completion for a hypothesis, evidence, gaps and proposed next action. That proposal does not drive an iterative tool loop.
3. **Prepare lab:** provision an isolated instance for the selected implemented scenario.
4. **Validate:** run the scenario and evaluate its success criteria.
5. **Detect:** evaluate recorded telemetry against the scenario's predefined demonstration baseline.
6. **Improve and verify:** reset the instance, rerun the same scenario and evaluate its predefined improved rule. The model does not generate or deploy a new rule.

Missing provider configuration is recorded as skipped; provider failures as unavailable. Lab stages can still run when research is skipped. A stage marked `ok` means it executed: inspect its simulation/detection result to determine whether reproduction or detection succeeded. Failed lab preparation prevents validation stages from running.

Oyster's sidebar **Findings** holds saved chat findings. Investigation findings are a separate JSON-backed collection displayed within Investigate, with investigation references, sources, lab provenance and detection/retest results. They are not yet unified with the sidebar collection. The promotion endpoint checks that the investigation exists but does not enforce a successful reproduction; an operator must review evidence before describing a finding as verified.

The Devin preview shows an evidence package and destination repository. The handoff currently constructs a shorter textual summary from selected fields, rather than transmitting that entire package or all source references. It requires an explicitly allowed repository and operator action; there is no merge operation in the adapter. Persisted Devin session tracking still needs end-to-end verification: the generic record redactor also redacts keys containing `session`, including the stored session object.

## Architecture and integrations

The browser calls FastAPI. Local retrieval and Ollama answer generation remain distinct from the investigation services. Integration adapters are statically registered backend modules, not a runtime plugin marketplace.

| Component | Actual role and data flow |
|---|---|
| Nemotron **reranking** | A local cross-encoder (`nvidia/llama-nemotron-rerank-1b-v2`) scores question/passage pairs and reorders retrieved evidence through `/v1/ranking`. It does not generate answers or coordinate research. |
| Nemotron **reasoning** | The local adapter sends scenario/CVE context and retrieved snippets to Nebius Token Factory's OpenAI-compatible chat-completions endpoint, requesting structured decision-summary JSON. It needs an explicitly configured model ID available to the account; listing models is not proof that completions work. |
| Tavily | Search and extraction adapter. The current workflow uses search only. Search merges the configured excluded-domain list; extraction does not currently enforce that list itself. Walkthrough exclusions cannot remove prior model knowledge of Juice Shop. |
| Devin | Uses organization-scoped v3 session endpoints for an operator-requested investigation/fix proposal in an allowed repository. Sends the finding summary, not model weights or the raw lab telemetry. Real session creation, permissions and PR output remain unverified. |
| OpenCVE | Read-only v2 catalog adapter using bearer authentication, pagination and dedicated vendor/product routes. Sends query/filter parameters, not lab evidence. Supplies the local cached intelligence feed. |

Adapters are registered in `oyster/backend/services/integrations/registry.py`. Their common base supplies connection status and bounded connection checks; provider methods use HTTP client timeouts and provider-specific error handling. Configuration presence alone is not a connection: **Test connection** attempts a real request (model listing, minimal search, session listing or CVE listing). These checks may consume provider quota and do not certify every endpoint. Status can reflect a cached previous check.

Settings are read server-side from configuration. Account Settings → Integrations accepts allowlisted runtime overrides in process memory; they are lost on restart. Secret readback is masked, including a short prefix/suffix for longer values. Disconnect clears the runtime credential; restarting can restore an environment-provided value. Repository allowlists and search exclusions are deployment configuration, not panel overrides.

Errors are sanitized on handled paths, but redaction is best-effort and not a blanket guarantee for arbitrary text. Provider base URLs are configurable; this is not a strict provider-host egress boundary. Treat configuration as trusted operator input. Shared deployment needs protected secret injection and access controls.

## Juice Shop lab (local-only)

The lab uses the official OWASP Juice Shop source pinned to `v20.2.0`, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`. Provisioning checks the source revision and rejects a dirty checkout. Instances use disposable copies; a recorded patch binds the target to loopback.

Isolation uses macOS `sandbox-exec` with a self-test. Missing or failed isolation causes provisioning to refuse to run; there is no unsandboxed fallback or implemented Linux/container equivalent. The target, telemetry proxy and scoped scenario runner have separate roles. The runner sends requests through the collector; detection reads its JSONL events. Missing telemetry is inconclusive.

Implemented scenarios are **SQL injection login bypass** and **IDOR basket access** with synthetic users. XSS, authentication/session, path traversal and rate-limit scenarios remain unavailable placeholders. Baselines are deliberately weak demonstration rules. IDOR identity/ownership ground truth comes from test-harness markers and context, not trustworthy application audit logs; production detection would need application-supplied identity evidence.

Instances have reset/cleanup operations, a concurrency cap and TTL sweeps during lifecycle activity. Do not treat the TTL as an independently scheduled hard deadline. Use the Investigate cleanup control (or `DELETE /investigation/lab/instances/<instance-id>`) before shutdown. A cleanup-all helper exists, but no shutdown hook calling it was found in the inspected backend entry point; stopping the stack is not guaranteed to clean up lab processes.

## Setup, start and stop

These scripts are for local development. The published baseline can run Chat/Ask with the required assets; the local-only features described above require a separately reviewed implementation update first. No command here downloads those unpublished changes.

Prerequisites: Git, Python 3.11 with venv support, Node.js/npm compatible with the frontend and the pinned Juice Shop release, Ollama, and enough disk/RAM for the selected models. The lab additionally requires macOS, `sandbox-exec` and the macOS copy/tooling used by the provisioner. Check Juice Shop's pinned `package.json` engine requirements before installing it; a frontend-compatible Node version alone is insufficient. Initial setup needs network access and downloads substantial assets.

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

`setup.sh` installs Python/frontend dependencies and downloads/registers Huihui. In the local investigation version it also calls `scripts/setup-lab.sh`; that script is absent from the published baseline. Lab setup failure is reported but does not abort the remaining stack setup. Setup does not install Oyster Dolphin weights or create a missing knowledge index.

Default service ports are frontend **3101**, backend **8101**, reranker **8110**, and existing Ollama **11434**. The local lab allocates loopback ports from **31100–31199**. Backend and reranker startup explicitly bind loopback; the frontend command does not explicitly bind loopback. Auth is disabled by default in these development scripts, including the frontend flag: do not use them as a shared deployment configuration.

```bash
curl --fail http://127.0.0.1:8101/health
curl --fail http://127.0.0.1:8110/v1/health/ready
# After cleaning up any lab instances:
scripts/stop.sh
```

`start.sh` prints URLs after its wait loop even if readiness was never reached; verify health and logs. `stop.sh` kills listeners on the three configured service ports without checking process ownership. Ensure those ports belong to this stack first. It leaves Ollama running. Logs normally live under `$REDBEARS_ASSETS/logs` (`backend.log`, `frontend.log`, `rerank.log`).

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

## Remaining work and next research workflow

The next phase is a genuine **Token Factory + Tavily deep-research loop**: primary inference on Token Factory, web retrieval through Tavily, model-directed planning/search/extraction/follow-up/stopping, an evidence ledger with claim-supporting citations, and a visible trace of actual tool calls. Then connect one authorized Juice Shop validation and detection retest to the researched evidence. This is planned work, not a description of today's fixed pipeline.

Planned implementation references are the [Nebius deep-research cookbook](https://dev.nebius.com/cookbook/deep-research-agent-tavily) and [Token Factory documentation index](https://docs.tokenfactory.nebius.com/llms.txt). Provider/model availability and API behaviour must be checked against current documentation and live authorized accounts during that phase.

Other blockers are live-provider verification, complete adapter regression coverage, browser validation, unified findings, enforceable finding-verification criteria, Devin preview/session persistence correctness, broader scenario coverage and portable lab isolation. Shared deployment also needs verified authentication/authorization, HTTPS, spend controls, durable multi-worker limits, protected secrets, retention/backup policy and a production bundle review.

A minimal public runnable submission still needs separate ownership, licensing and publication review. This README-only update does not authorize publication of additional proprietary Oyster code, knowledge assets or runtime data. The planned two-minute demo deadline is **18 October 2026, 18:30 Europe/Berlin**.
