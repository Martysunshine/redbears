# Investigation workflow — integrations, isolated lab, scenarios, detection

Research → Investigate → Prepare lab → Validate → Detect → Improve and verify, in the **Red Bears → Investigate**
tab. Everything below states plainly whether it was **live-verified** (a real call/process actually ran and its
output is quoted), **unit-tested only** (a mocked-transport test proves the code is right, but no live network
call was ever made), or **unimplemented**.

## 1. Integration adapters (`oyster/backend/services/integrations/`)

A shared contract (`base.py`): configuration, a real connection check, timeout/cancellation, one status
vocabulary (`not_configured` / `connected` / `unavailable`). No adapter has a code path that reports `connected`
without an actual 2xx from the provider in that same call.

| Integration | Role | Verified against | Live-verified here? |
|---|---|---|---|
| **Nemotron Reasoning** (`nemotron_reasoning.py`) | Generative chat model for research planning, evidence analysis, investigation coordination — **not** the reranker below | docs.tokenfactory.nebius.com (2026-10-18): base `https://api.tokenfactory.nebius.com/v1`, `Authorization: Bearer`, `GET /models`, `POST /chat/completions`, `response_format: json_schema` | **No** — no Nebius credential exists on this machine. Unit-tested only (mocked transport: connects, lists models, rejects an unset model id, structured-completion success/refusal/malformed-JSON paths). |
| **Tavily** (`tavily.py`) | Web research: search, extraction, source-attributed with retrieval timestamps | docs.tavily.com (2026-10-18): `POST /search`, `POST /extract`, `Authorization: Bearer tvly-...` | **No** — no Tavily key here. Unit-tested only. Juice Shop walkthroughs are excluded from every call via `TAVILY_EXCLUDE_DOMAINS` (code-enforced, not a prompt instruction) — Oyster's own prior model knowledge of Juice Shop cannot be excluded the same way; the UI/record never claims otherwise. |
| **Devin** (`devin.py`) | Investigates/proposes a fix for one verified finding, in one explicitly allowed repo | docs.devin.ai (2026-10-18): current API is **v3** (`POST /v3/organizations/{org_id}/sessions`, key prefix `cog_`); legacy v1 `apk_`/`apk_user_` keys are deprecated and **not used** | **No** — no Devin credential, org id, or allowed repo configured. `DEVIN_ALLOWED_REPOS` is empty by default, which blocks session creation regardless of credentials. Unit-tested only; **no session was created during this implementation**, per the instruction not to start one. |
| **OpenCVE** (`opencve.py`) | Read-only CVE catalog: latest/changed CVEs, vendor/product lookups, change history, for the Security Intel "Latest intelligence" feed | Live OpenAPI v2 schema fetched 2026-10-18 from `https://app.opencve.io/api/v2/schema/?format=json` (not the rendered Swagger page, which needs JS the fetch tool can't run): confirmed paths `GET /cves`, `/cves/{cve_id}`, `/cves/{cve_id}/changes`, `/vendors/{vendor_name}/cves`, `/vendors/{vendor_name}/products/{product_name}/cves`; auth `Authorization: Bearer opc_org.<id>.<secret>` (`OrganizationBearerAuth` in the schema). API v1 confirmed deprecated per docs.opencve.io. | **No** — no `OPENCVE_API_TOKEN` exists on this machine. Unit-tested only (13 tests: configured/not-configured, connection check success/401/429, vendor+product endpoint selection, page_size clamped to the schema's documented max of 100). Live-checked that the **absence** path is honest: `GET /integrations` and `GET /security-intel/feed` both correctly report `not_configured`/`stale` with no network call attempted (see §6 below). |

The existing **Nemotron reranker** (`services/rerank_service.py`, a cross-encoder) is unchanged and stays a
separate module/class from `nemotron_reasoning.py` — the settings panel and the pipeline both label them
distinctly ("reranker" vs. "reasoning") so neither is ever described as the other's role.

## 2. Integrations settings panel

Inside **Account Settings → Integrations** (operator-only), not a new nav section. Per integration: live status
badge, role, configured model (if any), masked credential shape (`tvly…yz (42 chars)`), **Test connection**
(makes the real call above) and **Disconnect**. Credentials typed into the panel are held only in this backend
process's memory (`services/integrations/credential_store.py`) — never written to disk by this panel, never
echoed back to the browser, lost on restart. This is **not** a production secret manager; see `docs/SECURITY.md`
for how a real deployment should inject these instead. Verified live: loading the panel, configuring/clearing a
value, and a real `test` call against each adapter's `is_configured()==False` path (all three correctly show
"Not configured" with no network call attempted).

## 3. Isolated Juice Shop lab (`oyster/backend/services/lab/`)

* **Pinned**: `github.com/juice-shop/juice-shop` tag `v20.2.0`, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`
  (verified against the upstream repo 2026-10-18; MIT-equivalent — actually MIT per upstream `package.json`).
  `provisioner.py` refuses to provision from a checkout whose `HEAD` doesn't match this commit, or that has local
  modifications.
* **Isolation mechanism**: macOS `sandbox-exec` (Seatbelt), applied to the Juice Shop Node process itself —
  network restricted to its own loopback port, file access restricted to its own per-instance working copy.
  **Live-verified** (`services/lab/selftest.py`, run automatically before every provision — the lab refuses to
  start if this fails): a probe process under the real profile could reach its own port, could **not** reach
  another local port, `1.1.1.1:443`, or the `169.254.169.254` metadata address, could **not** read a file outside
  its working directory or the user's `~/.zshrc`, and could write inside its own directory. No Docker socket is
  referenced anywhere in this implementation.
* **Known, documented gap closed with a recorded patch**: Juice Shop's own `server.listen(port)` call binds every
  interface, not loopback — unpatched, it would be reachable from other devices on the same network while
  running. `provisioner.py` rewrites exactly that one line in the **instance's own** `build/server.js` (never the
  pristine checkout) before first start, and records the before/after SHA-256 in the instance record. Live-
  verified: `lsof` on a running instance shows `127.0.0.1:<port> (LISTEN)`, not `*:<port>`.
* **Disposable, reset/cleanup**: each instance is its own APFS-cloned (`cp -c`) copy of the pristine checkout —
  zero extra disk until written to. `reset` wipes and re-provisions in place (fresh SQLite DB); `cleanup` stops
  the process and deletes the directory. TTL (`LAB_INSTANCE_TTL_S`, default 30 min) and a max-concurrent cap
  (`LAB_MAX_INSTANCES`, default 2) are enforced before every new provision. Resource limits: V8 heap capped via
  `NODE_OPTIONS=--max-old-space-size=512`; a CPU-seconds `ulimit` backstop; the hard TTL as the final backstop.
* **Three separated roles** (brief §4): the **target** (Juice Shop, loopback-only); the **telemetry collector**
  (`telemetry_proxy.py`, a reverse proxy — the only thing that ever talks to the target, logging every
  request/response to a JSONL file with credentials/session tokens redacted before they touch disk); the **test
  runner** (`services/scenarios/runner.py`) is only ever handed the collector's URL, enforced in code
  (`ScopedClient` raises `ScopeViolation` on any absolute/other-host request) — not a convention a model could
  ignore. All three are live-verified running together (see §4 below for a real run's output).
* **If isolation can't run**: `LAB_ENABLED` is forced off if `sandbox-exec` is missing or the self-test fails —
  the lab never falls back to an unsandboxed process. This machine (macOS) passes; a non-macOS deploy target
  would need an equivalent mechanism (e.g. Linux namespaces/seccomp or an actual container runtime) before
  `LAB_ENABLED=true` is safe there — **not implemented for other OSes**.

## 4. Scenario catalogue (`oyster/backend/services/scenarios/`)

Two implemented, four labelled `available: false` placeholders (XSS, broken auth, path traversal, rate-limit
bypass) with real field values and no `run` — visible in the catalogue, not hidden. Each scenario declares its
lab template, prerequisites, permitted target, request budget, timeout, machine-checked success criteria,
required telemetry and cleanup; `ScenarioRunner` enforces the budget/timeout/target itself, not the scenario's
own code.

Both are **live-verified**, repeatedly, against the real sandboxed lab (not mocked):

* **`sqli_login_bypass`** — targets Juice Shop's own documented teaching vulnerability (the upstream source
  tags the line `vuln-code-snippet vuln-line loginAdminChallenge`; a raw-SQL login lookup). One documented
  probe (`admin@juice-sh.op' --`) plus a wrong-password control. A real run: control → `401`; probe → `200` with
  an issued token for `admin@juice-sh.op` → **simulation: reproduced**.
* **`idor_basket_access`** — targets the documented "Basket Access" IDOR (`GET /rest/basket/:id` has no
  ownership check — confirmed by reading `build/routes/basket.js`). Two **synthetic** accounts are registered
  fresh inside the lab instance each run; User B's own token is used to fetch User A's basket by id. A real run:
  User B reading their own basket → `200`; User B reading User A's basket with their own token → `200`,
  **returns User A's basket id** → **simulation: reproduced**.

Juice Shop's own walkthroughs/solutions are excluded from the Research stage's Tavily calls (not from the
scenario code, which never reads them) — documented caveat: prior model knowledge of these well-known
challenges cannot be ruled out, independent of retrieval.

## 5. Detection validation (`oyster/backend/services/detection/`)

Rules read **real telemetry** (the proxy's own JSONL records), never a scenario's self-report. Every baseline is
explicitly marked `is_demo_baseline: true` and described as weak by construction — not presented as a credible
production rule. Benign comparison traffic (an apostrophe-containing but non-injection login; a user re-reading
their own basket) is generated and scored by the same rule to check for false positives.

Both scenarios' baseline → improved → retest were run for real, end to end, twice (direct Python call and over
the live HTTP API):

| Scenario | Baseline rule (demo config) | Baseline result | Improved rule | Improved result | False positive on benign traffic |
|---|---|---|---|---|---|
| SQLi login bypass | Alert only on the literal keyword `DROP TABLE` in the login body | **missed** (the real payload contains no such keyword) | Flag a **successful** login whose email contains a SQL comment marker / boolean operator | **detected** | **No** |
| IDOR basket access | Alert only on HTTP 403 from `/rest/basket/:id` | **missed** (the route never returns 403 for this issue — it returns 200) | Flag a successful basket read where the requester's identity (a test-harness marker, `X-RedBears-Actor`) doesn't match the basket's recorded owner | **detected** | **No** |

Missing telemetry always reports `inconclusive`, never `missed` (`evaluator.py` checks this before evaluating
any rule). "Improve and verify" resets the lab instance to a fresh state and reruns the **same** scenario,
confirming the improved rule still catches it there too (live-verified both times).

**Documented simplification for IDOR**: the improved rule's "who owns this basket" ground truth comes from the
test harness's own `X-RedBears-Actor` header, not from decoding the session JWT's own claims or an app-level
audit log — because Juice Shop (a deliberately insecure demo app) doesn't emit the latter. A production
deployment would need the application itself to log the authenticated principal; that gap is itself a real,
reportable detection-engineering finding, not swept under the rug.

## 6. Investigation pipeline + verified findings + Devin handoff

`POST /investigation/run` runs all six stages for one scenario and persists the full record
(`services/investigation/store.py`, a JSON file under `OYSTER_DATA_DIR`, outside git). A real run's stage list
(live-verified, this scenario_id = `sqli_login_bypass`):

```
research            skipped     Tavily is not configured.
investigate         skipped     Nemotron reasoning is not configured.
prepare_lab         ok          Lab instance <id> ready.
validate            ok          Simulation: reproduced.
detect              ok          Detection: missed.
improve_and_verify  ok          Retest simulation: reproduced; detection: detected.
```

An honest `skipped` status is the correct outcome for the two unconfigured integrations — the pipeline does not
substitute a fabricated research/decision-summary stage. Every write to the record store redacts dict keys
*containing* (not just equal to) `token`/`password`/`secret`/etc. — this was tested with a regression test
(`test_investigation_store.py`) after an exact-match version of the same check missed a compound key
(`bid_token`) and would have written a real session JWT to disk; confirmed fixed by grepping a real run's stored
record for the token's own content after the fix.

**Devin handoff** (`POST /investigation/findings/{id}/devin-handoff`): the evidence package `devin-preview`
shows is the exact object sent as the prompt — live-verified that with no credential configured, `devin-preview`
correctly reports `devin_configured: false`, `repo_allowed: false` (no repo in `DEVIN_ALLOWED_REPOS`), and the
handoff call itself returns HTTP 409 rather than pretending to create a session. **No Devin session was created
during this implementation** (none could be — no credential exists — and none was attempted, per instruction).

## Checks run

* Backend: `952 passed, 1 skipped` (`pytest`), including new tests for the rerank service, investigation store
  redaction, and the ones already covered above.
* Frontend: `tsc --noEmit` clean; `vitest` **90 passed** (`IntegrationsPanel` never renders a credential value,
  only reports Connected after a real test call; `InvestigationWorkflow` shows each stage's true status
  including a skipped integration, labels an unavailable scenario, and never claims a Devin handoff happened
  without the backend's own session response; `RedBearsPanel` now also covers the restored Chat tab; the new
  `SecurityIntelligencePanel.feed` tests cover the Latest intelligence feed and "Research this CVE").
* Backend: `pytest` **968 passed, 1 skipped** (13 for the OpenCVE adapter, 5 for the feed cache, 3 for
  `research_cve`, on top of everything from the first increment).
* Live, over the real running stack (`scripts/start.sh`, not a test harness): `GET /integrations`,
  `GET /investigation/scenarios`, `POST /investigation/run` for **both** scenarios, `POST /investigation/findings`
  (promote), `GET .../devin-preview`, `POST .../devin-handoff` (correctly refused), lab instance list/cleanup.
  Existing Oyster chat, streaming, citations, model selection and the Red Bears Ask tab were re-checked and
  still work unmodified.
* **Not done**: opening the Investigate tab in an actual browser (no browser automation was available here) —
  verified via its component tests and the live API calls above instead.

## 6. Security Intel: "Latest intelligence" feed + "Research this CVE"

`services/intel/opencve_feed.py` is a small, disk-cached, deduplicated mirror of OpenCVE catalog activity —
manual refresh only by default (`POST /security-intel/feed/refresh`); a scheduled background refresh exists
(`main.py`'s `_opencve_scheduled_refresh_loop`) but stays off unless `OPENCVE_SCHEDULED_REFRESH_ENABLED=true` is
set deliberately. The cache file lives under `$REDBEARS_ASSETS/data/opencve_feed_cache.json` — outside git, like
every other runtime asset.

**What it honestly can and cannot show, and why:**
* OpenCVE's v2 schema defines only `created_at`/`updated_at` on a CVE record — its own catalog timestamps, **not**
  NVD's `publishedDate`/`lastModifiedDate`, which the schema does not expose. "Newly published" and "recently
  modified" badges are derived from those two OpenCVE fields and are labelled as such everywhere they're shown
  (frontend copy, API field names) — never presented as NVD's own publication dates.
* `ApiCveDetail`'s `metrics`/`weaknesses`/`vendors` fields are untyped (`{}`) in the schema; drf-spectacular could
  not infer their internal shape, and no credential exists here to observe a real response. Rather than guess a
  field name for "severity" and risk showing a wrong number with high confidence, the feed displays **no**
  severity for OpenCVE entries and says so in the UI. CISA KEV / CVSS severity elsewhere in Security Intel comes
  from the existing, already-verified `services/knowledge/vulnerabilities/sources/` pipeline, which is untouched.
* `GET /cves` itself has no vendor/product/severity filter — only free-text `q`. A true vendor/product filter
  goes through the dedicated `/vendors/{v}/cves` and `/vendors/{v}/products/{p}/cves` endpoints instead
  (`OpenCVEAdapter.list_cves`), confirmed against the schema, not assumed.
* A failed refresh **keeps the existing cache** and sets `stale: true` with the real error — it never clears
  cached results just because the latest attempt failed (`test_opencve_feed.py::test_failed_refresh_keeps_prior_cache_and_marks_stale`).

**"Research this CVE"** (`POST /investigation/research-cve`, `services/investigation/workflow.py::research_cve`)
seeds the Research/Investigate stages from the CVE's own id/summary. It runs an actual lab scenario **only** if
`workflow.CVE_SCENARIO_COMPAT` names a compatible, implemented scenario for that **exact** CVE id — that map is
empty by default, because Juice Shop's two implemented scenarios are generic vulnerability-class demonstrations,
not tied to any real CVE. This is the brief's own constraint — "do not imply a newly published CVE affects Juice
Shop merely because both involve the same vulnerability class" — enforced structurally (a dict lookup a maintainer
must deliberately populate) rather than left to a prompt a model could ignore; `test_research_cve.py::test_matching_vulnerability_class_alone_never_enables_lab_validation`
proves this directly, by feeding a SQL-injection-themed CVE summary at an empty compat map and asserting no lab
instance is created. Every other CVE correctly returns `lab_validation: "skipped"` with the label "Research
only — no compatible lab test for this CVE."

Live-verified over the real running stack: `GET /security-intel/feed` (empty cache, `configured: false`),
`POST /security-intel/feed/refresh` (correctly reports `OpenCVE is not configured` and leaves the cache
untouched), `POST /investigation/research-cve` (returns a persisted, research-only investigation record with
Tavily's real "not configured" stage result, not a fabricated one). Unit-tested: 13 tests for the adapter, 5 for
the feed cache (dedup, modified-record wins, stale-on-failure, not-configured reason, empty-cache-not-stale),
3 for `research_cve`. Frontend: a new "Latest intelligence" section in `SecurityIntelligencePanel.tsx` (manual
refresh, vendor/product filters, stale banner, per-entry "Research this CVE"), 2 component tests.

## Startup

Same as the main [README.md](../README.md) — `scripts/start.sh` starts everything, including this workflow (no
separate service to run). The lab needs nothing extra beyond the pinned Juice Shop checkout already present
under `$REDBEARS_ASSETS/lab/juice-shop-src` (see `scripts/setup.sh`); `sandbox-exec` ships with macOS.
To use a real integration, configure its credential either via `.env` (see `.env.example`) or the
Integrations settings panel, then press **Test connection**. For OpenCVE specifically, set `OPENCVE_API_TOKEN`
then press **Refresh** on Security Intel's "Latest intelligence" card (manual by default — see §6).

## Remaining blockers (see also docs/CHECKPOINT.md)

1. No live-credentialed call has been made to Nebius Token Factory, Tavily, Devin, or OpenCVE — only
   mocked-transport unit tests cover their request/response shapes.
2. `DEVIN_ALLOWED_REPOS` is empty; a real Devin handoff needs that set deliberately, by a human, before it can
   do anything.
3. The lab isolation mechanism is macOS-specific (`sandbox-exec`); a non-macOS deployment needs an equivalent
   before enabling `LAB_ENABLED` there.
4. Only Juice Shop is wired as a lab template, and only two scenarios are implemented; XSS/auth/path-traversal/
   rate-limit remain explicitly `available: false`.
5. The IDOR detection rule's "who owns this basket" ground truth is test-harness-supplied, not derived from an
   app-level audit log Juice Shop doesn't emit — a real deployment's improved rule would need that logged first.
6. OpenCVE's `metrics`/`weaknesses`/`vendors` response shape (severity scoring source/version in particular) is
   unverified against a live response — the feed deliberately shows no severity for OpenCVE entries rather than
   guess a field name. A real token would let this be observed and, if the shape matches what's assumed, filled in.
7. `CVE_SCENARIO_COMPAT` is empty by design — no CVE currently gets lab validation from "Research this CVE"
   until a maintainer deliberately maps one, which is the correct default but means the feature is Research-only
   end to end today.
