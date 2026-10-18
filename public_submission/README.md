# Red Bears Research

A standalone security research demo using **Nebius Token Factory for inference** and **Tavily for web search and extraction**. No Oyster imports, local model weights, knowledge snapshots or private user data are needed.

Status: implemented and deterministically tested; live provider acceptance is blocked because credentials were not supplied. No account model ID has been verified. This package never silently substitutes local inference. The macOS Juice Shop adapter lives in the separate Oyster integration and is not included here; this package runs research-only on all supported systems.

## Run locally

Use Python 3.11+ (Python 3.12+ for the optional upstream cookbook dependencies).

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[test]'
[ -f .env ] || cp .env.example .env
# Edit .env locally; never paste credentials into chat or commit this file.
python -m uvicorn redbears_research.app:app --host 127.0.0.1 --port 8120
```

Open `http://127.0.0.1:8120`. Stop with Ctrl-C. The standalone server refuses non-loopback clients and cross-origin/cross-site requests; it is not a public multi-user deployment. Use one worker. Runtime records default to the current user's `.redbears-research` directory outside the package; override with `REDBEARS_RESEARCH_DATA` if needed. Records persist source text and user questions, so choose a protected location and remove unwanted run JSON files after stopping the server.

Set `NEBIUS_API_KEY`, `TAVILY_API_KEY` and `NEMOTRON_REASONING_MODEL`. Keep the default `NEBIUS_TOKEN_FACTORY_BASE_URL` unless the client is deliberately adapted for an approved endpoint. The core client restricts provider requests to the documented Token Factory and Tavily hosts.

### Live verification (requires credentials and consumes provider quota)

```bash
python -m redbears_research.verify_live
```

This queries the account catalog, tries a bounded number of actual tool-call generations (preferring Nemotron), and checks one Tavily search and extraction. If another catalog model is needed, its exact ID is printed explicitly. Put the verified ID in `NEMOTRON_REASONING_MODEL`; the application itself does not auto-switch models. A catalog response alone does not verify generation.

The requested cookbook smoke run is provided separately and has not been run against an account:

```bash
python -m pip install '.[cookbook]'
python -m redbears_research.cookbook 'Research defensive access-control checks and cite the evidence.'
```

It follows the [Nebius cookbook](https://dev.nebius.com/cookbook/deep-research-agent-tavily) framework pattern. Existing configuration names map to the cookbook's base URL/model settings without introducing `NEBIUS_BASE_URL` or `NEBIUS_MODEL` aliases. Optional framework/dependency compatibility still needs a live smoke run. The integrated core uses a small explicit tool loop following the [Token Factory function-calling contract](https://docs.tokenfactory.nebius.com/ai-models-inference/function-calling), so budgets, source validation and persisted activity can be inspected directly.

## Research behaviour

The model chooses among plan, search, read and finish tools. It may ask for further evidence or finish early; follow-up searches are not scripted. Search/extraction results are untrusted data. The app has no shell, filesystem-reading or arbitrary-target execution tools.

Default per-run bounds: 10 iterations, 5 searches, 4 extraction batches (up to 3 pages each), 180 seconds, 1,800 output tokens per generation and a 120,000-token conservative reservation budget. Reservations use UTF-8 input bytes plus maximum output tokens before sending each request, rather than trusting a provider's post-hoc usage report. The same time/token budget covers the claim-support check. One run executes at a time, and operator cancellation stops research requests. Provider timeout is 30 seconds; failed calls are not silently retried.

The evidence ledger assigns stable IDs to URLs, retaining titles, retrieval timestamps, publication dates where supplied, and bounded passages. A factual claim must quote an extracted passage exactly, then pass a separate model entailment check against that quotation. Unsupported claims become unresolved; model review is an aid, not independent factual certification. Reports distinguish source-supported facts, agent inference and unresolved questions. Live verification still needs manual review of three selected claims.

Activity is recorded before and after actual calls. It is not reconstructed from a final answer and does not display private chain-of-thought. Search snippets are not represented as extracted pages. Exhausted budgets, cancellation, provider errors, interrupted runs and missing credentials are visible; no canned successful report is substituted. No results or telemetry are claimed from a lab in this standalone package.

## Tests and known limits

```bash
python -m pytest -q
```

Tests stub provider transport/model decisions and cover early stopping, follow-up selection, quote/entailment rejection, budgets, cancellation, missing credentials, source exclusions, persistence and local-only HTTP access. They do not prove live model compatibility or web-source truth.

Current limitations: single-process task state; bounded excerpts can omit relevant page text; the same provider performs support review; source dates may be absent; no multilingual tokenization optimization, production authentication, shared rate limiter, retention scheduler or deployment hardening. The standalone server intentionally has no lab adapter. The separate local Oyster demo supports only fixed, sandboxed Juice Shop scenarios, with harness-derived IDOR ownership and predefined detection rules.

## Two-minute demo

- **0:00–0:15:** State the defensive question and show the configured, verified Token Factory model.
- **0:15–0:45:** Start research; show actual search queries, pages read and a follow-up or evidence-sufficient stopping decision.
- **0:45–1:10:** Open three material claims and their exact supporting passages/URLs; point out inference and uncertainty.
- **1:10–1:40:** In the local Oyster integration, approve the proposed fixed Juice Shop scenario and show reproduction, baseline detection and fresh-instance retest, including benign controls.
- **1:40–2:00:** Summarize the report and limitations: known vulnerable benchmark, possible prior model knowledge, harness identity data, detection improvement is not a vulnerability fix.

Until credentials are supplied, demonstrate missing-configuration handling and the separately verified local lab; do not present a fixture or skipped research stage as a live provider run.

Publication is pending a review of this package's exact manifest and destination. Do not publish the enclosing Oyster repository/history as a shortcut to publishing these files.
