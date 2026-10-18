# Handoff — Martin (and whichever assistant picks this up)

Written for: Martin, picking up this repo with his own Claude/assistant session, after Pritika's branch
(research/investigation workflow + chat restoration + Security Intel feed) was merged together with Martin's
own `feat/idor-lab` work and pushed to `main`. This is current as of **2026-10-18, commit `51483722`** (or
whatever commit `git log -1` shows if this file is read later — check that first; this document is a snapshot,
not a live source of truth).

## tl;dr — what's here now

Two independent pieces of work are now on one branch (`main`), with **zero file overlap** between them:

1. **Martin's `lab/` directory** — a tiny, standalone, Docker-or-plain-Python IDOR demo target (vulnerable vs.
   patched FastAPI app), built for the "gateway" (Emre's) track. Completely separate from Oyster; no imports
   either way.
2. **Everything under `oyster/`** — Pritika's work this session: restored Oyster chat, an isolated sandboxed
   Juice Shop lab (SQLi + IDOR scenarios, different from Martin's lab — see "Two IDOR labs" below), the
   Research → Investigate → Prepare lab → Validate → Detect → Improve-and-verify pipeline, backend integration
   adapters (Nemotron reasoning, Tavily, Devin, OpenCVE), and a Security Intel "Latest intelligence" feed
   (OpenCVE or CISA KEV fallback).

**Verified together, right now, on this merged branch**: backend `981 passed, 1 skipped`; frontend `94 passed`
+ `tsc` clean; Martin's own `lab/test_lab.py` `20 passed`; Martin's `lab/selfcheck.py` — all 10 checks pass
against live local instances. Nothing in the merge touched the other side's files (confirmed by diffing before
merging: Martin's 5 commits only ever touch `lab/*`).

## Two IDOR labs — they are not the same thing, on purpose

| | `lab/` (Martin) | `oyster/backend/services/lab/` (Pritika) |
|---|---|---|
| Target | A ~130-line FastAPI app Martin wrote himself, two records, two personas | The *real*, official `juice-shop/juice-shop` (pinned `v20.2.0`) |
| Isolation | Loopback-bound process or Docker container, read-only (GET-only routes), synthetic data | macOS `sandbox-exec` (Seatbelt), with an automated isolation self-test that forces the lab off if it can't verify the sandbox |
| Purpose | A minimal, auditable, intentionally-vulnerable teaching target for the gateway/agent track | A realistic target for the full research→lab→detect pipeline, with a telemetry-collecting reverse proxy |
| Scenarios | One: IDOR, via `GET /api/records/{id}` | Two: SQLi login bypass, IDOR basket access |
| Run it | `python -m lab.run_local` → ports 18081/18082 | Provisioned on demand by `services/lab/provisioner.py`, ports 31100–31199 |

If you're extending the IDOR story, decide deliberately which of these two you're pointing an agent at —
they're both real, both tested, and not interchangeable. Nothing currently wires Martin's `lab/` app into
Pritika's `services/scenarios/`/`services/lab/` pipeline; that's open work if you want the agent's
"research → lab" handoff (`/investigation/research-cve`, `ResearchPanel`'s own scenario proposal) to also be
able to target Martin's lighter-weight app instead of/alongside Juice Shop.

## Start everything

```bash
# Oyster stack (chat, Security Intel, Red Bears — Chat/Ask/Investigate, the research panel)
cp .env.example .env            # then fill in real values — see "Credentials" below
scripts/setup.sh                # venv, npm ci, Huihui weights, Juice Shop lab checkout
scripts/start.sh                # reranker :8110, backend :8101, frontend :3101
open http://127.0.0.1:3101

# Martin's IDOR demo lab (independent of the above — run it any time)
python3 -m venv lab/.venv && lab/.venv/bin/pip install -r lab/requirements.txt
python -m lab.run_local         # vulnerable :18081, patched :18082
python -m lab.selfcheck         # read-only acceptance matrix

# The standalone, Oyster-free research package (for a judge/clean-room run)
cd public_submission && python3 -m venv .venv && . .venv/bin/activate
pip install '.[test]' && cp .env.example .env   # fill in real values
python -m uvicorn redbears_research.app:app --host 127.0.0.1 --port 8120
```

`scripts/stop.sh` stops only the three Oyster-stack services it started, by recorded PID — it won't touch
Martin's lab or anyone else's processes.

## Credentials (names only — see `.env.example`, never paste real values anywhere)

| Variable | For |
|---|---|
| `NEBIUS_API_KEY` + `NEMOTRON_REASONING_MODEL` | Token Factory — reasoning/decision summaries. **Live-verified this session**: catalog listed (28 models), real tool-calling generation confirmed with `nvidia/nemotron-3-super-120b-a12b` (a smaller `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B` connects but didn't reliably converge to `finish` — documented, not silently swapped). |
| `TAVILY_API_KEY` | Research — search + extraction. **Live-verified**: real search (5 results) and real page extraction, both through the running backend and through `public_submission`'s own `verify_live.py`. |
| `DEVIN_API_KEY` + `DEVIN_ORG_ID` + `DEVIN_ALLOWED_REPOS` | Devin handoff. **Live-tested, not usable yet**: the key authenticates but the org lacks permission — `Test connection` returns `"Devin key is valid but lacks permission for this org (403)."` No session has ever been created. |
| `OPENCVE_API_TOKEN` | Security Intel's "Latest intelligence" feed. **Not provided.** OpenCVE's hosted API genuinely requires one (verified live: unauthenticated `GET /cves` → `401`); without it the feed automatically and correctly falls back to the public CISA KEV catalog instead (**live-verified**: a real refresh returned 1748 entries). |
| `ALICE_TEST_TOKEN` / `BOB_TEST_TOKEN` | Martin's lab only — demo bearer tokens, not real secrets (dev fallbacks exist if unset). |

Set Oyster-side credentials in the root `.env` (gitignored — confirm with `git check-ignore -v .env`), or via
Account Settings → Integrations in the running app (process-memory only, lost on restart, masked on readback).
**Never put real values in any `.env.example`** — that file is tracked by git on every path in this repo.

## What's genuinely live-verified this session (not mocked) — quoted

Full pipeline, SQLi scenario, through the real running backend:
```
POST /investigation/run {scenario_id: sqli_login_bypass, ...}
research            ok   5 source(s) retrieved.
investigate         ok   Decision summary produced.
prepare_lab         ok   Lab instance c7aeb042b06d ready.
validate            ok   Simulation: reproduced.
detect              ok   Detection: missed.
improve_and_verify  ok   Retest simulation: reproduced; detection: detected.
```
Same pipeline, IDOR scenario, also fully reproduced/detected/improved in an earlier run this session
(`investigation_id: 60d6da8e21bf`).

Martin's lab, the actual IDOR attack, against live local instances:
```
curl -H "Authorization: Bearer dev-bob-token" http://127.0.0.1:18081/api/records/101
→ 200 {"id":101,"owner":"alice","label":"Alice's demo record"}      # vulnerable: full disclosure
curl -H "Authorization: Bearer dev-bob-token" http://127.0.0.1:18082/api/records/101
→ 403 {"detail":"Forbidden"}                                         # patched: denied, no body leak
```
`python -m lab.selfcheck`: all 10 checks pass (both modes × 5 cases each).

OpenCVE/KEV feed, real fetch through the running backend:
```
POST /security-intel/feed/refresh
→ {"source":"cisa_kev","stale":false,"last_error":null, ...200 real CVE entries cached...}
```
"Research this CVE" from a real KEV entry (`CVE-2026-102764`) ran real Tavily + real Nemotron and correctly
returned `lab_validation: "skipped"` — it never implies a CVE affects Juice Shop just because it's the same
vulnerability class.

## What's still unit-tested-only or unimplemented — be honest about this in the demo

- No live OpenCVE account was ever used (no token) — only the fallback path is live.
- Devin: key authenticates, org permission denied. No session, ever, on this build.
- Only two Juice Shop scenarios exist (SQLi, IDOR); XSS/auth/path-traversal/rate-limit are catalogued as
  `available: false`, not hidden.
- `workflow.CVE_SCENARIO_COMPAT` (in `services/investigation/workflow.py`) is empty by design — no CVE triggers
  a real lab run from "Research this CVE" until someone deliberately maps one.
- The deep-research agent panel (`ResearchPanel.tsx` / `public_submission/redbears_research/`) didn't reliably
  propose a compatible scenario from a free-form question in testing; the direct `/investigation/run` path is
  the one proven to complete end-to-end every time.
- The Juice Shop lab's isolation (`sandbox-exec`) is macOS-only; there's no Linux/container equivalent yet —
  unrelated to Martin's lab, which works anywhere Docker or plain Python runs.
- IDOR "ownership" ground truth in Pritika's Juice Shop scenario comes from the test harness, not an app-level
  audit log (Juice Shop doesn't emit one) — documented, not hidden. Martin's own lab doesn't have this problem:
  its `owner` field is the app's own data.

## Repo/branch state at the time of writing

- `main` was fast-forwarded to include: the hackathon UI (Security Intel / Red Bears / Findings nav, with Chat
  restored as a tab inside Red Bears alongside Ask/Investigate), the full integrations + lab + detection +
  research work, the Security Intel KEV fallback, **and** Martin's `feat/idor-lab` (already merged via PR #1
  before this handoff — that part was already on `main`).
- The repo (`Martysunshine/redbears`) is **public**. `docs/CHECKPOINT.md` and `docs/SECURITY.md` have the
  fuller licensing/attribution caveats for the third-party knowledge packs — worth reading before pointing
  anyone outside the team at this.
- Every commit pushed was scanned for secret-shaped strings before pushing; `.env` is gitignored and was
  never tracked. If you ever see a real credential land in a diff, stop and fix it the same way this session
  did once already: copy the real value out to the gitignored `.env`, then `git checkout --` the tracked file
  back to its placeholder state — never commit over it.

## Architecture quick-reference (Oyster side)

```
services/integrations/          one adapter per third party (base.py's shared contract): never reports
                                 "connected" without a real 2xx in that same call.
services/intel/opencve_feed.py  OpenCVE-backed feed cache
services/intel/kev_feed.py      CISA KEV fallback, same contract, auto-selected by
                                 routers/security_intel_feed.py when no OpenCVE token is set
services/investigation/         the 6-stage pipeline (workflow.py) + the JSON record store (store.py,
                                 redacts anything key-name-containing token/password/session/etc. before disk)
services/lab/                   Juice Shop provisioning, sandboxing, telemetry proxy
services/scenarios/             SQLi + IDOR scenario implementations + the placeholder catalogue
services/detection/              baseline/improved rule pairs + benign-traffic false-positive checks
```
See `docs/INVESTIGATION.md` for the full live-verified/unit-tested/unimplemented ledger (it's long; this file
is the short version) and the root `README.md` for the user-facing setup/architecture doc.
