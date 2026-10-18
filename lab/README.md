# Red Bears IDOR demo lab

A tiny, disposable, **intentionally vulnerable** FastAPI target — the source of
truth for the real HTTP evidence the Red Bears agent investigates. It is a
teaching target in the spirit of OWASP Juice Shop / WebGoat / DVWA, built for
one scenario: **Broken Object Level Authorization (IDOR)**.

It runs in two modes from one codebase:

- **vulnerable** — authentication works, but the per-record ownership check is
  deliberately omitted, so any authenticated persona can read any record.
- **patched** — the same app with the ownership check restored.

The point of the demo is to show the agent finding the flaw in `vulnerable` and
confirming it is gone in `patched`.

## Safety

This is safe to run **only because** of how it is built, and it must stay that way:

- **Loopback only.** Everything binds `127.0.0.1`. Never expose it off this machine.
- **Read-only.** Only `GET` endpoints exist. There are no write/delete routes.
- **Synthetic data.** Two fake records, no secrets, nothing real to protect.
- **Token → persona.** Identity comes only from a demo bearer token. An `X-User`
  (or any other) header is never trusted as proof of identity.
- **Operator-selected mode.** `LAB_MODE` is chosen at startup. It is not an
  endpoint; a request (or the model) cannot change a running service's mode.
- Logs record method, path, persona, status, mode and a request id — **never**
  the token value.

Do not point any client at anything but this local lab.

## Quick start (no Docker needed)

```bash
# from the repo root
python -m venv lab/.venv
lab/.venv/Scripts/pip install -r lab/requirements.txt   # Windows
# lab/.venv/bin/pip install -r lab/requirements.txt      # macOS / Linux

python -m lab.run_local
```

This starts both targets, loopback only:

| Mode | URL |
|---|---|
| vulnerable | http://127.0.0.1:18081 |
| patched | http://127.0.0.1:18082 |

Readiness:

```bash
curl http://127.0.0.1:18081/health    # {"ok":true,"mode":"vulnerable"}
curl http://127.0.0.1:18082/health    # {"ok":true,"mode":"patched"}
```

Stop with Ctrl-C. The app is stateless: restarting gives identical fixtures, so
"reset" is just a relaunch (well under 60s).

## Docker (equivalent, when the daemon is up)

```bash
docker compose -f lab/docker-compose.yml up -d --build
curl http://127.0.0.1:18081/health
curl http://127.0.0.1:18082/health
docker compose -f lab/docker-compose.yml down        # cleanup
```

Published ports bind `127.0.0.1` only. The `0.0.0.0:8000` inside each container
is the container-internal listen address, not a host exposure.

## The records and the two demo identities

| Record | Owner | Demo token (dev fallback) |
|---|---|---|
| `101` | alice | `dev-alice-token` |
| `202` | bob | `dev-bob-token` |

Override the tokens with `ALICE_TEST_TOKEN` / `BOB_TEST_TOKEN` (see
[.env.example](.env.example)); unset, the dev fallbacks above apply so it runs
with no configuration.

## Expected behaviour (the acceptance matrix)

| Authenticated request | vulnerable | patched |
|---|---|---|
| bob → `202` (his own) | 200, `owner=bob` | 200, `owner=bob` |
| alice → `101` (her own) | 200, `owner=alice` | 200, `owner=alice` |
| bob → `101` (not his) | **200, `owner=alice`** | **403**, no record body |
| missing / invalid token → any | 401 | 401 |
| any persona → unknown id | 404 | 404 |

Manual check (authorized GETs against the local lab):

```bash
# vulnerable: Bob authenticated as himself reads Alice's record -> discloses it
curl -s -H "Authorization: Bearer dev-bob-token" http://127.0.0.1:18081/api/records/101
# {"id":101,"owner":"alice","label":"Alice's demo record"}

# patched: same request -> denied, nothing leaks
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer dev-bob-token" http://127.0.0.1:18082/api/records/101
# 403
```

Or run the bundled read-only self-check (needs both services up):

```bash
python -m lab.selfcheck
```

It runs the whole matrix with GET requests only, prints a pass/fail table, and
writes `lab/artifacts/last_selfcheck.json`.

## Interface for the gateway (Emre)

Config **key names** only — real values stay out of git, chat and logs:

```
VULNERABLE_URL=http://127.0.0.1:18081
PATCHED_URL=http://127.0.0.1:18082
ALICE_TEST_TOKEN=<local env, not committed>
BOB_TEST_TOKEN=<local env, not committed>
```

An authorized record read returns a stable shape:

```json
{ "id": 101, "owner": "alice", "label": "Alice's demo record" }
```

`probe_record(persona, record_id)` (the gateway) maps a persona to its demo
token and calls `GET /api/records/{id}` against the operator-selected lab URL.
The lab implements only the target; it does not implement the gateway.

## Tests

```bash
lab/.venv/Scripts/python -m pytest lab/test_lab.py -q     # Windows
# lab/.venv/bin/python -m pytest lab/test_lab.py -q         # macOS / Linux
```

No network and no LLM: the tests drive the app in-process and assert the full
matrix for both modes, the 401/404 cases, and that a patched 403 leaks no
record content.
