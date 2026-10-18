# Public submission review manifest

Status: prepared locally; **not published**. Publish these files into a separately approved repository with a clean history. Do not push the enclosing Oyster tree or its existing commits as part of this package.

The package contains only the independent research service/UI, provider clients, fixtures, configuration template and run instructions. It has no Oyster imports, models, indexes, lab telemetry, credentials, copied knowledge packs or existing Git history. The optional local lab integration remains outside this package.

## Exact file manifest

Paths below are relative to `public_submission/`. SHA-256 hashes identify the reviewed bytes.

| File | SHA-256 |
|---|---|
| `.env.example` | `2d69e0ed4eb747dbf8203fca34f5cdc2e51aceaa3aa46dcc6086ac2d6961e25f` |
| `.gitignore` | `ded825760a8817acc398185c7916b4012d9df4acb8dfe93a4bffd1e00bd8c869` |
| `README.md` | `5e4f6b3628f8a84952e500c846f6e7fba71e9e0f51e7e4aeb8da3818ca134af9` |
| `pyproject.toml` | `56d66153ebfe9137212db01f25fafdf9f994339a9e672b36ca73d03c01686b4b` |
| `redbears_research/__init__.py` | `7b90b302df953a750284818b836b8a7dc45474074d1716ff2d5edcaea68c0e33` |
| `redbears_research/api.py` | `3760cc06eb2394ff3713d4cce57afdb82bbc8a07e80e2bb933af71bb1635f53e` |
| `redbears_research/app.py` | `e70f7cbd53f99e2af056cbd0a5a5176a4ab7da995ab47697b2fe278b6c638206` |
| `redbears_research/cookbook.py` | `7415fcc2aa037d70cbfa5a2335ab24ce8378d47d03c9f8ec1d2f7fff53367fbf` |
| `redbears_research/engine.py` | `988390f7adb7b366c325d8149c5c67ed0446ebfc76f74f7713b8ce736a536c81` |
| `redbears_research/providers.py` | `6c2f5c7af255cf41495beb28e0a168eed390d5010071fc9958b77add485c17fe` |
| `redbears_research/static/app.css` | `c0f6a201a4e05768c79fbfaa93d9101f63fe04672ae0560b037c16f6ff1c11b8` |
| `redbears_research/static/app.js` | `49343b25d81f9fb2762fc7c11948c42f433b63a9d4d7cc4bb83ba1541ca9e66a` |
| `redbears_research/static/index.html` | `af5efbafeff5b27272d4975d1dc345957191bb0eecc4d3c9d54773359de13e7e` |
| `redbears_research/verify_live.py` | `48b7ea5f853fb3265857d86065ae0c9af396e3ee96753a4bd32e67c7f195226b` |
| `tests/test_research.py` | `cab90a6419dc5e262a98ea339ef0d3c8f446ab8e780ab76b80f94c8d5608b704` |

## Verification

- Fresh virtual environment installed the copied package as a wheel; the imported module resolved from that environment, not Oyster.
- 24 deterministic tests passed in that clean environment.
- Chrome loaded the standalone page, started a run, displayed missing credentials without fabricated sources/report, and restored that record after reload.
- No live Token Factory model, Tavily result, or cloud-generated report has been verified; the operator chose to continue without credentials.

## Publication decision needed

Approve the destination repository and release/licensing terms for these 15 files. A separate public repository with only this package and new history is the proposed boundary. Existing visibility on the full repository is not treated as authorization to publish additional Oyster code. No visibility changes or public deployment have been made.
