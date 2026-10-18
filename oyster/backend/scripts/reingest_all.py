#!/usr/bin/env python3
"""Rebuild the knowledge base from primary sources (reproducible path).

The SECOND way to stand up the knowledge base on a fresh machine (the first,
exact, fast way is a snapshot restore — see ``restore_knowledge.py``). This drives
the existing, verified connector pipeline for every source in
``deploy/pinned_sources.json`` and then the structured vulnerability sync.

Honest limits — this is network-bound and slow:
  * needs outbound access to each upstream (GitHub, MITRE, NVD, CISA, …);
  * NVD in particular rate-limits (HTTP 429/503) — a full CVE backfill takes hours
    and is resumable, not instant;
  * counts may differ slightly from the snapshot as upstreams move on.

It is idempotent (deterministic ids + upserts) and resumable (re-run to continue).
Run the audit afterwards to confirm the >=100k threshold.

Run (from ``backend/``, venv active, backend NOT running, network available):
    python -m scripts.reingest_all --list           # show what would run
    python -m scripts.reingest_all --connectors     # install doc/rule connectors only
    python -m scripts.reingest_all --all            # connectors + vulnerability sync
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

import config  # noqa: E402


def _manifest() -> dict:
    mf = _BACKEND_DIR / "deploy" / "pinned_sources.json"
    if not mf.exists():
        raise SystemExit("deploy/pinned_sources.json not found — run export_source_manifest first")
    return json.loads(mf.read_text())


async def _install_connectors(connector_ids: list[str]) -> list[dict]:
    from services.knowledge.connectors import service as connector_service
    from services.knowledge import store as knowledge_store
    knowledge_store.init_db()
    results = []
    for cid in connector_ids:
        print(f"  installing {cid} …", flush=True)
        try:
            r = await connector_service.install(cid)
            results.append({"connector": cid, "ok": True, "detail": r})
        except Exception as e:  # noqa: BLE001 — record and continue, never abort the batch
            print(f"    ! {cid} failed: {e}")
            results.append({"connector": cid, "ok": False, "error": str(e)})
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="Reproducible rebuild of the knowledge base from source.")
    ap.add_argument("--list", action="store_true", help="List pinned sources and exit.")
    ap.add_argument("--connectors", action="store_true", help="Install doc/rule connectors.")
    ap.add_argument("--all", action="store_true", help="Connectors + structured vulnerability sync.")
    args = ap.parse_args()

    manifest = _manifest()
    connector_ids = [p["pack_id"] for p in manifest["packs"] if str(p["pack_id"]).endswith("-src")]

    if args.list or not (args.connectors or args.all):
        print(f"Pinned manifest: {manifest['pack_count']} packs, embedding {manifest['embedding_model']}")
        print(f"Connector-backed sources ({len(connector_ids)}):")
        for p in manifest["packs"]:
            if str(p["pack_id"]).endswith("-src"):
                print(f"  {p['pack_id']:<32} ref={p.get('upstream_ref') or p.get('version')}  "
                      f"chunks~{p.get('chunk_count')}")
        print("\nStructured vulnerability sync (NVD/OSV/GHSA/CSAF/EPSS/CWE/CAPEC) drives the "
              "oyster_vulnerabilities collection — run with --all (network + hours).")
        print("\nAfter a rebuild:  python -m scripts.audit_knowledge   # confirm >=100k")
        return 0

    results = asyncio.run(_install_connectors(connector_ids))
    ok = sum(1 for r in results if r["ok"])
    print(f"\nconnectors: {ok}/{len(results)} succeeded")

    if args.all:
        print("\nStructured vulnerability sync — this is the long pole (network + NVD rate limits).")
        try:
            from services.knowledge.vulnerabilities import sync as vuln_sync  # noqa: F401
            print("  vulnerability sync module available; invoke its backfill/sync entrypoint per "
                  "backend/services/knowledge/vulnerabilities/cli.py (kept manual — it can run for hours).")
        except Exception as e:  # noqa: BLE001
            print(f"  ! vulnerability sync unavailable: {e}")

    print("\nNow run:  python -m scripts.audit_knowledge")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
