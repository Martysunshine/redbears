#!/usr/bin/env python3
"""Operator entrypoint for the vulnerability knowledge subsystem.

Deliberately NOT under ``backend/scripts/`` — that directory is treated as
separate, pre-existing user-owned work in this project and is left untouched.
Nothing here is invoked by application startup; every action is explicit.

Usage (from ``oyster/backend``, with the venv active)::

    python3 -m services.knowledge.vulnerabilities.cli sync kev
    python3 -m services.knowledge.vulnerabilities.cli sync cwe
    python3 -m services.knowledge.vulnerabilities.cli sync capec
    python3 -m services.knowledge.vulnerabilities.cli sync epss
    python3 -m services.knowledge.vulnerabilities.cli sync nvd --days 7
    python3 -m services.knowledge.vulnerabilities.cli enrich-kev
    python3 -m services.knowledge.vulnerabilities.cli backfill nvd --start 2024-01-01 --end 2024-02-01
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone

from . import store, sync


def _print(result: dict) -> None:
    print(json.dumps(result, indent=2, default=str))


async def _run_sync(source: str, days: int) -> dict:
    if source == "kev":
        return await sync.sync_kev()
    if source == "cwe":
        return await sync.sync_cwe()
    if source == "capec":
        return await sync.sync_capec()
    if source == "epss":
        return await sync.sync_epss()
    if source == "nvd":
        return await sync.sync_nvd_incremental(days=days)
    raise ValueError(f"unknown source '{source}'")


def main() -> int:
    store.init_db()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_sync = sub.add_parser("sync", help="incremental/bounded sync for one source")
    p_sync.add_argument("source", choices=["kev", "cwe", "capec", "epss", "nvd"])
    p_sync.add_argument("--days", type=int, default=7, help="nvd only: lookback window")

    sub.add_parser("enrich-kev", help="NVD exact-CVE-id enrichment for every KEV-listed CVE")

    p_backfill = sub.add_parser("backfill", help="explicit, never-automatic full historical import")
    p_backfill.add_argument("source", choices=["nvd"])
    p_backfill.add_argument("--start", required=True, help="YYYY-MM-DD")
    p_backfill.add_argument("--end", required=True, help="YYYY-MM-DD")

    args = parser.parse_args()

    if args.command == "sync":
        result = asyncio.run(_run_sync(args.source, args.days))
    elif args.command == "enrich-kev":
        result = asyncio.run(sync.enrich_kev_from_nvd())
    elif args.command == "backfill":
        start = datetime.strptime(args.start, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = datetime.strptime(args.end, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        result = asyncio.run(sync.sync_nvd_backfill(start, end))
    else:  # pragma: no cover — argparse `required=True` prevents this
        parser.error("no command given")
        return 2

    _print(result)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
