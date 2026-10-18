#!/usr/bin/env python3
"""Daily Knowledge Pack connector refresh — invoked by launchd, not by hand.

For every connector known to profiles.py, checks upstream drift via
update_check() and re-installs ONLY when status == "update-available".
Connectors the user never opted into ("not-installed") are left alone —
this script never auto-installs anything new. Per-connector failures are
caught and logged; they never abort the run.

Run directly for testing:
    cd oyster/backend && venv/bin/python3 scripts/daily_knowledge_refresh.py
"""
from __future__ import annotations

import asyncio
import sys
import time

sys.path.insert(0, ".")  # bare `import config` / `import services...` needs cwd=backend/

import log_config                                                         # noqa: E402
from services import db                                                   # noqa: E402
from services.knowledge import pack_service                               # noqa: E402
from services.knowledge.connectors import service as connectors_service   # noqa: E402


def _init_db() -> None:
    """Idempotent. Safe on the very first run (memory.db doesn't exist yet)."""
    db.apply_startup_pragmas()
    pack_service.init_db()  # -> services/knowledge/store.py: knowledge_import_jobs, pack_meta


async def _refresh_one(connector_id: str) -> dict:
    """Check, and conditionally install, ONE connector. Never raises."""
    try:
        check = connectors_service.update_check(connector_id)
    except Exception as e:  # noqa: BLE001
        log_config.error("daily_knowledge_refresh", str(e),
                          {"connector": connector_id, "stage": "update_check"})
        return {"connector": connector_id, "outcome": "check_failed", "error": str(e)}

    if not check.get("ok"):
        log_config.error("daily_knowledge_refresh", check.get("error", "update_check failed"),
                          {"connector": connector_id, "stage": "update_check"})
        return {"connector": connector_id, "outcome": "check_failed", "error": check.get("error")}

    status = check["status"]
    if status != "update-available":
        # "not-installed" -> never auto-opt-in; "current" -> nothing to do;
        # "unknown-upstream" -> can't tell, so don't guess.
        return {"connector": connector_id, "outcome": "skipped", "status": status}

    try:
        result = await connectors_service.install(connector_id)
    except Exception as e:  # noqa: BLE001
        log_config.error("daily_knowledge_refresh", str(e),
                          {"connector": connector_id, "stage": "install"})
        return {"connector": connector_id, "outcome": "install_failed", "error": str(e)}

    if not result.get("ok"):
        # install() already wrote its own "knowledge_import_failed" audit
        # record internally — just fold the outcome into our summary.
        return {"connector": connector_id, "outcome": "install_failed", "error": result.get("error")}

    return {"connector": connector_id, "outcome": "installed", "ref": result.get("ref"),
            "docs": result.get("docs"), "chunks": result.get("chunks")}


async def main() -> int:
    _init_db()
    started = time.monotonic()
    log_config.audit("daily_knowledge_refresh_started", {})

    try:
        connectors = connectors_service.list_connectors()
    except Exception as e:  # noqa: BLE001
        log_config.error("daily_knowledge_refresh", str(e), {"stage": "list_connectors"})
        log_config.audit("daily_knowledge_refresh_aborted", {"error": str(e)})
        return 1  # the run itself couldn't start — the one case worth a nonzero exit

    results = [await _refresh_one(c["id"]) for c in connectors]

    summary = {
        "connector_count": len(connectors),
        "installed": [r["connector"] for r in results if r["outcome"] == "installed"],
        "skipped_current": [r["connector"] for r in results
                             if r["outcome"] == "skipped" and r.get("status") == "current"],
        "skipped_not_installed": [r["connector"] for r in results
                                   if r["outcome"] == "skipped" and r.get("status") == "not-installed"],
        "skipped_unknown_upstream": [r["connector"] for r in results
                                      if r["outcome"] == "skipped" and r.get("status") == "unknown-upstream"],
        "failed": [{"connector": r["connector"], "error": r.get("error")} for r in results
                   if r["outcome"] in ("check_failed", "install_failed")],
        "duration_s": round(time.monotonic() - started, 1),
    }
    log_config.audit("daily_knowledge_refresh_finished", summary)
    print(f"knowledge refresh: {len(summary['installed'])} installed, "
          f"{len(summary['failed'])} failed, {len(connectors)} total ({summary['duration_s']}s)")
    return 0  # per-connector failures are logged, never fatal to the run


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
