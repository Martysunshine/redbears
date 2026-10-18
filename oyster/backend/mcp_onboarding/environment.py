"""Environment health checks for onboarding.

Each check returns a :class:`CheckResult` with one of three statuses so both the
installer (pre-flight) and the doctor speak the same language:

    PASS          — working
    ACTION NEEDED — a user step is required (config, install a client, etc.)
    FAIL          — a software problem (a bug or a broken environment)

Checks never print secrets and never require the backend HTTP server to be
running.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from . import core

PASS = "PASS"
ACTION = "ACTION NEEDED"
FAIL = "FAIL"


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str = ""

    def line(self) -> str:
        return f"{self.status:<13} {self.name}" + (f" — {self.detail}" if self.detail else "")


def check_os() -> CheckResult:
    name = core.os_name()
    if name in ("macos", "linux", "windows"):
        return CheckResult("Operating system", PASS, name)
    return CheckResult("Operating system", ACTION, f"unrecognized platform '{name}'")


def check_python() -> CheckResult:
    py = core.default_python()
    from pathlib import Path
    if Path(py).exists():
        return CheckResult("Python interpreter", PASS, py)
    return CheckResult("Python interpreter", ACTION,
                       "project venv not found; create backend/venv or the client will use the "
                       "system python")


def check_gateway_import() -> CheckResult:
    try:
        from mcp_gateway.core import protocol, catalogue  # noqa: F401
        return CheckResult("Gateway imports", PASS,
                           f"{len(catalogue.CATALOGUE)} tools, protocol {protocol.PROTOCOL_VERSION}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Gateway imports", FAIL, f"{type(exc).__name__}: {exc}")


def check_dependencies() -> CheckResult:
    missing = []
    for mod in ("fastapi", "starlette", "httpx", "jose", "uvicorn"):
        try:
            __import__(mod)
        except Exception:  # noqa: BLE001
            missing.append(mod)
    if missing:
        return CheckResult("Backend dependencies", FAIL, f"missing: {', '.join(missing)}")
    return CheckResult("Backend dependencies", PASS, "core packages importable")


def knowledge_counts() -> tuple[int | None, int | None]:
    """(chunk_count, enabled_pack_count) read-only, or (None, None) on failure."""
    try:
        import config
        db = str(config.MEMORY_DB)
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            chunks = con.execute("SELECT count(*) FROM knowledge_chunks").fetchone()[0]
            packs = con.execute("SELECT count(*) FROM knowledge_packs WHERE enabled=1").fetchone()[0]
            return int(chunks), int(packs)
        finally:
            con.close()
    except Exception:  # noqa: BLE001
        return None, None


def check_knowledge_db() -> CheckResult:
    try:
        import config
        from pathlib import Path
        if not Path(config.MEMORY_DB).exists():
            return CheckResult("Knowledge database", ACTION,
                               "no knowledge DB at the configured path — run Oyster's knowledge "
                               "setup or point OYSTER_MEMORY_DB at your DB")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Knowledge database", FAIL, f"config error: {exc}")
    chunks, packs = knowledge_counts()
    if chunks is None:
        return CheckResult("Knowledge database", ACTION,
                           "DB present but knowledge tables not readable (empty index?)")
    return CheckResult("Knowledge database", PASS,
                       f"{chunks:,} indexed chunks across {packs} enabled packs")


def check_configuration() -> CheckResult:
    try:
        import config
        enabled = config.MCP_GATEWAY_ENABLED
        return CheckResult("Configuration", PASS if enabled else ACTION,
                           "MCP gateway enabled" if enabled else
                           "OYSTER_MCP_ENABLED is false — set it true to use the gateway")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("Configuration", FAIL, f"config import failed: {exc}")


def preflight() -> list[CheckResult]:
    return [check_os(), check_python(), check_gateway_import(), check_dependencies(),
            check_knowledge_db(), check_configuration()]
