"""Start both lab modes on loopback — the primary run path (no Docker needed).

Runs the vulnerable target on 127.0.0.1:18081 and the patched target on
127.0.0.1:18082, each as its own uvicorn server in this process. Both bind
loopback only; the lab is never exposed off this machine. Ctrl-C stops both.

    python lab/run_local.py              # from the repo root
    python -m lab.run_local

Override ports with REDBEARS_VULN_PORT / REDBEARS_PATCHED_PORT if 18081/18082
are taken. This is for local development only (auth is demo-only tokens).
"""

from __future__ import annotations

import asyncio
import os

import uvicorn

try:  # works as `python -m lab.run_local` and as `python lab/run_local.py`
    from .app import create_app
except ImportError:  # pragma: no cover - direct-path invocation
    import pathlib
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from lab.app import create_app

HOST = "127.0.0.1"
VULN_PORT = int(os.environ.get("REDBEARS_VULN_PORT", "18081"))
PATCHED_PORT = int(os.environ.get("REDBEARS_PATCHED_PORT", "18082"))


async def _serve() -> None:
    servers = [
        uvicorn.Server(uvicorn.Config(create_app("vulnerable"), host=HOST, port=VULN_PORT, log_level="info")),
        uvicorn.Server(uvicorn.Config(create_app("patched"), host=HOST, port=PATCHED_PORT, log_level="info")),
    ]
    print(f"  vulnerable  ->  http://{HOST}:{VULN_PORT}   (GET /health, /api/records/{{id}})")
    print(f"  patched     ->  http://{HOST}:{PATCHED_PORT}")
    print("  loopback only. Ctrl-C to stop both.\n")
    await asyncio.gather(*(s.serve() for s in servers))


def main() -> None:
    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
