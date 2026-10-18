from __future__ import annotations
from mcp_server.tools._safe_env import safe_env

import re
import subprocess
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parents[3].resolve()
_BACKEND_DIR = _PROJECT_ROOT / "backend"
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"
_TIMEOUT = 60


def inspect_fastapi_routes() -> dict:
    """Extract @app.* and @router.* route declarations from main.py and server.py."""
    routes: list[dict] = []
    sources = [
        _BACKEND_DIR / "main.py",
        _BACKEND_DIR / "mcp_server" / "server.py",
    ]
    for source in sources:
        if not source.exists():
            continue
        text = source.read_text(encoding="utf-8")
        for match in re.finditer(
            r'@(?:app|router)\.(get|post|put|delete|patch)\("([^"]+)"', text
        ):
            routes.append({
                "method": match.group(1).upper(),
                "path": match.group(2),
                "source": str(source.relative_to(_PROJECT_ROOT)),
            })
    return {"routes": routes, "total": len(routes)}


def inspect_nextjs_routes() -> dict:
    """List Next.js app-router page files."""
    app_dir = _FRONTEND_DIR / "src" / "app"
    if not app_dir.exists():
        return {"error": "Next.js app directory not found", "checked": str(app_dir)}
    routes: list[dict] = []
    page_files = sorted(app_dir.rglob("page.tsx")) + sorted(app_dir.rglob("page.ts"))
    for f in page_files:
        rel = f.parent.relative_to(app_dir)
        route = "/" + str(rel).replace("\\", "/") if str(rel) != "." else "/"
        routes.append({"route": route, "file": str(f.relative_to(_PROJECT_ROOT))})
    return {"routes": routes, "total": len(routes)}


def run_frontend_build() -> dict:
    if not _FRONTEND_DIR.exists():
        return {"error": "Frontend directory not found", "path": str(_FRONTEND_DIR)}
    try:
        proc = subprocess.run(
            ["npm", "run", "build"],
            cwd=str(_FRONTEND_DIR),
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            shell=False,
            env=safe_env(),
        )
        return {
            "command": "npm run build",
            "stdout": proc.stdout[:8_000],
            "stderr": proc.stderr[:2_000],
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Build timed out after {_TIMEOUT}s"}
    except Exception as exc:
        return {"error": f"run_frontend_build failed: {exc}"}


def run_backend_import_check() -> dict:
    try:
        proc = subprocess.run(
            ["python", "-c", "import main; print('ok')"],
            cwd=str(_BACKEND_DIR),
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
            env=safe_env(),
        )
        return {
            "command": "python -c 'import main; print(ok)'",
            "stdout": proc.stdout[:2_000],
            "stderr": proc.stderr[:2_000],
            "returncode": proc.returncode,
            "success": proc.returncode == 0,
        }
    except Exception as exc:
        return {"error": f"run_backend_import_check failed: {exc}"}
