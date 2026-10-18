"""Local file analysis adapter (Class 0 — read-only local).

Hashes, metadata, secret indicators and safe archive listing over a file that
already lives inside the project's artifact directory. Never executes uploaded
code, never leaves ``config.ARTIFACTS_DIR``. No network, no approval.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

import config
from services.media.redact import scan as scan_secrets
from .base import AdapterContext, AdapterResult

_MAX_READ = 5 * 1024 * 1024  # 5 MB read cap for text scanning


def _safe_path(raw: str) -> Path | None:
    """Resolve a path and confirm it stays within the artifacts directory."""
    root = config.ARTIFACTS_DIR.resolve()
    try:
        candidate = (root / raw).resolve() if not os.path.isabs(raw) else Path(raw).resolve()
    except Exception:
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


async def run(ctx: AdapterContext) -> AdapterResult:
    rel = ctx.parameters.get("path") or ctx.target
    path = _safe_path(rel)
    if path is None:
        return AdapterResult(
            exit_code=2,
            error_summary=f"Path '{rel}' is not a readable file inside the project artifact store.",
        )

    stat = path.stat()
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    read = 0
    head = b""
    with path.open("rb") as fh:
        while True:
            block = fh.read(65536)
            if not block:
                break
            sha256.update(block)
            md5.update(block)
            if read < _MAX_READ:
                head += block[: _MAX_READ - read]
            read += len(block)

    parsed: dict = {
        "filename": path.name,
        "size_bytes": stat.st_size,
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "modified": stat.st_mtime,
    }

    # Secret indicators (values masked by the scanner)
    try:
        text = head.decode("utf-8", errors="replace")
        indicators = scan_secrets(text)
        parsed["secret_indicators"] = indicators
    except Exception:
        parsed["secret_indicators"] = []

    # Safe archive listing (names only, never extracted / executed)
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()[:200]
            parsed["archive"] = {"type": "zip", "entry_count": len(names), "entries": names}
        except Exception as exc:  # noqa: BLE001
            parsed["archive"] = {"error": str(exc)}

    lines = [
        f"File: {path.name}",
        f"  size:   {stat.st_size} bytes",
        f"  sha256: {parsed['sha256']}",
        f"  md5:    {parsed['md5']}",
        f"  secret indicators: {len(parsed['secret_indicators'])}",
    ]
    if "archive" in parsed and "entries" in parsed["archive"]:
        lines.append(f"  archive entries: {parsed['archive']['entry_count']}")
    return AdapterResult(stdout="\n".join(lines), exit_code=0, parsed=parsed)


def version() -> str:
    return "oyster-file-analysis 1.0"
