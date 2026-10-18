"""OSV.dev — per-ecosystem bulk vulnerability export.

https://osv.dev — the aggregator's own code/API is Apache-2.0
(https://github.com/google/osv.dev/blob/master/LICENSE); the individual
records it re-publishes each carry their original source's licence, verified
per-ecosystem before this connector was written: PyPI/npm-via-GHSA/Go/OSS-Fuzz
advisories are CC-BY 4.0, RustSec/Haskell/GSD are CC0 1.0, Drupal/AlmaLinux
are MIT, Bitnami/OpenSSF-malicious-packages are Apache 2.0 — every source in
scope here is redistribution-permissive.

Bulk export, not the per-package query API: each ecosystem publishes one zip
of many individual OSV-schema JSON files at
``https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip``.
Downloaded to a temp file, extracted to a temp directory, parsed, then both
are deleted — nothing from this fetch is a committed path.

Bounded to the ecosystems the task named (npm, PyPI, Maven, Go, crates.io for
Rust, NuGet, RubyGems, Packagist for Composer, GitHub Actions) rather than
OSV's full ~40-ecosystem catalog (which includes several Linux-distro
package feeds an order of magnitude larger and less relevant to application
supply-chain defense) — a deliberate, disclosed scope limit, not silent
partial coverage.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote

import httpx

import config

SOURCE_ID = "osv"
LICENCE = "apache-2.0"
ATTRIBUTION = "Open Source Vulnerabilities (OSV.dev), Google — aggregating CC-BY 4.0 / CC0 1.0 / MIT / Apache 2.0 sourced advisories."
BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# OSV.dev's own ecosystem names (case/spacing-sensitive in the URL path).
ECOSYSTEMS = ["npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "RubyGems",
             "Packagist", "GitHub Actions"]

_MAX_ZIP_BYTES = 400 * 1024 * 1024
_MAX_MEMBER_BYTES = 2 * 1024 * 1024


def _zip_url(ecosystem: str) -> str:
    return f"{BASE_URL}/{quote(ecosystem)}/all.zip"


async def download_ecosystem_zip(ecosystem: str, dest_dir: Path, *, max_retries: int = 4) -> Path:
    """Streams the zip to a temp file with retry/backoff on transient errors."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{ecosystem.replace('/', '_')}.zip"
    url = _zip_url(ecosystem)
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT) as client:
                async with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    written = 0
                    with open(dest, "wb") as f:
                        async for chunk in resp.aiter_bytes(65536):
                            written += len(chunk)
                            if written > _MAX_ZIP_BYTES:
                                raise ValueError(f"{ecosystem} export exceeds size budget")
                            f.write(chunk)
            return dest
        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.TransportError) as e:
            last_exc = e
            dest.unlink(missing_ok=True)
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
    raise last_exc or RuntimeError(f"download of {ecosystem} failed with no captured exception")


def iter_records_from_zip(zip_path: Path):
    """Yields raw parsed dicts, one per OSV-schema JSON member. A single
    corrupt member is skipped (never raises, never stops the rest)."""
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json") or info.file_size > _MAX_MEMBER_BYTES:
                continue
            try:
                with zf.open(info) as f:
                    yield json.loads(f.read().decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError, zipfile.BadZipFile):
                continue


def cleanup(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)
