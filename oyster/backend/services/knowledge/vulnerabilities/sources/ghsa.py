"""GitHub Security Advisory Database — reviewed advisories.

https://github.com/github/advisory-database — CC-BY 4.0
(https://github.com/github/advisory-database/blob/main/LICENSE.md), verified
directly against the repo's own LICENSE.md before this connector was written.

Each advisory is published as a single OSV-schema JSON file under
``advisories/github-reviewed/<year>/<month>/<GHSA-id>/<GHSA-id>.json`` — tens
of thousands of small files, one GitHub API call each if fetched individually.
Instead this does one sparse, partial (``--filter=blob:none``) git clone of
just the ``advisories/github-reviewed`` tree (skips ``unreviewed``, which is
machine-generated and lower quality), then reads every JSON file locally —
the same technique already proven for large detection-rule repos in
``git_connector.py``, generalized here for a structured-record source rather
than a chunked/embedded pack.

The clone lands in a temp workdir (never a committed path) and is deleted
after parsing, win or lose — this module never leaves a checkout on disk.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import config

SOURCE_ID = "ghsa"
LICENCE = "cc-by-4.0"
ATTRIBUTION = "GitHub Security Advisory Database, GitHub, Inc. — CC BY 4.0."
REPO_URL = "https://github.com/github/advisory-database"
ADVISORY_SUBDIR = "advisories/github-reviewed"
_MAX_FILE_BYTES = 2 * 1024 * 1024


def _git(*args: str, cwd: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=False, shell=False)


def clone_reviewed_advisories() -> tuple[Path, str]:
    """Sparse+partial clone of just the reviewed-advisories tree. Returns
    ``(local_dir, commit_sha)``. Caller owns cleanup (``cleanup()``)."""
    workroot = Path(config.KNOWLEDGE_CONNECTOR_WORKDIR)
    workroot.mkdir(parents=True, exist_ok=True)
    dest = Path(tempfile.mkdtemp(prefix="oyster_ghsa_", dir=str(workroot)))
    ct = config.KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT
    r = _git("clone", "--depth", "1", "--filter=blob:none", "--sparse",
             "--single-branch", REPO_URL, str(dest), timeout=ct)
    if r.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(f"GHSA clone failed: {r.stderr.strip()[:500]}")
    sp = _git("sparse-checkout", "set", "--no-cone", f"/{ADVISORY_SUBDIR}", cwd=str(dest), timeout=60)
    _git("checkout", cwd=str(dest), timeout=ct)
    if sp.returncode != 0 or not (dest / ADVISORY_SUBDIR).exists():
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError("GHSA sparse-checkout did not produce the expected advisories directory")
    sha = _git("rev-parse", "HEAD", cwd=str(dest), timeout=30)
    return dest, (sha.stdout.strip() if sha.returncode == 0 else "unknown")


def iter_advisory_files(clone_dir: Path):
    yield from sorted((clone_dir / ADVISORY_SUBDIR).rglob("GHSA-*.json"))


def load_advisory(path: Path) -> dict | None:
    """Reads and JSON-parses one advisory file. Never executes anything from
    it — pure data. Returns ``None`` (never raises) on any I/O/parse error so
    one bad file can be skipped by the caller without stopping the run."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def source_url_for(ghsa_id: str) -> str:
    return f"https://github.com/advisories/{ghsa_id}"


def cleanup(clone_dir: Path) -> None:
    shutil.rmtree(clone_dir, ignore_errors=True)
