"""Ingest security tool documentation and README content."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from tqdm import tqdm

import sys
sys.path.insert(0, str(Path(__file__).parents[3]))
from config import CATEGORIES, TOOL_REPOS, PAYLOAD_REPOS
from scripts.pipeline.clean import clean
from scripts.pipeline.chunk import split_text
from scripts.pipeline.metadata import build_metadata
from scripts.pipeline.embed import upsert_chunks

log = logging.getLogger(__name__)

_TEXT_EXTS = {".md", ".txt", ".rst", ".yaml", ".yml"}
_SKIP_DIRS  = {"node_modules", ".git", "__pycache__", ".github", "vendor", "test", "tests"}

# For large repos (SecLists, nuclei-templates) only index top-level + docs/
_SHALLOW_REPOS = {"nuclei-templates", "SecLists"}


def _clone_or_pull(repo_url: str, dest: Path) -> None:
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=False, capture_output=True)
    else:
        subprocess.run(["git", "clone", "--depth=1", repo_url, str(dest)], check=True, capture_output=True)


def _iter_files(root: Path, repo_name: str) -> list[Path]:
    files: list[Path] = []
    shallow = repo_name in _SHALLOW_REPOS
    for f in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        # for huge repos, only index docs/ and root-level files
        if shallow:
            rel = f.relative_to(root)
            depth = len(rel.parts)
            if depth > 2 and "doc" not in str(rel).lower():
                continue
        if f.is_file() and f.suffix.lower() in _TEXT_EXTS:
            files.append(f)
    return sorted(files)


def _process_repo(repo_name: str, dest: Path, category: str, chunk_size: int, overlap: int) -> int:
    files = _iter_files(dest, repo_name)
    all_chunks: list[str] = []
    all_meta:   list[dict] = []

    for fpath in tqdm(files, desc=repo_name, unit="file", leave=False):
        try:
            raw = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        cleaned = clean(raw)
        if not cleaned:
            continue
        chunks = split_text(cleaned, chunk_size=chunk_size, overlap=overlap)
        for ck in chunks:
            meta = build_metadata(
                source_path=fpath,
                category=category,
                source_repo=repo_name,
                chunk_index=ck.index,
                chunk_count=len(chunks),
                text=ck.text,
            )
            all_chunks.append(ck.text)
            all_meta.append(meta)

    n = upsert_chunks(all_chunks, all_meta, show_progress=True)
    log.info("  %s → %d chunks upserted", repo_name, n)
    return n


def ingest(chunk_size: int = 1000, overlap: int = 200) -> int:
    dest_root = CATEGORIES["tools"]
    dest_root.mkdir(parents=True, exist_ok=True)
    total = 0

    all_repos = {**TOOL_REPOS, **PAYLOAD_REPOS}

    for repo_name, repo_url in all_repos.items():
        dest = dest_root / repo_name
        try:
            _clone_or_pull(repo_url, dest)
        except subprocess.CalledProcessError as e:
            log.error("Failed to clone %s: %s", repo_name, e)
            continue
        total += _process_repo(repo_name, dest, "tools", chunk_size, overlap)

    return total
