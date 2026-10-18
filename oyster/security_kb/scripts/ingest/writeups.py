"""Ingest public security writeups — local markdown files + curated repos."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import requests
from tqdm import tqdm

import sys
sys.path.insert(0, str(Path(__file__).parents[3]))
from config import CATEGORIES
from scripts.pipeline.clean import clean
from scripts.pipeline.chunk import split_text
from scripts.pipeline.metadata import build_metadata
from scripts.pipeline.embed import upsert_chunks

log = logging.getLogger(__name__)

_TEXT_EXTS = {".md", ".txt", ".rst", ".html"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__"}

# Curated writeup repos — small, high-signal
_WRITEUP_REPOS: dict[str, str] = {
    "hacktricks":          "https://github.com/HackTricks-wiki/hacktricks.git",
    "pentestbook":         "https://github.com/six2dez/pentest-book.git",
    "bugbounty-cheatsheet":"https://github.com/EdOverflow/bugbounty-cheatsheet.git",
}


def _clone_or_pull(repo_url: str, dest: Path) -> None:
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=False, capture_output=True)
    else:
        subprocess.run(["git", "clone", "--depth=1", repo_url, str(dest)], check=True, capture_output=True)


def _iter_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for f in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        if f.is_file() and f.suffix.lower() in _TEXT_EXTS:
            files.append(f)
    return sorted(files)


def _process_dir(root: Path, repo_name: str, chunk_size: int, overlap: int) -> int:
    files = _iter_text_files(root)
    all_chunks: list[str] = []
    all_meta:   list[dict] = []

    for fpath in tqdm(files, desc=repo_name, unit="file", leave=False):
        try:
            raw = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        is_html = fpath.suffix.lower() == ".html"
        cleaned = clean(raw, is_html=is_html)
        if not cleaned:
            continue
        chunks = split_text(cleaned, chunk_size=chunk_size, overlap=overlap)
        for ck in chunks:
            meta = build_metadata(
                source_path=fpath,
                category="writeups",
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


def ingest_local_writeups(writeup_dir: Path, chunk_size: int = 1000, overlap: int = 200) -> int:
    """Index any .md / .txt writeups you've saved locally in the writeups/ dir."""
    if not writeup_dir.exists():
        return 0
    return _process_dir(writeup_dir, "local_writeups", chunk_size, overlap)


def ingest(chunk_size: int = 1000, overlap: int = 200) -> int:
    dest_root = CATEGORIES["writeups"]
    dest_root.mkdir(parents=True, exist_ok=True)
    total = 0

    for repo_name, repo_url in _WRITEUP_REPOS.items():
        dest = dest_root / repo_name
        try:
            _clone_or_pull(repo_url, dest)
        except subprocess.CalledProcessError as e:
            log.error("Failed to clone %s: %s", repo_name, e)
            continue
        total += _process_dir(dest, repo_name, chunk_size, overlap)

    # Also index any writeups you've dropped manually
    total += ingest_local_writeups(dest_root / "local", chunk_size, overlap)

    return total
