"""Ingest AI/LLM security repos and prompt injection resources."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from tqdm import tqdm

import sys
sys.path.insert(0, str(Path(__file__).parents[3]))
from config import CATEGORIES, AI_SECURITY_REPOS
from scripts.pipeline.clean import clean
from scripts.pipeline.chunk import split_text
from scripts.pipeline.metadata import build_metadata
from scripts.pipeline.embed import upsert_chunks

log = logging.getLogger(__name__)

_TEXT_EXTS = {".md", ".txt", ".rst", ".yaml", ".yml", ".json"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".github", "dist", "build"}

# JSON prompt-injection datasets worth including
_PROMPT_INJECTION_DATA: list[str] = [
    "https://raw.githubusercontent.com/greshake/llm-security/main/docs/llm-security.md",
    "https://raw.githubusercontent.com/jthack/PIPE/main/README.md",
]


def _clone_or_pull(repo_url: str, dest: Path) -> None:
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=False, capture_output=True)
    else:
        subprocess.run(["git", "clone", "--depth=1", repo_url, str(dest)], check=True, capture_output=True)


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for f in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        if f.is_file() and f.suffix.lower() in _TEXT_EXTS:
            files.append(f)
    return sorted(files)


def _process_dir(root: Path, repo_name: str, chunk_size: int, overlap: int) -> int:
    files = _iter_files(root)
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
                category="ai_security",
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


def _fetch_and_index_url(url: str, dest_dir: Path, chunk_size: int, overlap: int) -> int:
    import requests
    try:
        r = requests.get(url, timeout=20)
        r.raise_for_status()
    except Exception as e:
        log.warning("Could not fetch %s: %s", url, e)
        return 0

    filename = url.split("/")[-1] or "resource.md"
    fpath = dest_dir / filename
    fpath.write_text(r.text, encoding="utf-8")

    cleaned = clean(r.text)
    if not cleaned:
        return 0
    chunks = split_text(cleaned, chunk_size=chunk_size, overlap=overlap)
    all_chunks = [ck.text for ck in chunks]
    all_meta = [
        build_metadata(
            source_path=fpath,
            category="ai_security",
            source_repo="fetched",
            chunk_index=ck.index,
            chunk_count=len(chunks),
            text=ck.text,
            extra={"original_url": url},
        )
        for ck in chunks
    ]
    n = upsert_chunks(all_chunks, all_meta)
    log.info("  %s → %d chunks upserted", url, n)
    return n


def ingest(chunk_size: int = 1000, overlap: int = 200) -> int:
    dest_root = CATEGORIES["ai_security"]
    dest_root.mkdir(parents=True, exist_ok=True)
    total = 0

    for repo_name, repo_url in AI_SECURITY_REPOS.items():
        dest = dest_root / repo_name
        try:
            _clone_or_pull(repo_url, dest)
        except subprocess.CalledProcessError as e:
            log.error("Failed to clone %s: %s", repo_name, e)
            continue
        total += _process_dir(dest, repo_name, chunk_size, overlap)

    # Fetch supplementary prompt injection resources
    extra_dir = dest_root / "_fetched"
    extra_dir.mkdir(exist_ok=True)
    for url in _PROMPT_INJECTION_DATA:
        total += _fetch_and_index_url(url, extra_dir, chunk_size, overlap)

    return total
