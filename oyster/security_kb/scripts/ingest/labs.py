"""Ingest vulnerable lab source code and documentation."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from tqdm import tqdm

import sys
sys.path.insert(0, str(Path(__file__).parents[3]))
from config import CATEGORIES, LAB_REPOS
from scripts.pipeline.clean import clean
from scripts.pipeline.chunk import split_text
from scripts.pipeline.metadata import build_metadata
from scripts.pipeline.embed import upsert_chunks

log = logging.getLogger(__name__)

# Index only documentation and challenge descriptions for labs — not full app code
_DOC_EXTS   = {".md", ".txt", ".rst", ".html"}
_CODE_EXTS  = {".py", ".js", ".ts", ".java", ".php", ".rb", ".go"}
_SKIP_DIRS  = {".git", "node_modules", "__pycache__", ".github", "build", "dist", "vendor"}


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
        ext = f.suffix.lower()
        if f.is_file() and (ext in _DOC_EXTS or ext in _CODE_EXTS):
            files.append(f)
    return sorted(files)


def ingest(chunk_size: int = 1000, overlap: int = 200) -> int:
    dest_root = CATEGORIES["labs"]
    dest_root.mkdir(parents=True, exist_ok=True)
    total = 0

    for repo_name, repo_url in LAB_REPOS.items():
        dest = dest_root / repo_name
        try:
            _clone_or_pull(repo_url, dest)
        except subprocess.CalledProcessError as e:
            log.error("Failed to clone %s: %s", repo_name, e)
            continue

        files = _iter_files(dest)
        log.info("Processing %d files from %s …", len(files), repo_name)

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

            # mark code files explicitly
            is_code = fpath.suffix.lower() in _CODE_EXTS
            chunks = split_text(cleaned, chunk_size=chunk_size, overlap=overlap)
            for ck in chunks:
                meta = build_metadata(
                    source_path=fpath,
                    category="labs",
                    source_repo=repo_name,
                    chunk_index=ck.index,
                    chunk_count=len(chunks),
                    text=ck.text,
                    extra={"is_source_code": str(is_code)},
                )
                all_chunks.append(ck.text)
                all_meta.append(meta)

        n = upsert_chunks(all_chunks, all_meta, show_progress=True)
        log.info("  %s → %d chunks upserted", repo_name, n)
        total += n

    return total
