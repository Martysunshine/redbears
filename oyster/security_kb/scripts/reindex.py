#!/usr/bin/env python3
"""Wipe the vector store and re-embed all already-downloaded raw data.

Use this when you change EMBEDDING_MODEL, CHUNK_SIZE, or COLLECTION_NAME
without wanting to re-clone the full repos.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
from pathlib import Path

from rich.console import Console

sys.path.insert(0, str(Path(__file__).parents[1]))

from config import VECTOR_STORE_DIR, COLLECTION_NAME, CATEGORIES
from scripts.pipeline.clean import clean
from scripts.pipeline.chunk import split_text
from scripts.pipeline.metadata import build_metadata
from scripts.pipeline.embed import upsert_chunks, collection_stats

console = Console()
log = logging.getLogger(__name__)

_TEXT_EXTS = {".md", ".txt", ".rst", ".html", ".yaml", ".yml", ".py", ".js", ".ts", ".java", ".php"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".github", "venv", "dist", "build"}


def wipe_store() -> None:
    if VECTOR_STORE_DIR.exists():
        console.print(f"[red]Wiping[/red] {VECTOR_STORE_DIR} …")
        shutil.rmtree(VECTOR_STORE_DIR)
    VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)
    console.print("[green]Vector store reset.[/green]")


def reindex_category(category: str, chunk_size: int, overlap: int) -> int:
    root = CATEGORIES.get(category)
    if root is None or not root.exists():
        console.print(f"[yellow]Skipping {category} — directory not found[/yellow]")
        return 0

    files: list[Path] = []
    for f in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        if f.is_file() and f.suffix.lower() in _TEXT_EXTS:
            files.append(f)

    console.print(f"[cyan]{category}[/cyan]: {len(files)} files")

    all_chunks: list[str] = []
    all_meta:   list[dict] = []

    for fpath in files:
        try:
            raw = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        is_html = fpath.suffix.lower() == ".html"
        cleaned = clean(raw, is_html=is_html)
        if not cleaned:
            continue
        # derive repo name from first subdir under category root
        try:
            repo_name = fpath.relative_to(root).parts[0]
        except (IndexError, ValueError):
            repo_name = category

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
    console.print(f"  → {n:,} chunks upserted")
    return n


def main() -> None:
    logging.basicConfig(level=logging.WARNING)

    parser = argparse.ArgumentParser(description="Reindex all downloaded raw data into a fresh vector store")
    parser.add_argument("--chunk-size", type=int, default=1000)
    parser.add_argument("--overlap",    type=int, default=200)
    parser.add_argument("--no-wipe", action="store_true", help="Skip wiping; only add/update")
    parser.add_argument(
        "categories",
        nargs="*",
        default=list(CATEGORIES.keys()),
        choices=list(CATEGORIES.keys()),
    )
    args = parser.parse_args()

    if not args.no_wipe:
        wipe_store()

    total = 0
    for cat in args.categories:
        total += reindex_category(cat, args.chunk_size, args.overlap)

    stats = collection_stats()
    console.print(f"\n[bold]Done.[/bold] {total:,} chunks indexed. Collection total: {stats['count']:,}")


if __name__ == "__main__":
    main()
