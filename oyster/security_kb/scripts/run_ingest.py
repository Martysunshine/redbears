#!/usr/bin/env python3
"""Main ingestion runner — clone repos, clean, chunk, embed, upsert."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table

# add security_kb root to path
sys.path.insert(0, str(Path(__file__).parents[1]))

from scripts.ingest import owasp, tools, labs, writeups, ai_security
from scripts.pipeline.embed import collection_stats

console = Console()
log = logging.getLogger(__name__)

SOURCES: dict[str, object] = {
    "owasp":       owasp,
    "tools":       tools,
    "labs":        labs,
    "writeups":    writeups,
    "ai_security": ai_security,
}


def run(selected: list[str], chunk_size: int, overlap: int) -> None:
    results: list[tuple[str, int, float, str]] = []

    for name in selected:
        mod = SOURCES.get(name)
        if mod is None:
            console.print(f"[red]Unknown source:[/red] {name}")
            continue

        console.rule(f"[bold cyan]{name}[/bold cyan]")
        t0 = time.perf_counter()
        try:
            count = mod.ingest(chunk_size=chunk_size, overlap=overlap)  # type: ignore[attr-defined]
            elapsed = time.perf_counter() - t0
            results.append((name, count, elapsed, "ok"))
        except Exception as e:
            elapsed = time.perf_counter() - t0
            console.print_exception()
            results.append((name, 0, elapsed, f"ERROR: {e}"))

    # ── summary table ─────────────────────────────────────────────────────────
    table = Table(title="Ingestion Summary", show_lines=True)
    table.add_column("Source",  style="cyan")
    table.add_column("Chunks",  justify="right", style="green")
    table.add_column("Time",    justify="right")
    table.add_column("Status",  style="bold")

    for name, count, elapsed, status in results:
        color = "green" if status == "ok" else "red"
        table.add_row(name, str(count), f"{elapsed:.1f}s", f"[{color}]{status}[/{color}]")

    console.print(table)

    stats = collection_stats()
    console.print(f"\n[bold]Collection total:[/bold] {stats['count']:,} documents in [cyan]{stats['name']}[/cyan]")


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="Oyster Security KB — ingestion pipeline")
    parser.add_argument(
        "sources",
        nargs="*",
        default=list(SOURCES.keys()),
        choices=list(SOURCES.keys()),
        help="Which source categories to ingest (default: all)",
    )
    parser.add_argument("--chunk-size", type=int, default=1000)
    parser.add_argument("--overlap",    type=int, default=200)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    console.print("[bold green]Oyster Security KB — ingestion starting[/bold green]")
    console.print(f"Sources: {args.sources}")
    console.print(f"Chunk size: {args.chunk_size}  Overlap: {args.overlap}\n")

    run(args.sources, args.chunk_size, args.overlap)


if __name__ == "__main__":
    main()
