#!/usr/bin/env python3
"""Streaming abliteration tunnel.

The tunnel deliberately separates activation statistics, compact candidate
estimates, and materialization.  Safetensor shards are opened read-only and
one tensor is held at a time; the output is sharded the same way.  No complete
source and transformed state dictionaries are ever constructed.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import resource
import tempfile
from pathlib import Path
from typing import Iterable

import numpy as np
from safetensors import safe_open
from safetensors.torch import save_file


def peak_gib() -> float:
    # macOS reports bytes; Linux reports KiB.
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if os.uname().sysname == "Darwin":
        return value / (1024**3)
    return value / (1024**2)


def sha256_file(path: Path, block: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while data := f.read(block):
            h.update(data)
    return h.hexdigest()


def tensor_names(source: Path) -> list[str]:
    names: list[str] = []
    for shard in _shards(source):
        with safe_open(str(shard), framework="pt", device="cpu") as sf:
            names.extend(sf.keys())
    return names


def iter_tensors(source: Path) -> Iterable[tuple[str, object, Path]]:
    for shard in _shards(source):
        with safe_open(str(shard), framework="pt", device="cpu") as sf:
            for name in sf.keys():
                yield name, sf.get_tensor(name), shard


def _shards(source: Path) -> list[Path]:
    """Return unique safetensor files, ignoring compatibility symlinks."""
    seen: set[Path] = set()
    out: list[Path] = []
    for path in sorted(source.glob("*.safetensors")):
        real = path.resolve()
        if real in seen:
            continue
        seen.add(real)
        out.append(path)
    return out


def project_tensor(tensor, direction: np.ndarray, alpha: float):
    """Remove a projection with explicit orientation/shape validation."""
    import torch

    if tensor.ndim != 2:
        return tensor
    d = torch.as_tensor(direction, dtype=tensor.dtype, device=tensor.device)
    if d.ndim != 1 or not torch.isfinite(d).all():
        raise ValueError("direction must be a finite rank-1 vector")
    d = d / torch.linalg.vector_norm(d).clamp_min(torch.finfo(d.dtype).eps)
    if tensor.shape[0] == d.numel():
        # Output/residual-writing orientation: W' = W - a r (r^T W).
        return tensor - alpha * torch.outer(d, d @ tensor)
    if tensor.shape[1] == d.numel():
        # Input orientation: W' = W - a (W r) r^T.
        return tensor - alpha * torch.outer(tensor @ d, d)
    raise ValueError(f"direction length {d.numel()} matches neither matrix shape {tuple(tensor.shape)}")


def materialize(source: Path, output: Path, directions: Path, alpha: float,
                checkpoint: Path, include: list[str] | None = None) -> dict:
    """Write one safetensor shard per source tensor and a resumable manifest."""
    import torch  # local import keeps metadata-only commands lightweight

    output.mkdir(parents=True, exist_ok=True)
    dirs = np.load(directions, allow_pickle=False)
    selected = set(include or dirs.files)
    manifest_path = output / "tunnel-manifest.json"
    state = json.loads(checkpoint.read_text()) if checkpoint.exists() else {"done": []}
    done = set(state.get("done", []))
    index_file = output / "model.safetensors.index.json"
    index: dict[str, dict] = json.loads(index_file.read_text()).get("weight_map", {}) if index_file.exists() else {}
    transformed = 0
    for name, tensor, _src_shard in iter_tensors(source):
        if name in done:
            continue
        out_name = f"{len(index):05d}-{hashlib.sha1(name.encode()).hexdigest()[:10]}.safetensors"
        target = output / out_name
        if name in selected and name in dirs:
            tensor = project_tensor(tensor, dirs[name], alpha)
            transformed += 1
        save_file({name: tensor.contiguous()}, str(target), metadata={"oyster_tensor": name})
        index[name] = {"filename": out_name, "shape": list(tensor.shape), "dtype": str(tensor.dtype)}
        done.add(name)
        checkpoint.write_text(json.dumps({"done": sorted(done), "peak_gib": peak_gib()}, indent=2))
        del tensor
        gc.collect()
    index_file.write_text(json.dumps({"weight_map": index}, indent=2))
    manifest = {"source": str(source), "alpha": alpha, "transformed_tensors": transformed,
                "tensor_count": len(index), "peak_gib": peak_gib(), "checkpoint": str(checkpoint)}
    manifest_path.write_text(json.dumps(manifest, indent=2))
    return manifest


def metadata(source: Path) -> dict:
    names = tensor_names(source)
    return {"source": str(source), "tensor_count": len(names),
            "source_hashes": {str(p): sha256_file(p) for p in _shards(source)},
            "peak_gib": peak_gib()}


def main() -> None:
    ap = argparse.ArgumentParser(prog="oyster-abliterate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("metadata"); m.add_argument("source", type=Path)
    x = sub.add_parser("materialize"); x.add_argument("source", type=Path); x.add_argument("output", type=Path)
    x.add_argument("--directions", type=Path, required=True); x.add_argument("--alpha", type=float, required=True)
    x.add_argument("--checkpoint", type=Path, required=True); x.add_argument("--include", nargs="*")
    args = ap.parse_args()
    if args.cmd == "metadata":
        print(json.dumps(metadata(args.source), indent=2))
    else:
        print(json.dumps(materialize(args.source, args.output, args.directions, args.alpha, args.checkpoint, args.include), indent=2))


if __name__ == "__main__":
    main()
