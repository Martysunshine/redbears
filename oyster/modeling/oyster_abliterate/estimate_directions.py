#!/usr/bin/env python3
"""Derive compact row/column directions from a reference transformation.

This is a validation utility for an already available Edge source/derived
pair. It streams corresponding tensors and writes only one normalized vector
per selected matrix to NPZ; it never retains either model in memory.
"""
from __future__ import annotations

import argparse
import gc
import json
from pathlib import Path

import numpy as np
import torch
from safetensors import safe_open

from .tunnel import _shards, peak_gib


def load_index(root: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for shard in _shards(root):
        with safe_open(str(shard), framework="pt", device="cpu") as sf:
            for name in sf.keys():
                out[name] = shard
    return out


def run(base: Path, derived: Path, output: Path) -> dict:
    base_i, derived_i = load_index(base), load_index(derived)
    vectors: dict[str, np.ndarray] = {}
    compared = 0
    for name, bpath in base_i.items():
        if name not in derived_i:
            continue
        with safe_open(str(bpath), framework="pt", device="cpu") as bf, safe_open(str(derived_i[name]), framework="pt", device="cpu") as df:
            b, d = bf.get_tensor(name), df.get_tensor(name)
        if b.ndim != 2 or b.shape != d.shape or not torch.is_floating_point(b):
            del b, d
            continue
        delta = d - b
        # The dominant output-space direction is a compact approximation of
        # the observed change; orientation is recovered by project_tensor.
        row = delta.float().mean(dim=1)
        col = delta.float().mean(dim=0)
        v = row if row.norm() >= col.norm() else col
        if float(v.norm()) > 0 and torch.isfinite(v).all():
            vectors[name] = (v / v.norm()).numpy().astype(np.float32)
            compared += 1
        del b, d, delta, row, col, v
        gc.collect()
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez(output, **vectors)
    report = {"base": str(base), "derived": str(derived), "directions": len(vectors),
              "compared": compared, "peak_gib": peak_gib()}
    output.with_suffix(".json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("base", type=Path); ap.add_argument("derived", type=Path); ap.add_argument("output", type=Path)
    print(json.dumps(run(**vars(ap.parse_args())), indent=2))
