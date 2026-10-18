#!/usr/bin/env python3
"""Turn matched activation means into normalized, compact directions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import numpy as np


def run(stats: Path, output: Path, allowed: str = "allowed", refused: str = "refusal_like") -> dict:
    z = np.load(stats, allow_pickle=False)
    out: dict[str, np.ndarray] = {}
    for key in z.files:
        if not key.endswith("__" + allowed):
            continue
        prefix = key[: -len(allowed) - 2]
        other = prefix + "__" + refused
        if other not in z:
            continue
        d = z[key].astype(np.float32) - z[other].astype(np.float32)
        norm = float(np.linalg.norm(d))
        if norm > 0 and np.isfinite(norm):
            out[prefix] = d / norm
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez(output, **out)
    report = {"stats": str(stats), "directions": len(out), "allowed": allowed, "refused": refused}
    output.with_suffix(".json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("stats", type=Path); ap.add_argument("output", type=Path)
    print(json.dumps(run(**vars(ap.parse_args())), indent=2))
