#!/usr/bin/env python3
"""Incremental residual activation statistics for matched prompt pairs."""
from __future__ import annotations

import argparse
import gc
import json
from pathlib import Path

import numpy as np
import torch

from .tunnel import peak_gib


def collect(model_dir: Path, prompts: Path, output: Path, module_glob: str = "") -> dict:
    from transformers import AutoModelForCausalLM, AutoTokenizer

    rows = json.loads(prompts.read_text())
    tok = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(model_dir, torch_dtype=torch.float32,
                                                  device_map="cpu", local_files_only=True)
    names = [n for n, _ in model.named_modules() if (not module_glob or module_glob in n) and n]
    sums = {n: {} for n in names}
    counts = {n: {} for n in names}
    handles = []

    def hook(name):
        def capture(_module, _inputs, output):
            value = output[0] if isinstance(output, tuple) else output
            value = value.detach().float().cpu()
            # Mean over batch and sequence; this keeps one hidden-size vector.
            current = value.mean(dim=tuple(range(value.ndim - 1))).numpy()
            label = active["label"]
            sums[name][label] = sums[name].get(label, 0) + current
            counts[name][label] = counts[name].get(label, 0) + 1
        return capture

    for n, module in model.named_modules():
        if n in sums:
            handles.append(module.register_forward_hook(hook(n)))
    active = rows[0]
    try:
        for row in rows:
            active = row
            ids = tok(row["prompt"], return_tensors="pt", truncation=True, max_length=96)
            with torch.inference_mode():
                model(**ids)
            del ids
            gc.collect()
            output.parent.mkdir(parents=True, exist_ok=True)
            np.savez(output, **{f"{n}__{label}": sums[n][label] / counts[n][label]
                               for n in sums for label in sums[n]})
    finally:
        for handle in handles:
            handle.remove()
        del model
        gc.collect()
    report = {"prompts": len(rows), "modules": len(names), "peak_gib": peak_gib()}
    output.with_suffix(".json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("model_dir", type=Path); ap.add_argument("prompts", type=Path); ap.add_argument("output", type=Path)
    ap.add_argument("--module-glob", default="")
    args = ap.parse_args()
    print(json.dumps(collect(args.model_dir, args.prompts, args.output, args.module_glob), indent=2))
