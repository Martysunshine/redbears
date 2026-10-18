# Oyster Abliteration Tunnel v1

`oyster_abliterate/tunnel.py` is the memory-bounded core. It never loads a
complete state dictionary: `safe_open` reads one tensor, projection is applied
with an explicit row/column shape check, one output safetensor shard is written,
and the tensor is released. A JSON checkpoint is written after every tensor,
so an interrupted run resumes without replacing source files. Candidate
strengths remain scalar manifests until one is selected.

The current implementation is intentionally conservative: embeddings,
normalization tensors, and output heads are unchanged unless explicitly
selected. Activation collection and direction estimation must produce a
compact `.npz` direction file before `materialize` is run. Generated commands
remain text and are never executed by the tunnel.

Example metadata check:

```sh
venv-ablation/bin/python -m oyster_abliterate.tunnel metadata models/base/Qwen3.5-0.8B-Base
```

Materialization requires an activation-derived direction file and checkpoint:

```sh
venv-ablation/bin/python -m oyster_abliterate.tunnel materialize \
  models/base/Qwen3.5-0.8B-Base \
  runs/tunnel-edge-a100 \
  --directions runs/tunnel-edge/directions.npz \
  --alpha 0.5 \
  --checkpoint runs/tunnel-edge-a100/checkpoint.json
```

The tunnel refuses to infer tensor orientation from names and reports peak
resident memory in its manifest. Dolphin processing is blocked until the Edge
reproduction and a measured peak below 20 GiB are both recorded.
