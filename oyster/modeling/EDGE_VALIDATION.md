# Tunnel validation record

Validated against the preserved Oyster Edge Qwen3.5-0.8B source and derived artifact. No model weights or private responses are included here.

| Stage | Result |
|---|---:|
| Safetensor metadata scan | 488 tensors; 0.21 GiB peak RSS |
| Incremental activation capture | 4 prompts, 378 hooked modules; 4.80 GiB peak RSS |
| Compact activation directions | 360 normalized vectors |
| One-tensor projection materialization | finite output, nonzero weight delta; 1.83 GiB peak RSS |
| Resume from checkpoint | 0 duplicate transformations; 0.20 GiB peak RSS |

Dolphin source download and transformation remain gated until a complete Edge reproduction comparison is accepted. The installed Dolphin Ollama model is unchanged.
