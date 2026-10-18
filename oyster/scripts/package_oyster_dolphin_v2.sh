#!/usr/bin/env bash
# Assemble the Oyster Dolphin V2 transfer package (GGUF + Modelfile + checksum +
# installer) OUTSIDE Git, for out-of-band private transfer to Martin. Weights are
# NEVER committed. Idempotent: re-run to refresh the package.
#
# Usage: package_oyster_dolphin_v2.sh [GGUF_PATH] [OUT_DIR]
set -euo pipefail

GGUF_SRC="${1:-/Users/pritsss/oyster-heretic-work/oyster-dolphin-v2-q4_k_m.gguf}"
OUT="${2:-/Users/pritsss/oyster-heretic-work/martin-oyster-dolphin-v2}"
HERE="$(cd "$(dirname "$0")" && pwd)"          # oyster/scripts
REPO="$(cd "$HERE/../.." && pwd)"

[ -f "$GGUF_SRC" ] || { echo "ERROR: GGUF not found: $GGUF_SRC" >&2; exit 1; }
mkdir -p "$OUT"

# cp -c uses an APFS clone when possible (instant, no extra space); falls back to a real copy.
cp -c "$GGUF_SRC" "$OUT/oyster-dolphin-v2-q4_k_m.gguf" 2>/dev/null || cp "$GGUF_SRC" "$OUT/oyster-dolphin-v2-q4_k_m.gguf"

# Package Modelfile uses a RELATIVE FROM so `ollama create` works from the package dir.
cat > "$OUT/Modelfile" <<'EOF'
# oyster-dolphin-v2-gguf-q4 — transformed (refusal-ablated) Dolphin 3.0 Llama 3.1 8B,
# exported to GGUF Q4_K_M. ChatML template + source-derived stop tokens. Run
# `ollama create` from THIS directory.
FROM ./oyster-dolphin-v2-q4_k_m.gguf
TEMPLATE """{{ range .Messages }}<|im_start|>{{ .Role }}
{{ .Content }}<|im_end|>
{{ end }}<|im_start|>assistant
"""
PARAMETER stop "<|im_end|>"
PARAMETER stop "<|end_of_text|>"
PARAMETER stop "<|eom_id|>"
PARAMETER stop "<|eot_id|>"
PARAMETER temperature 0
PARAMETER top_p 0.9
PARAMETER num_ctx 8192
PARAMETER num_batch 64
EOF

cp "$HERE/install_oyster_dolphin_v2.sh" "$OUT/install_oyster_dolphin_v2.sh"
chmod +x "$OUT/install_oyster_dolphin_v2.sh"
cp "$REPO/oyster/docs/MARTIN_MODEL_TRANSFER.md" "$OUT/MARTIN_MODEL_TRANSFER.md" 2>/dev/null || true
cp "$REPO/oyster/modeling/configs/oyster-dolphin-v2-gguf-q4.manifest.json" "$OUT/manifest.json" 2>/dev/null || true

( cd "$OUT" && shasum -a 256 oyster-dolphin-v2-q4_k_m.gguf Modelfile install_oyster_dolphin_v2.sh manifest.json > SHA256SUMS )

echo "Package ready: $OUT"
ls -la "$OUT"
echo
echo "SHA256SUMS:"; cat "$OUT/SHA256SUMS"
echo
echo "Total size:"; du -sh "$OUT" | awk '{print $1}'
