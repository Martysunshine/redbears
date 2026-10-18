#!/usr/bin/env bash
# Install the transformed (refusal-ablated) Oyster Dolphin V2 model into Ollama
# from the transfer package, with integrity checks. No weights live in Git — this
# script runs INSIDE the package directory that holds the GGUF + Modelfile +
# SHA256SUMS (see oyster/docs/MARTIN_MODEL_TRANSFER.md for how the package is built
# and transferred).
#
# Usage:  cd <package dir> && ./install_oyster_dolphin_v2.sh
# Needs:  ollama on PATH, ~5 GB free, the package's GGUF + Modelfile + SHA256SUMS.
set -euo pipefail

MODEL="oyster-dolphin-v2-gguf-q4"
GGUF="oyster-dolphin-v2-q4_k_m.gguf"
EXPECT_GGUF_SHA="61422299380cb628562411fff869d56b555e0f72257a7a37d7c0e585ca6143d3"
EXPECT_OLLAMA_DIGEST="d82c7860dff52af5ba63f2f4eda43b958ef3f309f0e2d79ca7b0782926166670"

cd "$(dirname "$0")"

command -v ollama >/dev/null 2>&1 || { echo "ERROR: ollama not found on PATH" >&2; exit 1; }
[ -f "$GGUF" ] || { echo "ERROR: $GGUF not found next to this script" >&2; exit 1; }
[ -f Modelfile ] || { echo "ERROR: Modelfile not found next to this script" >&2; exit 1; }

echo "== 1/4 verifying GGUF checksum =="
if command -v shasum >/dev/null 2>&1; then GOT="$(shasum -a 256 "$GGUF" | awk '{print $1}')";
else GOT="$(sha256sum "$GGUF" | awk '{print $1}')"; fi
if [ "$GOT" != "$EXPECT_GGUF_SHA" ]; then
  echo "ERROR: checksum mismatch!" >&2
  echo "  expected $EXPECT_GGUF_SHA" >&2
  echo "  got      $GOT" >&2
  echo "The transfer is corrupt or tampered — do NOT install. Re-transfer." >&2
  exit 1
fi
echo "   OK  $GOT"

echo "== 2/4 importing into Ollama as $MODEL =="
ollama create "$MODEL" -f Modelfile

echo "== 3/4 verifying model identity =="
ollama show "$MODEL" | sed -n '1,12p'
echo "   (expect: architecture llama, parameters 8.0B, quantization Q4_K_M)"

echo "== 4/4 verifying Ollama manifest digest =="
DIGEST="$(ollama list 2>/dev/null | awk -v m="$MODEL" '$1 ~ ("^"m":latest$")||$1==m {print $2}' | head -1)"
case "$DIGEST" in
  "${EXPECT_OLLAMA_DIGEST:0:12}"*) echo "   OK  digest $DIGEST matches ${EXPECT_OLLAMA_DIGEST:0:12}…" ;;
  *) echo "   NOTE: digest is '$DIGEST' (expected prefix ${EXPECT_OLLAMA_DIGEST:0:12}…)."
     echo "         A different digest with a matching GGUF checksum usually means a"
     echo "         different Ollama version packed the manifest; the weights are the same." ;;
esac

cat <<EOF

Done — $MODEL is installed.

Smoke test:
  ollama run $MODEL "Explain how a SYN flood works in two sentences."

Wire Oyster to it (the backend resolves the key 'oyster-dolphin-v2' to this model):
  export OYSTER_DEFAULT_MODEL=oyster-dolphin-v2    # on the box running the Oyster backend
  # then restart the backend. The frontend's DEFAULT_MODEL is already oyster-dolphin-v2.

Rollback (keep these installed; do not delete):
  oyster-dolphin-v1-q4   (previous default)   |   dolphin3  (anonymous/baseline)
  To revert: set OYSTER_DEFAULT_MODEL=oyster-dolphin-v1 and restart.
EOF
