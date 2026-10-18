#!/usr/bin/env bash
# Download the pinned Huihui GGUF (resumable), verify its SHA-256 against the value recorded
# from Hugging Face, and register it with Ollama as a separately named model.
# Existing Oyster models are untouched. Override HUIHUI_VARIANT to pick another file.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
REPO="huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF"
REV="1c69098e9c32db6dc06fc48f1d6cc75ad07da89e"
VARIANT="${HUIHUI_VARIANT:-UD-IQ3_XXS}"
case "$VARIANT" in
  UD-IQ3_XXS) WANT_SHA="e86259c841888b06fd84750963a0263947c9aae3c3029b52cbb3faa34a554827" ;;
  UD-IQ4_XS)  WANT_SHA="d83adbbbaace8acdfcfe28004f779326176b9df00b4ec99dc6c24d749723d3b9" ;;
  *) echo "Unknown HUIHUI_VARIANT $VARIANT (add its sha256 from the HF file listing)" >&2; exit 1 ;;
esac
FILE="Huihui-Qwen3.8-27B-abliterated-$VARIANT.gguf"
DEST="$REDBEARS_ASSETS/models/huihui"; mkdir -p "$DEST"
if [ ! -f "$DEST/$FILE" ] || [ "$(shasum -a 256 "$DEST/$FILE" | cut -d' ' -f1)" != "$WANT_SHA" ]; then
  curl -L -C - --fail -o "$DEST/$FILE" "https://huggingface.co/$REPO/resolve/$REV/$FILE"
fi
GOT="$(shasum -a 256 "$DEST/$FILE" | cut -d' ' -f1)"
[ "$GOT" = "$WANT_SHA" ] || { echo "SHA-256 mismatch: $GOT" >&2; exit 1; }
TAG="huihui-qwen3.8-27b-abliterated-$(echo "$VARIANT" | tr 'A-Z' 'a-z' | tr -d '_')"
sed "s#@GGUF_PATH@#$DEST/$FILE#" "$ROOT/models/Modelfile.huihui" > "$DEST/Modelfile.resolved"
ollama create "$TAG" -f "$DEST/Modelfile.resolved"
echo "Registered Ollama model: $TAG"
