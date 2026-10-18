#!/usr/bin/env bash
# One-time setup: Python venv, frontend deps, Hugging Face weights, Ollama model, knowledge index.
# Large files go to $REDBEARS_ASSETS (default ~/redbears-assets), never into git.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
mkdir -p "$REDBEARS_ASSETS"/{models,data}

echo "== Python venv ($VENV)"
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -r "$ROOT/oyster/backend/requirements.txt" -r "$ROOT/rerank_server/requirements.txt"

echo "== Frontend deps"
(cd "$ROOT/oyster/frontend" && npm ci)

echo "== Knowledge index"
if [ ! -d "$REDBEARS_ASSETS/data/knowledge_snapshot/vector_db" ]; then
  echo "   No index at $REDBEARS_ASSETS/data/knowledge_snapshot."
  echo "   Copy the existing Oyster snapshot (APFS clone = no extra disk):"
  echo "   cp -cR <oyster>/oyster/backend/data/knowledge_snapshot $REDBEARS_ASSETS/data/"
  echo "   or rebuild it from the packs: see oyster/backend/KNOWLEDGE_BASE.md"
fi

echo "== Huihui model + Ollama registration"
"$ROOT/scripts/install-huihui.sh"

echo "== Nemotron reranker weights (pinned revision, ~2.5 GB, downloaded on first server start)"
echo "Done. Start with scripts/start.sh"
