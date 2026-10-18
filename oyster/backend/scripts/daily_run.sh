#!/bin/zsh
# oyster/backend/scripts/daily_run.sh
#
# The single entry point launchd calls. Runs both daily scripts in sequence
# using the venv's python3 binary directly (NOT `source venv/bin/activate` —
# that resolved python3 to a pyenv interpreter lacking torch/transformers/peft
# when tested), and appends a combined, timestamped log — a scheduled run has
# no visible terminal, so this file IS the terminal.
#
# Order: knowledge refresh first (fast, network-bound), training second
# (slow, possibly hours) — a light job never sits queued behind a heavy one.
#
# A simple mkdir-lock guards against overlap: LoRA training has no timeout,
# so if last night's run is still going when tonight's StartCalendarInterval
# fires, launchd WILL start a second daily_run.sh concurrently unless stopped.

set -uo pipefail   # NOT -e: one script failing must not skip the other

BACKEND_DIR="/Users/pritsss/cold-calling-ai-agent/oyster/backend"
PYTHON="$BACKEND_DIR/venv/bin/python3"
LOG_FILE="$BACKEND_DIR/logs/daily_run.log"
LOCK_DIR="$BACKEND_DIR/data/.daily_run.lock"

mkdir -p "$BACKEND_DIR/logs"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "$(date -u +%FT%TZ) daily_run: previous run still in progress (lock held) — skipping" >> "$LOG_FILE"
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT

cd "$BACKEND_DIR" || { echo "cannot cd to $BACKEND_DIR" >> "$LOG_FILE"; exit 1; }

{
  echo "===== daily_run $(date -u +%FT%TZ) ====="

  echo "--- daily_knowledge_refresh.py ---"
  caffeinate -i "$PYTHON" scripts/daily_knowledge_refresh.py
  echo "knowledge_refresh exit=$?"

  echo "--- daily_training.py ---"
  caffeinate -i "$PYTHON" scripts/daily_training.py
  echo "training exit=$?"

  echo "===== daily_run done $(date -u +%FT%TZ) ====="
} >> "$LOG_FILE" 2>&1
